"""Parse Prowler output and keep the findings worth a Jira ticket."""

import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    status: str
    account_id: str
    region: str
    resource_id: str
    description: str = ""
    remediation: str = ""
    ip_addresses: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Stable ID so the same finding never creates two Jira tickets."""
        raw = f"{self.account_id}|{self.check_id}|{self.resource_id}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["fingerprint"] = self.fingerprint
        return data


def extract_public_ips(*texts: str) -> list[str]:
    """Return public IPv4 addresses found in the text, skipping private and 0.0.0.0."""
    found: list[str] = []
    for text in texts:
        for match in IP_PATTERN.findall(text or ""):
            try:
                ip = ipaddress.ip_address(match)
            except ValueError:
                continue
            if ip.is_global and match not in found:
                found.append(match)
    return found


def _from_ocsf(item: dict[str, Any]) -> Finding:
    info = item.get("finding_info", {})
    resource = (item.get("resources") or [{}])[0]
    cloud = item.get("cloud", {})
    resource_id = resource.get("uid", "")
    description = item.get("status_detail") or info.get("desc", "")
    return Finding(
        check_id=item.get("metadata", {}).get("event_code", ""),
        title=info.get("title", ""),
        severity=str(item.get("severity", "")).lower(),
        status=str(item.get("status_code", "")).upper(),
        account_id=str(cloud.get("account", {}).get("uid", "")),
        region=resource.get("region") or cloud.get("region", ""),
        resource_id=resource_id,
        description=description,
        remediation=item.get("remediation", {}).get("desc", ""),
        ip_addresses=extract_public_ips(resource_id, description),
    )


def _from_legacy(item: dict[str, Any]) -> Finding:
    resource_id = item.get("ResourceArn") or item.get("ResourceId", "")
    description = item.get("StatusExtended", "")
    return Finding(
        check_id=item.get("CheckID", ""),
        title=item.get("CheckTitle", ""),
        severity=str(item.get("Severity", "")).lower(),
        status=str(item.get("Status", "")).upper(),
        account_id=str(item.get("AccountId", "")),
        region=item.get("Region", ""),
        resource_id=resource_id,
        description=description,
        remediation=item.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
        ip_addresses=extract_public_ips(resource_id, description),
    )


def parse_finding(item: dict[str, Any]) -> Finding:
    if "finding_info" in item or "status_code" in item:
        return _from_ocsf(item)
    return _from_legacy(item)


def load_findings(path: str | Path) -> list[Finding]:
    """Load a Prowler JSON array or JSON-lines file."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if text.startswith("["):
        items = json.loads(text)
    else:
        items = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [parse_finding(item) for item in items]


def filter_actionable(findings: list[Finding], min_severity: str = "high") -> list[Finding]:
    """Keep failed findings at or above min_severity, without duplicates."""
    if min_severity not in SEVERITY_ORDER:
        raise ValueError(f"Unknown severity: {min_severity}")
    threshold = SEVERITY_ORDER[min_severity]
    seen: set[str] = set()
    result: list[Finding] = []
    for finding in findings:
        if finding.status != "FAIL":
            continue
        if SEVERITY_ORDER.get(finding.severity, -1) < threshold:
            continue
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        result.append(finding)
    return result


if __name__ == "__main__":
    actionable = filter_actionable(load_findings(sys.argv[1]))
    print(json.dumps([f.to_dict() for f in actionable], indent=2))
