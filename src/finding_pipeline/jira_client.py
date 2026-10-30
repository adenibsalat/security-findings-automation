"""Create Jira Cloud tickets for Prowler findings, skipping ones already filed."""

import argparse
import os
from dataclasses import dataclass
from typing import Any, Self

import requests
from dotenv import load_dotenv

from finding_pipeline.prowler import Finding, filter_actionable, load_findings
from finding_pipeline.secrets import get_jira_credentials

SEVERITY_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


@dataclass
class JiraConfig:
    base_url: str
    email: str
    api_token: str
    project_key: str
    issue_type: str = "Task"
    severity_field: str = ""
    account_field: str = ""
    resource_field: str = ""

    @classmethod
    def from_env(cls) -> Self:
        email, api_token = get_jira_credentials()
        return cls(
            base_url=os.environ["JIRA_BASE_URL"].rstrip("/"),
            email=email,
            api_token=api_token,
            project_key=os.environ.get("JIRA_PROJECT_KEY", "SEC"),
            issue_type=os.environ.get("JIRA_ISSUE_TYPE", "Task"),
            severity_field=os.environ.get("JIRA_FIELD_SEVERITY", ""),
            account_field=os.environ.get("JIRA_FIELD_ACCOUNT", ""),
            resource_field=os.environ.get("JIRA_FIELD_RESOURCE", ""),
        )


def _adf(*paragraphs: str) -> dict[str, Any]:
    """Jira Cloud API v3 wants descriptions in Atlassian Document Format."""
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": p}]} for p in paragraphs if p
        ],
    }


class JiraClient:
    def __init__(self, config: JiraConfig, session: requests.Session | None = None):
        self.config = config
        self.session = session or requests.Session()
        self.session.auth = (config.email, config.api_token)
        self.session.headers.update({"Accept": "application/json"})

    def _url(self, path: str) -> str:
        return f"{self.config.base_url}{path}"

    def find_by_fingerprint(self, fingerprint: str) -> str | None:
        jql = f'project = "{self.config.project_key}" AND labels = "fp-{fingerprint}"'
        resp = self.session.post(
            self._url("/rest/api/3/search/jql"),
            json={"jql": jql, "maxResults": 1, "fields": ["key"]},
            timeout=30,
        )
        resp.raise_for_status()
        issues = resp.json().get("issues", [])
        return issues[0]["key"] if issues else None

    def build_payload(self, finding: Finding) -> dict[str, Any]:
        cfg = self.config
        summary = f"[{finding.severity.upper()}] {finding.title} - {finding.resource_id}"
        labels = ["prowler", f"fp-{finding.fingerprint}", finding.check_id]
        fields: dict[str, Any] = {
            "project": {"key": cfg.project_key},
            "issuetype": {"name": cfg.issue_type},
            "summary": summary[:255],
            "description": _adf(
                finding.description,
                f"Check: {finding.check_id}",
                f"Account: {finding.account_id} / Region: {finding.region}",
                f"Resource: {finding.resource_id}",
                f"Remediation: {finding.remediation}" if finding.remediation else "",
            ),
            "labels": [label for label in labels if label],
        }
        if cfg.severity_field:
            fields[cfg.severity_field] = {"value": SEVERITY_LABELS.get(finding.severity, "High")}
        if cfg.account_field:
            fields[cfg.account_field] = finding.account_id
        if cfg.resource_field:
            fields[cfg.resource_field] = finding.resource_id[:255]
        return {"fields": fields}

    def create_issue(self, finding: Finding) -> tuple[str, bool]:
        """Return (issue key, created). created is False when the ticket already existed."""
        existing = self.find_by_fingerprint(finding.fingerprint)
        if existing:
            return existing, False
        resp = self.session.post(
            self._url("/rest/api/3/issue"), json=self.build_payload(finding), timeout=30
        )
        if not resp.ok:
            raise RuntimeError(f"Jira rejected the ticket ({resp.status_code}): {resp.text}")
        return resp.json()["key"], True

    def list_custom_fields(self) -> list[dict[str, str]]:
        resp = self.session.get(self._url("/rest/api/3/field"), timeout=30)
        resp.raise_for_status()
        return [{"id": f["id"], "name": f["name"]} for f in resp.json() if f.get("custom")]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("fields", help="List custom field IDs")
    create = sub.add_parser("create", help="Create tickets from a Prowler file")
    create.add_argument("path")
    create.add_argument("--min-severity", default="high")
    args = parser.parse_args()

    load_dotenv()
    client = JiraClient(JiraConfig.from_env())
    if args.command == "fields":
        for field in client.list_custom_fields():
            print(f"{field['id']:<22} {field['name']}")
        return
    for finding in filter_actionable(load_findings(args.path), args.min_severity):
        key, created = client.create_issue(finding)
        print(f"{'CREATED' if created else 'EXISTS '} {key}  {finding.title}")


if __name__ == "__main__":
    main()
