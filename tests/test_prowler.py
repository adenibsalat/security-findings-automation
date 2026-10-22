from pathlib import Path

import pytest

from finding_pipeline.prowler import (
    extract_public_ips,
    filter_actionable,
    load_findings,
    parse_finding,
)

SAMPLE = Path(__file__).parent / "fixtures" / "prowler_sample.json"


def test_keeps_only_failed_high_and_critical():
    actionable = filter_actionable(load_findings(SAMPLE))
    assert [f.severity for f in actionable] == ["critical", "high"]
    assert all(f.status == "FAIL" for f in actionable)


def test_duplicates_are_removed():
    findings = load_findings(SAMPLE)
    assert len(findings) == 5
    fingerprints = [f.fingerprint for f in filter_actionable(findings)]
    assert len(fingerprints) == len(set(fingerprints))


def test_min_severity_medium_includes_medium():
    actionable = filter_actionable(load_findings(SAMPLE), min_severity="medium")
    assert len(actionable) == 3


def test_unknown_severity_raises():
    with pytest.raises(ValueError):
        filter_actionable([], min_severity="urgent")


def test_public_ip_extracted_from_finding():
    ssh_finding = filter_actionable(load_findings(SAMPLE))[1]
    assert ssh_finding.ip_addresses == ["45.33.32.156"]


def test_extract_public_ips_skips_private_and_invalid():
    text = "from 10.0.0.1 and 0.0.0.0/0 and 45.33.32.156 and 999.1.1.1"
    assert extract_public_ips(text) == ["45.33.32.156"]


def test_legacy_v3_format_is_parsed():
    item = {
        "CheckID": "s3_bucket_public_access",
        "CheckTitle": "Ensure S3 buckets are not publicly accessible",
        "Severity": "critical",
        "Status": "FAIL",
        "AccountId": "111122223333",
        "Region": "eu-west-1",
        "ResourceArn": "arn:aws:s3:::acme-logs",
        "StatusExtended": "Bucket is public.",
        "Remediation": {"Recommendation": {"Text": "Block public access."}},
    }
    finding = parse_finding(item)
    assert finding.severity == "critical"
    assert finding.remediation == "Block public access."


def test_fingerprint_is_stable():
    first = filter_actionable(load_findings(SAMPLE))[0]
    again = filter_actionable(load_findings(SAMPLE))[0]
    assert first.fingerprint == again.fingerprint
    assert len(first.fingerprint) == 16
