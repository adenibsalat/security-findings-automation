from finding_pipeline.jira_client import JiraClient, JiraConfig
from finding_pipeline.prowler import Finding


class FakeResponse:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status
        self.ok = status < 400
        self.text = str(data)

    def json(self):
        return self._data

    def raise_for_status(self):
        if not self.ok:
            raise RuntimeError(self.status_code)


class FakeSession:
    def __init__(self, existing=None):
        self.auth = None
        self.headers = {}
        self.existing = existing
        self.created = []

    def post(self, url, json, timeout):
        if url.endswith("/search/jql"):
            issues = [{"key": self.existing}] if self.existing else []
            return FakeResponse({"issues": issues})
        self.created.append(json)
        return FakeResponse({"key": "SEC-1"}, 201)


CONFIG = JiraConfig(
    base_url="https://example.atlassian.net",
    email="me@example.com",
    api_token="not-a-real-token",
    project_key="SEC",
    severity_field="customfield_10050",
)

FINDING = Finding(
    check_id="s3_bucket_public_access",
    title="Ensure S3 buckets are not publicly accessible",
    severity="critical",
    status="FAIL",
    account_id="111122223333",
    region="eu-west-1",
    resource_id="arn:aws:s3:::acme-logs",
    description="Bucket is public.",
    remediation="Block public access.",
)


def test_payload_sets_severity_labels_and_summary():
    fields = JiraClient(CONFIG, FakeSession()).build_payload(FINDING)["fields"]
    assert fields["customfield_10050"] == {"value": "Critical"}
    assert f"fp-{FINDING.fingerprint}" in fields["labels"]
    assert fields["summary"].startswith("[CRITICAL]")


def test_creates_ticket_when_none_exists():
    session = FakeSession()
    key, created = JiraClient(CONFIG, session).create_issue(FINDING)
    assert (key, created) == ("SEC-1", True)
    assert len(session.created) == 1


def test_skips_ticket_that_already_exists():
    session = FakeSession(existing="SEC-9")
    key, created = JiraClient(CONFIG, session).create_issue(FINDING)
    assert (key, created) == ("SEC-9", False)
    assert session.created == []


def test_long_summary_is_truncated():
    long = Finding(**{**FINDING.__dict__, "title": "x" * 400})
    fields = JiraClient(CONFIG, FakeSession()).build_payload(long)["fields"]
    assert len(fields["summary"]) == 255


def test_description_has_no_empty_paragraphs():
    no_fix = Finding(**{**FINDING.__dict__, "remediation": ""})
    content = JiraClient(CONFIG, FakeSession()).build_payload(no_fix)["fields"]["description"]
    assert all(p["content"][0]["text"] for p in content["content"])

def test_country_field_filled_from_ip(monkeypatch):
    monkeypatch.setattr(
        "finding_pipeline.jira_client.countries_for_ips",
        lambda ips: "United States (45.33.32.156)",
    )
    config = JiraConfig(**{**CONFIG.__dict__, "country_field": "customfield_10047"})
    finding = Finding(**{**FINDING.__dict__, "ip_addresses": ["45.33.32.156"]})
    fields = JiraClient(config, FakeSession()).build_payload(finding)["fields"]
    assert fields["customfield_10047"] == "United States (45.33.32.156)"