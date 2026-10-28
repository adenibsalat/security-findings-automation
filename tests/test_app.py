import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from finding_pipeline.app import app, get_jira_client

SAMPLE = json.loads((Path(__file__).parent / "fixtures" / "prowler_sample.json").read_text())
HEADERS = {"X-Api-Key": "test-key"}
client = TestClient(app)


class FakeJira:
    def __init__(self):
        self.created = []

    def create_issue(self, finding):
        self.created.append(finding.fingerprint)
        return f"SEC-{len(self.created)}", True

    def build_payload(self, finding):
        return {"fields": {"summary": finding.title}}


@pytest.fixture
def jira(monkeypatch):
    monkeypatch.setenv("PIPELINE_API_KEY", "test-key")
    fake = FakeJira()
    app.dependency_overrides[get_jira_client] = lambda: fake
    yield fake
    app.dependency_overrides.clear()


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_rejects_missing_api_key(jira):
    resp = client.post("/findings", json={"findings": SAMPLE})
    assert resp.status_code == 401
    assert jira.created == []


def test_rejects_wrong_api_key(jira):
    resp = client.post("/findings", json={"findings": SAMPLE}, headers={"X-Api-Key": "nope"})
    assert resp.status_code == 401


def test_creates_tickets_for_actionable_findings(jira):
    resp = client.post("/findings", json={"findings": SAMPLE}, headers=HEADERS)
    body = resp.json()
    assert resp.status_code == 200
    assert (body["received"], body["actionable"]) == (5, 2)
    assert [r["key"] for r in body["results"]] == ["SEC-1", "SEC-2"]


def test_dry_run_creates_nothing(jira):
    resp = client.post("/findings", json={"findings": SAMPLE, "dry_run": True}, headers=HEADERS)
    assert resp.status_code == 200
    assert jira.created == []
    assert "payload" in resp.json()["results"][0]


def test_bad_min_severity_returns_422(jira):
    payload = {"findings": SAMPLE, "min_severity": "urgent"}
    resp = client.post("/findings", json=payload, headers=HEADERS)
    assert resp.status_code == 422
