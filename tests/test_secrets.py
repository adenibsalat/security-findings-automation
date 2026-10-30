import json

from finding_pipeline import secrets


class FakeSecretsManager:
    def get_secret_value(self, SecretId):
        assert SecretId == "findings-pipeline/jira"
        return {"SecretString": json.dumps({"email": "a@example.com", "api_token": "from-aws"})}


def test_falls_back_to_env(monkeypatch):
    secrets.get_jira_credentials.cache_clear()
    monkeypatch.delenv("JIRA_SECRET_ID", raising=False)
    monkeypatch.setenv("JIRA_EMAIL", "me@example.com")
    monkeypatch.setenv("JIRA_API_TOKEN", "from-env")
    assert secrets.get_jira_credentials() == ("me@example.com", "from-env")


def test_reads_from_secrets_manager(monkeypatch):
    secrets.get_jira_credentials.cache_clear()
    monkeypatch.setenv("JIRA_SECRET_ID", "findings-pipeline/jira")
    monkeypatch.setattr(secrets.boto3, "client", lambda service: FakeSecretsManager())
    assert secrets.get_jira_credentials() == ("a@example.com", "from-aws")
    secrets.get_jira_credentials.cache_clear()
