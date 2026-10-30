"""Load Jira credentials from AWS Secrets Manager, falling back to environment variables."""

import json
import os
from functools import lru_cache

import boto3


@lru_cache(maxsize=1)
def get_jira_credentials() -> tuple[str, str]:
    """Return (email, api_token). Uses JIRA_SECRET_ID if set, else JIRA_EMAIL/JIRA_API_TOKEN."""
    secret_id = os.environ.get("JIRA_SECRET_ID")
    if not secret_id:
        return os.environ["JIRA_EMAIL"], os.environ["JIRA_API_TOKEN"]
    client = boto3.client("secretsmanager")
    secret = json.loads(client.get_secret_value(SecretId=secret_id)["SecretString"])
    return secret["email"], secret["api_token"]
