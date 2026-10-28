"""HTTP API that n8n calls to turn Prowler findings into Jira tickets."""

import hmac
import os
from typing import Annotated, Any

import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from finding_pipeline.jira_client import JiraClient, JiraConfig
from finding_pipeline.prowler import filter_actionable, parse_finding

load_dotenv()

app = FastAPI(title="Findings Pipeline API", version="0.1.0")


class FindingsRequest(BaseModel):
    findings: list[dict[str, Any]]
    min_severity: str = "high"
    dry_run: bool = False


def require_api_key(x_api_key: Annotated[str, Header()] = "") -> None:
    """Reject callers without the shared key. compare_digest avoids timing attacks."""
    expected = os.environ.get("PIPELINE_API_KEY", "")
    if not expected or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def get_jira_client() -> JiraClient:
    return JiraClient(JiraConfig.from_env())


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/findings", dependencies=[Depends(require_api_key)])
def process_findings(
    request: FindingsRequest,
    jira: Annotated[JiraClient, Depends(get_jira_client)],
) -> dict[str, Any]:
    try:
        findings = [parse_finding(item) for item in request.findings]
        actionable = filter_actionable(findings, request.min_severity)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    results = []
    for finding in actionable:
        summary = {
            "title": finding.title,
            "severity": finding.severity,
            "fingerprint": finding.fingerprint,
        }
        if request.dry_run:
            results.append({**summary, "payload": jira.build_payload(finding)})
            continue
        try:
            key, created = jira.create_issue(finding)
        except (RuntimeError, requests.RequestException) as exc:
            # Safe to retry: tickets already created are skipped by fingerprint.
            raise HTTPException(status_code=502, detail=f"Jira error: {exc}") from exc
        results.append({**summary, "key": key, "created": created})

    return {
        "received": len(findings),
        "actionable": len(actionable),
        "dry_run": request.dry_run,
        "results": results,
    }
