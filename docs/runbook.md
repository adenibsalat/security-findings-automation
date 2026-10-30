# Runbook

## Start / stop
- Start: `docker compose up -d` · Stop: `docker compose down` · Logs: `docker logs findings-api --tail 50`

## When something breaks
| Symptom | Likely cause | Fix |
|---|---|---|
| `HTTP 403 Authorization data is wrong!` | Wrong webhook key | Check `N8N_WEBHOOK_KEY` matches the n8n "Webhook key" credential |
| `HTTP 401` from the API | n8n's API key doesn't match | Check `PIPELINE_API_KEY` matches the n8n "Findings API key" credential, then restart the API |
| `HTTP 502 Jira error ... 401` | Jira token expired or revoked | Rotate the Jira token (below) |
| `HTTP 502 Jira error ... 400` field errors | A custom field isn't on the Create screen | Add it to the SEC screens in Jira |
| `AccessDenied` / `ExpiredToken` in API logs | svc key disabled or role changed | `aws sts get-caller-identity --profile findings-reader` |
| Source IP Country empty | No public IP in finding, or `.mmdb` missing | Check `data/geoip-country.mmdb`; refresh monthly from DB-IP |
| Webhook returns 404 | Workflow not published | Publish / activate "Findings Intake" in n8n |

## Rotation
- **Jira token** (Atlassian tokens expire, max 1 year): create a new token, store it with
  `put-secret-value` on `findings-pipeline/jira`, run `docker compose restart api`, then revoke the old token.
- **svc access key** (every 90 days): create a second key, update `.aws-findings\credentials`,
  restart the API, then deactivate and delete the old key.
- **Webhook / API keys**: generate a new one with `secrets.token_urlsafe(32)`, update `.env` and the n8n credential, restart.

## SSH open to the internet (SEC-3)
- Restrict port 22 in the security group to known IP ranges.
- Prefer AWS SSM Session Manager instead of SSH.