resource "aws_secretsmanager_secret" "jira" {
  #checkov:skip=CKV_AWS_149:AWS-managed key is enough here and avoids KMS cost
  #checkov:skip=CKV2_AWS_57:Atlassian API tokens can't be rotated by API; expiry is set in Atlassian and rotation is a runbook step
  name                    = "${var.project}/jira"
  description             = "Jira Cloud email and API token used by the findings API"
  recovery_window_in_days = 7
}