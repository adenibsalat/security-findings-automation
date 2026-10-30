output "secret_arn" {
  value = aws_secretsmanager_secret.jira.arn
}

output "reader_role_arn" {
  value = aws_iam_role.reader.arn
}

output "svc_user_name" {
  value = aws_iam_user.svc.name
}