# Service account the API container logs in as. Its only power: assume the reader role.
resource "aws_iam_user" "svc" {
  name = "${var.project}-svc"
}

resource "aws_iam_group" "svc" {
  name = "${var.project}-svc"
}

resource "aws_iam_user_group_membership" "svc" {
  user   = aws_iam_user.svc.name
  groups = [aws_iam_group.svc.name]
}

data "aws_iam_policy_document" "assume_reader" {
  statement {
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.reader.arn]
  }
}

resource "aws_iam_group_policy" "assume_reader" {
  name   = "assume-secret-reader"
  group  = aws_iam_group.svc.name
  policy = data.aws_iam_policy_document.assume_reader.json
}

# Role that can read exactly one secret, and only the svc user may assume it.
data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_user.svc.arn]
    }
  }
}

resource "aws_iam_role" "reader" {
  name                 = "${var.project}-secret-reader"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "read_secret" {
  statement {
    sid       = "ReadJiraSecretOnly"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [aws_secretsmanager_secret.jira.arn]
  }
}

resource "aws_iam_role_policy" "read_secret" {
  name   = "read-jira-secret"
  role   = aws_iam_role.reader.id
  policy = data.aws_iam_policy_document.read_secret.json
}