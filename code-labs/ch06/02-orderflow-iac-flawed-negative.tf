# Deliberately Flawed OrderFlow Terraform (Negative Test Fixture)
# Triggers Trivy HIGH/CRITICAL, Checkov CKV_AWS_304 & CKV_AWS_393
# Author: Kien Nguyen | https://github.com/kiennt308/ai-devsecops-labs

resource "aws_kms_key" "orderflow_audit_flawed" {
  description             = "Flawed KMS key without 90d rotation"
  enable_key_rotation     = false
  rotation_period_in_days = 365
}

resource "aws_s3_bucket" "orderflow_audit_flawed" {
  bucket = "orderflow-public-audit-flawed"
}

resource "aws_s3_bucket_acl" "orderflow_audit_flawed" {
  bucket = aws_s3_bucket.orderflow_audit_flawed.id
  acl    = "public-read"
}

data "aws_iam_policy_document" "github_oidc_wildcard_flawed" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type = "Federated"
      identifiers = [
        "arn:aws:iam::123456789012:oidc-provider/token.actions.github"
      ]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:kiennt308/*"]
    }
  }
}

resource "aws_iam_role" "orderflow_flawed_role" {
  name = "orderflow-wildcard-oidc-role"
  assume_role_policy = (
    data.aws_iam_policy_document.github_oidc_wildcard_flawed.json
  )
}

data "aws_iam_policy_document" "orderflow_admin_wildcard" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "orderflow_admin_wildcard" {
  name   = "orderflow-admin-wildcard"
  role   = aws_iam_role.orderflow_flawed_role.id
  policy = data.aws_iam_policy_document.orderflow_admin_wildcard.json
}
