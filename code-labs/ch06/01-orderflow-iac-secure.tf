# OrderFlow Secure Audit S3, KMS (90d) & Scoped GitHub OIDC IaC
# Author: Kien Nguyen | https://github.com/kiennt308/ai-devsecops-labs

terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

variable "central_log_bucket" {
  description = "Pre-provisioned central S3 access log bucket ID"
  type        = string
  default     = "orderflow-central-s3-access-logs-prod"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_iam_policy_document" "kms_audit_policy" {
  statement {
    sid    = "AllowAccountKmsAdmin"
    effect = "Allow"
    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
    }
    actions = [
      "kms:CreateAlias",
      "kms:DescribeKey",
      "kms:EnableKeyRotation",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListAliases",
      "kms:ListKeyPolicies",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
    ]
    resources = [
      join("", [
        "arn:aws:kms:",
        data.aws_region.current.name,
        ":",
        data.aws_caller_identity.current.account_id,
        ":key/*",
      ])
    ]
  }

  statement {
    sid    = "AllowOrderFlowRoleKmsUse"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.orderflow_gitops_deploy.arn]
    }
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
    ]
    resources = [
      join("", [
        "arn:aws:kms:",
        data.aws_region.current.name,
        ":",
        data.aws_caller_identity.current.account_id,
        ":key/*",
      ])
    ]
  }
}

resource "aws_kms_key" "orderflow_audit" {
  description             = "OrderFlow audit log CMK (90d rotation)"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 90
  policy = (
    data.aws_iam_policy_document.kms_audit_policy.json
  )
}

resource "aws_kms_alias" "orderflow_audit" {
  name          = "alias/orderflow-audit-prod"
  target_key_id = aws_kms_key.orderflow_audit.key_id
}

resource "aws_s3_bucket" "orderflow_audit" {
  bucket = "orderflow-secops-audit-prod"
}

resource "aws_s3_bucket_public_access_block" "orderflow_audit" {
  bucket                  = aws_s3_bucket.orderflow_audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "orderflow_audit" {
  bucket = aws_s3_bucket.orderflow_audit.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "orderflow_audit" {
  bucket = aws_s3_bucket.orderflow_audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.orderflow_audit.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.orderflow_audit.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "orderflow_audit" {
  bucket        = aws_s3_bucket.orderflow_audit.id
  target_bucket = var.central_log_bucket
  target_prefix = "audit-access-logs/"
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "github_oidc_assume" {
  statement {
    sid     = "AllowScopedGitHubActionsOidc"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:kiennt308/orderflow-gitops:ref:refs/heads/main"
      ]
    }
  }
}

resource "aws_iam_role" "orderflow_gitops_deploy" {
  name               = "orderflow-gitops-audit-writer"
  assume_role_policy = (
    data.aws_iam_policy_document.github_oidc_assume.json
  )
}

data "aws_iam_policy_document" "orderflow_least_priv" {
  statement {
    sid    = "AllowScopedAuditBucketWrite"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      "${aws_s3_bucket.orderflow_audit.arn}/*"
    ]
  }

  statement {
    sid    = "AllowScopedAuditKmsEncrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = [
      aws_kms_key.orderflow_audit.arn
    ]
  }
}

resource "aws_iam_role_policy" "orderflow_least_priv" {
  name   = "orderflow-audit-least-priv"
  role   = aws_iam_role.orderflow_gitops_deploy.id
  policy = data.aws_iam_policy_document.orderflow_least_priv.json
}
