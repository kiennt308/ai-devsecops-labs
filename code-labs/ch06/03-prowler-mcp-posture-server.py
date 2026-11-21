"""OrderFlow Prowler CIS v8.1 & IaC Posture MCP Server (MCP 2026-07-28).

Copyright (c) 2026 Kien Nguyen
Repository: https://github.com/kiennt308/ai-devsecops-labs
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
import re
from typing import Any
from mcp.server.mcpserver import MCPServer, ResourceSecurity

mcp = MCPServer(
    name="orderflow-prowler-posture-mcp",
    title="OrderFlow Prowler CIS v8.1 & IaC MCP Server",
    version="1.0.0",
    resource_security=ResourceSecurity(
        reject_path_traversal=True,
        reject_absolute_paths=True,
        reject_null_bytes=True,
    ),
)

OIDC_WILDCARD_RE = re.compile(
    r"githubusercontent\.com:sub[\s\S]{0,180}"
    r"values\s*=\s*\[[^\]]*\*[^\]]*\]"
)

PROWLER_CIS81_MAP: dict[str, dict[str, Any]] = {
    "prowler-aws-iam-oidc-wildcard": {
        "finding_id": "prowler-aws-iam-oidc-wildcard",
        "cis_v81_control": "CIS Controls v8.1 6.8",
        "checkov_id": "CKV_AWS_393",
        "source_tf_path": "infra/aws/orderflow_iam_oidc.tf",
        "patch_live_aws_clickops": False,
        "hitl_pr_required": True,
        "pr_patch_hunk": "\n".join(
            [
                "--- a/infra/aws/orderflow_iam_oidc.tf",
                "+++ b/infra/aws/orderflow_iam_oidc.tf",
                "@@ -11,3 +11,3 @@",
                '-      test     = "StringLike"',
                '-      values   = ["repo:kiennt308/*"]',
                '+      test     = "StringEquals"',
                '+      values   = ["repo:kiennt308/orderflow-gitops:'
                'ref:refs/heads/main"]',
            ]
        ),
    },
    "prowler-aws-kms-rotation": {
        "finding_id": "prowler-aws-kms-rotation",
        "cis_v81_control": "CIS Controls v8.1 3.11",
        "checkov_id": "CKV_AWS_304",
        "source_tf_path": "infra/aws/orderflow_kms.tf",
        "patch_live_aws_clickops": False,
        "hitl_pr_required": True,
        "pr_patch_hunk": "\n".join(
            [
                "--- a/infra/aws/orderflow_kms.tf",
                "+++ b/infra/aws/orderflow_kms.tf",
                "@@ -3,2 +3,2 @@",
                "-  enable_key_rotation     = false",
                "-  rotation_period_in_days = 365",
                "+  enable_key_rotation     = true",
                "+  rotation_period_in_days = 90",
            ]
        ),
    },
    "prowler-aws-s3-public": {
        "finding_id": "prowler-aws-s3-public",
        "cis_v81_control": "CIS Controls v8.1 3.3",
        "checkov_id": "CKV_AWS_20",
        "source_tf_path": "infra/aws/orderflow_s3_audit.tf",
        "patch_live_aws_clickops": False,
        "hitl_pr_required": True,
        "pr_patch_hunk": "\n".join(
            [
                "--- a/infra/aws/orderflow_s3_audit.tf",
                "+++ b/infra/aws/orderflow_s3_audit.tf",
                "@@ -5,3 +5,6 @@",
                '-  acl    = "public-read"',
                '+  block_public_acls       = true',
                '+  block_public_policy     = true',
                '+  ignore_public_acls      = true',
                '+  restrict_public_buckets = true',
            ]
        ),
    },
}


def _add_finding(
    findings: list[dict[str, str]],
    rule_id: str,
    checkov_id: str,
    severity: str,
    summary: str,
) -> None:
    findings.append(
        {
            "rule_id": rule_id,
            "checkov_id": checkov_id,
            "severity": severity,
            "summary": summary,
        }
    )


@mcp.tool()
def scan_iac_posture(tf_content: str) -> str:
    """Scan Terraform HCL for OIDC, KMS 90d, S3, and IAM flaws."""
    findings: list[dict[str, str]] = []
    if re.search(r'acl\s*=\s*"public-(?:read|read-write)"', tf_content):
        _add_finding(
            findings,
            "AVD-AWS-0092",
            "CKV_AWS_20",
            "HIGH",
            "S3 bucket exposes public-read ACL",
        )
    if "aws_s3_bucket" in tf_content:
        if "aws_s3_bucket_public_access_block" not in tf_content:
            _add_finding(
                findings,
                "AVD-AWS-0086",
                "CKV_AWS_53",
                "HIGH",
                "Missing aws_s3_bucket_public_access_block",
            )
        sse_res = "aws_s3_bucket_server_side_encryption_configuration"
        if sse_res not in tf_content:
            _add_finding(
                findings,
                "AVD-AWS-0132",
                "CKV_AWS_145",
                "HIGH",
                "Missing KMS S3 server-side encryption configuration",
            )
    if "aws_kms_key" in tf_content:
        if not re.search(r"enable_key_rotation\s*=\s*true", tf_content):
            _add_finding(
                findings,
                "AVD-AWS-0065",
                "CKV_AWS_7",
                "MEDIUM",
                "KMS enable_key_rotation must be true",
            )
        rot = re.search(
            r"rotation_period_in_days\s*=\s*(\d+)", tf_content
        )
        if rot is None or int(rot.group(1)) > 90:
            _add_finding(
                findings,
                "CKV_AWS_304",
                "CKV_AWS_304",
                "HIGH",
                "KMS rotation_period_in_days must be <= 90 days",
            )
    if OIDC_WILDCARD_RE.search(tf_content):
        _add_finding(
            findings,
            "CKV_AWS_393",
            "CKV_AWS_393",
            "CRITICAL",
            "Wildcard GitHub OIDC sub claim permits unauthorized repos",
        )
    has_star_act = re.search(r'actions\s*=\s*\[\s*"\*"\s*\]', tf_content)
    has_star_res = re.search(
        r'resources\s*=\s*\[\s*"\*"\s*\]', tf_content
    )
    if has_star_act or has_star_res:
        _add_finding(
            findings,
            "AVD-AWS-0057",
            "CKV_AWS_355",
            "HIGH",
            "IAM policy grants wildcard * actions or resources",
        )
    return json.dumps(
        {
            "passed": len(findings) == 0,
            "finding_count": len(findings),
            "findings": findings,
            "scanners": [
                "checkov-3.2.532+",
                "trivy-0.76.2",
                "cfn-guard-3.2.1",
            ],
        }
    )


@mcp.tool()
def map_prowler_cis81_to_terraform(finding_id: str) -> str:
    """Map Prowler CIS v8.1 finding to root .tf PR patch hunk."""
    entry = PROWLER_CIS81_MAP.get(finding_id)
    if entry is None:
        return json.dumps(
            {
                "mapped": False,
                "finding_id": finding_id,
                "patch_live_aws_clickops": False,
                "hitl_pr_required": True,
                "message": "Unknown finding; route to manual IaC triage",
            }
        )
    return json.dumps({"mapped": True, **entry})


def build_stateless_http_app():
    """Return stateless Streamable HTTP ASGI app for MCP 2026-07-28."""
    return mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )


if __name__ == "__main__":
    port = int(os.getenv("MCP_PORT", "18806"))
    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=port,
        stateless_http=True,
        json_response=True,
    )
