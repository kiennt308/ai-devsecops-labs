#!/usr/bin/env python3
"""EPSS v4, CISA KEV, Call-Graph Reachability, and OpenVEX v0.2.0 Triage.

Reduces container scanner noise on OrderFlow by elevating CISA KEV
findings regardless of CVSS, prioritizing reachable high-EPSS CVEs,
and emitting verifiable OpenVEX v0.2.0 statements for dead code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_ARTIFACT = (
    "oci://registry.orderflow.internal/orderflow-api@sha256:1a2b3c4d"
)
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
NOT_AFFECTED_JUSTIFICATION = "vulnerable_code_not_in_execute_path"
REPO_URL = "https://github.com/kiennt308/ai-devsecops-labs"


def artifact_to_oci_purl(artifact: str) -> str:
    """Convert an OCI image reference into a qualified pkg:oci PURL."""
    if "@sha256:" in artifact:
        name_part, digest = artifact.split("@", maxsplit=1)
        image_name = name_part.rsplit("/", maxsplit=1)[-1]
        return f"pkg:oci/{image_name}@{digest}?arch=amd64"
    image_name = artifact.rsplit("/", maxsplit=1)[-1]
    return f"pkg:oci/{image_name}?arch=amd64"


def score_finding(
    finding: dict[str, Any], epss_threshold: float = 0.50
) -> dict[str, Any]:
    """Score one vulnerability using KEV, reachability, and EPSS v4."""
    cvss = float(finding["cvss"])
    epss_v4 = float(finding["epss_v4"])
    is_kev = bool(finding["kev"])
    is_reachable = bool(finding["reachable"])

    if is_kev:
        risk_score = max(90.0, round(cvss * 5.0 + epss_v4 * 50.0, 2))
        return {
            **finding,
            "actionable": True,
            "priority": "P0_KEV_FLOOR",
            "reason": "cisa_kev_mandatory_floor",
            "risk_score": risk_score,
        }

    if not is_reachable:
        risk_score = round(cvss * 0.1 + epss_v4 * 5.0, 2)
        return {
            **finding,
            "actionable": False,
            "priority": "SUPPRESSED_VEX",
            "reason": NOT_AFFECTED_JUSTIFICATION,
            "risk_score": risk_score,
        }

    if epss_v4 >= epss_threshold:
        risk_score = round(cvss * 4.0 + epss_v4 * 60.0, 2)
        return {
            **finding,
            "actionable": True,
            "priority": "P1_REACHABLE_EPSS",
            "reason": "reachable_above_epss_v4_threshold",
            "risk_score": risk_score,
        }

    risk_score = round(cvss * 2.0 + epss_v4 * 30.0, 2)
    return {
        **finding,
        "actionable": False,
        "priority": "DEFERRED_LOW_EPSS",
        "reason": "reachable_below_epss_v4_threshold",
        "risk_score": risk_score,
    }


def build_openvex_document(
    artifact: str,
    suppressed: list[dict[str, Any]],
    author: str = "Kien Nguyen",
) -> dict[str, Any]:
    """Build an OpenVEX v0.2.0 document for unreachable findings."""
    product_purl = artifact_to_oci_purl(artifact)
    statements: list[dict[str, Any]] = []
    for item in suppressed:
        if item.get("reachable"):
            continue
        statements.append(
            {
                "vulnerability": {"name": item["cve_id"]},
                "products": [
                    {
                        "@id": product_purl,
                        "subcomponents": [{"@id": item["purl"]}],
                    }
                ],
                "status": "not_affected",
                "justification": NOT_AFFECTED_JUSTIFICATION,
                "impact_statement": (
                    f"Call graph unreachable in {item['pkg_name']}"
                ),
            }
        )
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"{REPO_URL}/vex/orderflow-api-v1",
        "author": author,
        "timestamp": "2026-11-20T00:00:00Z",
        "version": 1,
        "statements": statements,
    }


def triage_findings(
    findings: list[dict[str, Any]],
    epss_threshold: float = 0.50,
    artifact: str = DEFAULT_ARTIFACT,
) -> dict[str, Any]:
    """Triage findings into actionable queues and OpenVEX statements."""
    scored = [score_finding(item, epss_threshold) for item in findings]
    actionable = [item for item in scored if item["actionable"]]
    suppressed = [item for item in scored if not item["actionable"]]
    total = len(findings)
    noise_cut = (
        round((len(suppressed) / total) * 100.0, 1) if total else 0.0
    )
    openvex = build_openvex_document(artifact, suppressed)
    return {
        "artifact": artifact,
        "total_findings": total,
        "actionable": actionable,
        "suppressed": suppressed,
        "noise_reduction_pct": noise_cut,
        "openvex": openvex,
    }


def main() -> None:
    sample_path = (
        Path(__file__).resolve().parent / "01-trivy-sample-findings.json"
    )
    payload = json.loads(sample_path.read_text(encoding="utf-8"))
    result = triage_findings(
        payload["findings"],
        epss_threshold=0.50,
        artifact=payload["artifact"],
    )
    summary = {
        "artifact": result["artifact"],
        "total_findings": result["total_findings"],
        "actionable_count": len(result["actionable"]),
        "suppressed_count": len(result["suppressed"]),
        "noise_reduction_pct": result["noise_reduction_pct"],
        "actionable_cves": [
            {
                "cve_id": item["cve_id"],
                "priority": item["priority"],
                "cvss": item["cvss"],
                "epss_v4": item["epss_v4"],
                "kev": item["kev"],
            }
            for item in result["actionable"]
        ],
        "openvex_statements": len(result["openvex"]["statements"]),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
