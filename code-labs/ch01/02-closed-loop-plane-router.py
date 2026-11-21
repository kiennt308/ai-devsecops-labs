#!/usr/bin/env python3
"""Closed-Loop AI DevSecOps Plane Router for OrderFlow (Volume 09).

Routes application, supply-chain, cloud posture, and kernel eBPF
signals across Volume 09 planes while delegating Security-OF-Agents
workloads cleanly out to Volume 10 (OWASP ASI01-ASI10, gVisor sandbox).
"""

from __future__ import annotations

import json
from typing import Any


PLANE_RULES: dict[str, tuple[str, str]] = {
    "cve_reachability": ("PART_I_APPSEC", "EPSS v4 + KEV + OpenVEX"),
    "slsa_cosign_aibom": ("PART_II_SUPPLY_CHAIN", "SLSA v1.2 + Kyverno"),
    "iac_cspm_drift": ("PART_II_CLOUD_POSTURE", "Trivy + Checkov PR"),
    "kernel_ebpf_ocsf": ("PART_III_RUNTIME_EBPF", "Falco + Tetragon"),
    "agent_asi_sandbox": ("DELEGATE_VOL_10", "OWASP ASI / gVisor Scope"),
}


def route_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Classify a security finding into its exact defense plane."""
    cat = finding["category"]
    plane, engine = PLANE_RULES.get(
        cat, ("UNCLASSIFIED", "Manual Security Review")
    )
    if plane == "DELEGATE_VOL_10":
        return {
            "id": finding["id"],
            "plane": plane,
            "control": engine,
            "automerge": False,
            "scope": "VOL_10_CAPSTONE",
        }
    return {
        "id": finding["id"],
        "plane": plane,
        "control": engine,
        "automerge": False,
        "hitl_pr_required": finding.get("mutates_prod", True),
        "scope": "VOL_09_DEVSECOPS",
    }


def main() -> None:
    sample_events = [
        {"id": "ev-cve-01", "category": "cve_reachability"},
        {"id": "ev-sbom-02", "category": "slsa_cosign_aibom"},
        {"id": "ev-iac-03", "category": "iac_cspm_drift"},
        {"id": "ev-ebpf-04", "category": "kernel_ebpf_ocsf"},
        {"id": "ev-asi-05", "category": "agent_asi_sandbox"},
    ]
    results = [route_finding(ev) for ev in sample_events]
    print(json.dumps({"routed": results}, indent=2))


if __name__ == "__main__":
    main()
