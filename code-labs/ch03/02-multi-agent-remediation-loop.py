#!/usr/bin/env python3
"""Sandboxed Multi-Agent Vulnerability Remediation Loop for OrderFlow.

Coordinates four isolated agent stages:
1. TriageAgent -> selects prioritized KEV/reachable finding
2. ReproducerAgent -> proves security assertion fails BEFORE patch
3. MinimalPatchAgent -> rejects major bumps or stripped tests
4. SandboxVerifierAgent -> runs regression + Semgrep v1.170+ diff gate
"""

import importlib.util
import json
from pathlib import Path
from typing import Any


CH03_DIR = Path(__file__).resolve().parent
REPO_URL = "https://github.com/kiennt308/ai-devsecops-labs"


def _load_service_module() -> Any:
    mod_path = CH03_DIR / "01-vulnerable-orderflow-service.py"
    spec = importlib.util.spec_from_file_location("ch03_svc", mod_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module: {mod_path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PatchProposal:
    """Candidate remediation patch submitted for deterministic checks."""

    def __init__(
        self,
        cve_id: str,
        old_pin: str,
        new_pin: str,
        safe_mode: bool,
        diff_snippet: str,
        allow_major_version_jump: bool = False,
        tests_deleted: int = 0,
        assertions_lowered: int = 0,
    ) -> None:
        self.cve_id = cve_id
        self.old_pin = old_pin
        self.new_pin = new_pin
        self.safe_mode = safe_mode
        self.diff_snippet = diff_snippet
        self.allow_major_version_jump = allow_major_version_jump
        self.tests_deleted = tests_deleted
        self.assertions_lowered = assertions_lowered


class TriageAgent:
    """Selects highest-priority actionable CVE from triage queue."""

    def select_target(
        self, findings: list[dict[str, Any]]
    ) -> dict[str, Any]:
        for item in findings:
            if item.get("kev") or (
                item.get("reachable") and item.get("epss_v4", 0.0) >= 0.50
            ):
                return {
                    "cve_id": item["cve_id"],
                    "pkg_name": item["pkg_name"],
                    "old_pin": (
                        f"{item['pkg_name']}=={item['installed_version']}"
                    ),
                    "target_version": item["fixed_version"],
                    "call_path": item.get("call_path", "unknown"),
                }
        raise ValueError("No actionable CVE found in triage input")


class ReproducerAgent:
    """Executes failing security assertion before any patch is applied."""

    def reproduce(self, svc: Any) -> dict[str, Any]:
        pre_patch = svc.run_security_assertion(safe_mode=False)
        reproduced = not pre_patch["exploit_blocked"]
        if not reproduced:
            raise AssertionError("Pre-patch exploit failed to reproduce")
        return {
            "stage": "reproduce_before_patch",
            "reproduced": reproduced,
            "pre_patch_result": pre_patch,
        }


class MinimalPatchAgent:
    """Enforces minimal diff scope and anti-cheating test guardrails."""

    def evaluate_proposal(
        self, svc: Any, proposal: PatchProposal
    ) -> dict[str, Any]:
        reasons: list[str] = []
        if proposal.allow_major_version_jump:
            reasons.append("BREAKING_MAJOR_JUMP_DENIED")
        if not svc.is_minimal_pin_upgrade(
            proposal.old_pin, proposal.new_pin
        ):
            reasons.append("NON_MINIMAL_OR_MAJOR_PIN_JUMP")
        if proposal.tests_deleted > 0:
            reasons.append("TEST_DELETION_FORBIDDEN")
        if proposal.assertions_lowered > 0:
            reasons.append("ASSERTION_WEAKENING_FORBIDDEN")

        if reasons:
            return {
                "accepted": False,
                "new_pin": proposal.new_pin,
                "reasons": reasons,
            }
        return {
            "accepted": True,
            "old_pin": proposal.old_pin,
            "new_pin": proposal.new_pin,
            "reasons": [],
        }


class SandboxVerifierAgent:
    """Runs post-patch security, functional regression, and SAST gates."""

    UNSAFE_PATTERNS = (
        "Loader=yaml.Loader",
        "UnsafeLoader",
        "eval(",
        "exec(",
    )

    def _run_semgrep_diff_check(
        self, diff_snippet: str
    ) -> dict[str, Any]:
        hits = [p for p in self.UNSAFE_PATTERNS if p in diff_snippet]
        uses_safe_load = "yaml.safe_load" in diff_snippet
        clean = len(hits) == 0 and uses_safe_load
        return {
            "engine": "semgrep-1.170+",
            "clean": clean,
            "findings": hits,
        }

    def verify_and_build_pr(
        self,
        svc: Any,
        proposal: PatchProposal,
        patch_gate: dict[str, Any],
    ) -> dict[str, Any]:
        if not patch_gate["accepted"]:
            return {
                "pr_ready": False,
                "direct_merge": False,
                "hitl_approval_required": True,
                "rejected_reasons": patch_gate["reasons"],
            }

        safe_flag = proposal.safe_mode
        post_sec = svc.run_security_assertion(safe_mode=safe_flag)
        total_ok = (
            svc.compute_order_total(
                100.0, svc.VALID_DISCOUNT_YAML, safe_mode=safe_flag
            )
            == 85.0
        )
        below_min_ok = (
            svc.compute_order_total(
                30.0, svc.VALID_DISCOUNT_YAML, safe_mode=safe_flag
            )
            == 30.0
        )
        regression_passed = total_ok and below_min_ok
        sast = self._run_semgrep_diff_check(proposal.diff_snippet)

        pr_ready = (
            bool(post_sec["exploit_blocked"])
            and regression_passed
            and bool(sast["clean"])
        )
        return {
            "pr_ready": pr_ready,
            "direct_merge": False,
            "hitl_approval_required": True,
            "author": "Kien Nguyen",
            "repository": REPO_URL,
            "cve_id": proposal.cve_id,
            "pin_upgrade": f"{proposal.old_pin} -> {proposal.new_pin}",
            "post_patch_security": post_sec,
            "regression_passed": regression_passed,
            "sast_gate": sast,
            "openvex_update": {
                "cve_id": proposal.cve_id,
                "status": "fixed",
                "fixed_in": proposal.new_pin,
            },
        }


def run_remediation_pipeline(
    proposal: PatchProposal | None = None,
) -> dict[str, Any]:
    """Execute the 4-stage pipeline and return full audit trace."""
    svc = _load_service_module()
    triage = TriageAgent()
    reproducer = ReproducerAgent()
    patcher = MinimalPatchAgent()
    verifier = SandboxVerifierAgent()

    findings = [
        {
            "cve_id": "CVE-2026-4101",
            "pkg_name": "pyyaml",
            "installed_version": "6.0.0",
            "fixed_version": "6.0.2",
            "kev": True,
            "reachable": True,
            "epss_v4": 0.42,
            "call_path": "app.config.load_discount -> yaml.load",
        }
    ]
    target = triage.select_target(findings)
    repro = reproducer.reproduce(svc)

    unsafe_major_bump = PatchProposal(
        cve_id=target["cve_id"],
        old_pin=target["old_pin"],
        new_pin="pyyaml==7.0.0",
        safe_mode=True,
        diff_snippet="data = yaml.safe_load(raw_yaml)",
        allow_major_version_jump=True,
    )
    rejected_trace = patcher.evaluate_proposal(svc, unsafe_major_bump)

    active = proposal or PatchProposal(
        cve_id=target["cve_id"],
        old_pin=target["old_pin"],
        new_pin="pyyaml==6.0.2",
        safe_mode=True,
        diff_snippet="data = yaml.safe_load(raw_yaml)",
        allow_major_version_jump=False,
    )
    accepted_gate = patcher.evaluate_proposal(svc, active)
    pr_payload = verifier.verify_and_build_pr(svc, active, accepted_gate)
    return {
        "triage_target": target,
        "reproducer": repro,
        "rejected_unsafe_major_bump": rejected_trace,
        "patch_gate": accepted_gate,
        "gitops_pr_payload": pr_payload,
    }


def main() -> None:
    trace = run_remediation_pipeline()
    print(json.dumps(trace, indent=2))


if __name__ == "__main__":
    main()
