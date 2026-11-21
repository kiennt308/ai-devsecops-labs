#!/usr/bin/env python3
"""Pytest verification for Ch03 Multi-Agent Remediation Pipeline."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from typing import Any


CH03_DIR = Path(__file__).resolve().parent


def _load_module(filename: str, name: str) -> Any:
    mod_path = CH03_DIR / filename
    spec = importlib.util.spec_from_file_location(name, mod_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_exploit_reproduces_before_fix_and_passes_after_minimal_fix() -> (
    None
):
    loop = _load_module("02-multi-agent-remediation-loop.py", "ch03_loop")
    trace = loop.run_remediation_pipeline()
    assert trace["reproducer"]["reproduced"] is True
    assert (
        trace["reproducer"]["pre_patch_result"]["exploit_blocked"]
        is False
    )

    pr = trace["gitops_pr_payload"]
    assert pr["pr_ready"] is True
    assert pr["post_patch_security"]["exploit_blocked"] is True
    assert pr["regression_passed"] is True
    assert pr["sast_gate"]["clean"] is True
    assert pr["direct_merge"] is False
    assert pr["hitl_approval_required"] is True


def test_major_version_jump_is_rejected() -> None:
    svc = _load_module("01-vulnerable-orderflow-service.py", "ch03_svc")
    loop = _load_module("02-multi-agent-remediation-loop.py", "ch03_loop")
    bad_proposal = loop.PatchProposal(
        cve_id="CVE-2026-4101",
        old_pin="pyyaml==6.0.0",
        new_pin="pyyaml==7.0.0",
        safe_mode=True,
        diff_snippet="data = yaml.safe_load(raw_yaml)",
        allow_major_version_jump=True,
    )
    trace = loop.run_remediation_pipeline(bad_proposal)
    assert trace["patch_gate"]["accepted"] is False
    assert "BREAKING_MAJOR_JUMP_DENIED" in trace["patch_gate"]["reasons"]
    assert trace["gitops_pr_payload"]["pr_ready"] is False
    assert trace["gitops_pr_payload"]["direct_merge"] is False
    assert not svc.is_minimal_pin_upgrade(
        "pyyaml==6.0.0", "pyyaml==7.0.0"
    )


def test_stripped_tests_or_lowered_assertions_rejected() -> None:
    loop = _load_module("02-multi-agent-remediation-loop.py", "ch03_loop")
    cheating_proposal = loop.PatchProposal(
        cve_id="CVE-2026-4101",
        old_pin="pyyaml==6.0.0",
        new_pin="pyyaml==6.0.2",
        safe_mode=True,
        diff_snippet="data = yaml.safe_load(raw_yaml)",
        allow_major_version_jump=False,
        tests_deleted=1,
        assertions_lowered=2,
    )
    trace = loop.run_remediation_pipeline(cheating_proposal)
    assert trace["patch_gate"]["accepted"] is False
    reasons = trace["patch_gate"]["reasons"]
    assert "TEST_DELETION_FORBIDDEN" in reasons
    assert "ASSERTION_WEAKENING_FORBIDDEN" in reasons
    assert trace["gitops_pr_payload"]["pr_ready"] is False
    assert trace["gitops_pr_payload"]["direct_merge"] is False
