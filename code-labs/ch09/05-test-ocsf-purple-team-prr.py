"""Pytest verification for OCSF SecOps Correlator, Drills & 20-pt PRR.

Copyright (c) 2026 Kien Nguyen
Repository: https://github.com/kiennt308/ai-devsecops-labs
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from importlib import util
import json
from pathlib import Path
import sys

CH09_DIR = Path(__file__).resolve().parent
CORRELATOR_FILE = CH09_DIR / "02-ocsf-secops-correlator.py"
EVENTS_FILE = CH09_DIR / "01-ocsf-events-fixture.json"
PRR_READY_FILE = CH09_DIR / "03-devsecops-prr-ready.json"
PRR_BLOCKED_FILE = CH09_DIR / "04-devsecops-prr-blocked-negative.json"


def _load_correlator():
    """Load 02-ocsf-secops-correlator.py dynamically."""
    spec = util.spec_from_file_location(
        "ocsf_correlator_lab", CORRELATOR_FILE
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {CORRELATOR_FILE}")
    mod = util.module_from_spec(spec)
    sys.modules["ocsf_correlator_lab"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_ocsf_four_class_join_and_hitl_quarantine_pr() -> None:
    """Verify SQLite :memory: 4-class join & HITL NetworkPolicy PR."""
    mod = _load_correlator()
    inc = mod.load_and_correlate_ocsf(EVENTS_FILE)

    assert inc["incident_id"] == "inc-orderflow-09"
    assert inc["ocsf_classes"] == [1007, 2002, 2003, 2004]
    assert inc["tetragon_sigkill"] is True
    assert inc["post_syscall_bytes"] == 0
    assert inc["epss_score"] == 0.87
    assert inc["reachable"] is True
    assert inc["control_id"] == "CKV_AWS_393"
    assert inc["source_handoff"] == "vol08-bedrock-guardrails-2004"

    pr = mod.draft_hitl_quarantine_pr(inc)
    assert pr["automerge"] is False
    assert pr["hitl_signoff_required"] is True
    netpol = pr["network_policy"]
    assert netpol["kind"] == "NetworkPolicy"
    assert netpol["metadata"]["namespace"] == "orderflow-prod"
    assert netpol["spec"]["ingress"] == []
    assert netpol["spec"]["egress"] == []


def test_purple_team_drills_and_20_point_prr_gate() -> None:
    """Verify 10 Purple-Team drills & 20/20 PRR threshold."""
    mod = _load_correlator()
    purple = mod.run_purple_team_drills()

    assert purple["total_drills"] == 10
    assert purple["tp_detection_rate"] == 1.0
    assert purple["in_kernel_prevention_rate"] == 1.0
    assert purple["false_positive_rate"] == 0.0
    assert purple["mean_time_to_isolate_sec"] < 1.0

    ready = json.loads(PRR_READY_FILE.read_text(encoding="utf-8"))
    r_spec = ready["spec"]
    assert ready["kind"] == "DevSecOpsPRRAssessment"
    assert r_spec["score_passed"] == 20
    assert r_spec["total_checks"] == 20
    assert len(r_spec["prr_checks"]) == 20
    assert r_spec["ocsf_classes"] == [1007, 2002, 2003, 2004]
    assert r_spec["purple_team_validated"] is True

    blocked = json.loads(PRR_BLOCKED_FILE.read_text(encoding="utf-8"))
    b_spec = blocked["spec"]
    assert b_spec["score_passed"] < 20
    assert len(b_spec["ocsf_classes"]) < 4
    assert b_spec["purple_team_validated"] is False


def main() -> int:
    """Run Ch09 OCSF, Purple-Team & PRR verification standalone."""
    test_ocsf_four_class_join_and_hitl_quarantine_pr()
    test_purple_team_drills_and_20_point_prr_gate()
    print(json.dumps({"ch09_ocsf_prr": "PASS"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
