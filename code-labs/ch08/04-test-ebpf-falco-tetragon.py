"""Unified pytest suite for Falco v0.45.2 (Ch07) & Tetragon v1.8 (Ch08).

Copyright (c) 2026 Kien Nguyen
Repository: https://github.com/kiennt308/ai-devsecops-labs
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from importlib import util
import json
from pathlib import Path
import sys

CH08_DIR = Path(__file__).resolve().parent
CH07_DIR = CH08_DIR.parent / "ch07"


def _load_module(mod_name: str, file_path: Path):
    """Load hyphenated lab Python module without leaving caches."""
    spec = util.spec_from_file_location(mod_name, file_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {file_path}")
    mod = util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_falco_v045_linter_and_zero_false_positive_replay() -> None:
    """Ch07: modern_ebpf config & rules pass; legacy probe rejected."""
    falco = _load_module(
        "falco_v045_lab", CH07_DIR / "04-falco-rule-linter-and-replay.py"
    )
    cfg_ok = falco.lint_falco_engine_config(
        CH07_DIR / "02-falco-engine-config-valid.yaml"
    )
    cfg_bad = falco.lint_falco_engine_config(
        CH07_DIR / "03-falco-legacy-probe-negative.yaml"
    )
    rules_res = falco.lint_falco_rules(
        CH07_DIR / "01-falco-v045-orderflow-rules.yaml"
    )
    replay = falco.replay_syscall_events(
        CH07_DIR / "01-falco-v045-orderflow-rules.yaml"
    )

    assert cfg_ok["valid"] is True
    assert cfg_ok["engine_kind"] == "modern_ebpf"
    assert cfg_bad["valid"] is False
    assert len(cfg_bad["errors"]) >= 2

    assert rules_res["valid"] is True
    assert rules_res["rule_count"] == 3
    assert set(rules_res["operators_found"]) == {
        "oneof",
        "anyof",
        "allof",
    }

    assert replay["true_positives"] == 3
    assert replay["false_positives"] == 0
    assert replay["false_negatives"] == 0
    assert replay["true_negatives"] == 2


def test_tetragon_v18_policy_and_synchronous_sigkill() -> None:
    """Ch08: TracingPolicyNamespaced, Sigkill & TOCTOU race closure."""
    tet = _load_module(
        "tetragon_v18_lab",
        CH08_DIR / "03-tetragon-kernel-enforcer-sim.py",
    )
    ok = tet.validate_tracing_policy(
        CH08_DIR / "01-tetragon-v18-tracingpolicy-valid.yaml"
    )
    bad = tet.validate_tracing_policy(
        CH08_DIR / "02-tetragon-unscoped-tcp-negative.yaml"
    )
    sim = tet.simulate_kernel_enforcement(
        CH08_DIR / "01-tetragon-v18-tracingpolicy-valid.yaml"
    )

    assert ok["valid"] is True
    assert ok["namespace"] == "orderflow-prod"
    assert bad["valid"] is False
    assert len(bad["errors"]) >= 3

    race = sim["race_comparison"]
    assert race["falco_async"]["post_syscall_exfil_bytes"] > 0
    assert race["tetragon_v18_sync"]["post_syscall_exfil_bytes"] == 0
    assert race["tetragon_v18_sync"]["toctou_race_closed"] is True

    assert sim["fixtures_tested"] == 5
    assert sim["sigkill_count"] == 4
    assert sim["false_positives"] == 0
    assert sim["false_negatives"] == 0

    by_id = {row["id"]: row for row in sim["results"]}
    assert by_id["allowed_worker"]["action"] == "ALLOW"
    for blocked in (
        "shadow_open",
        "distroless_sh_c",
        "tmp_dropper_exec",
        "stateful_curl_pipe_sh",
    ):
        assert by_id[blocked]["action"] == "SIGKILL"
        assert by_id[blocked]["post_syscall_bytes"] == 0


def main() -> int:
    """Execute Ch07 + Ch08 assertions as standalone runner."""
    test_falco_v045_linter_and_zero_false_positive_replay()
    test_tetragon_v18_policy_and_synchronous_sigkill()
    print(json.dumps({"ch07_falco": "PASS", "ch08_tetragon": "PASS"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
