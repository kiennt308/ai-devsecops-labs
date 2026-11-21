"""Falco v0.45.2 Rule Linter, Engine Gate & Syscall Event Replay.

Copyright (c) 2026 Kien Nguyen
Repository: https://github.com/kiennt308/ai-devsecops-labs
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any
import yaml

CH07_DIR = Path(__file__).resolve().parent
RULES_PATH = CH07_DIR / "01-falco-v045-orderflow-rules.yaml"
VALID_CFG_PATH = CH07_DIR / "02-falco-engine-config-valid.yaml"
NEG_CFG_PATH = CH07_DIR / "03-falco-legacy-probe-negative.yaml"

RETIRED_ENGINES = {"ebpf", "kmod", "gvisor", "legacy_ebpf_probe"}
REQUIRED_RULES = {
    "OrderFlow Sensitive Shadow Read",
    "OrderFlow Temp Binary Exec",
    "OrderFlow Shell Spawn From Microservice",
}
REQUIRED_OPERATORS = ("oneof", "anyof", "allof")


def _parse_semver(version_str: str) -> tuple[int, int, int]:
    """Parse Falco version string into numeric major/minor/patch."""
    cleaned = version_str.lstrip("v")
    parts = [int(x) for x in re.findall(r"\d+", cleaned)[:3]]
    while len(parts) < 3:
        parts.append(0)
    return (parts[0], parts[1], parts[2])


def lint_falco_engine_config(config_path: Path) -> dict[str, Any]:
    """Validate Falco v0.45.2 modern_ebpf engine and socket contract."""
    doc = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if (
        not isinstance(doc, dict)
        or doc.get("kind") != "FalcoRuntimeConfig"
    ):
        errors.append("kind must be FalcoRuntimeConfig")
        return {"valid": False, "errors": errors}

    spec = doc.get("spec", {})
    ver = str(spec.get("falco_version", "v0.0.0"))
    if _parse_semver(ver) < (0, 44, 0):
        errors.append(f"falco_version {ver} is below v0.44+ baseline")

    engine_kind = str(spec.get("engine", {}).get("kind", ""))
    if engine_kind in RETIRED_ENGINES or engine_kind != "modern_ebpf":
        errors.append(
            f"engine.kind '{engine_kind}' retired; use modern_ebpf"
        )

    if spec.get("legacy_grpc_server_enabled") is True:
        errors.append("legacy_grpc_server_enabled removed in v0.44+")

    if spec.get("dry_run_validated") is not True:
        errors.append("dry_run_validated must be true")

    reload_cfg = spec.get("reload", {})
    if reload_cfg.get("unix_socket_protected") is not True:
        errors.append("reload.unix_socket_protected must be true")
    if reload_cfg.get("endpoint") != "GET /reload":
        errors.append("reload.endpoint must be 'GET /reload'")

    return {
        "file": config_path.name,
        "valid": len(errors) == 0,
        "falco_version": ver,
        "engine_kind": engine_kind,
        "errors": errors,
    }


def _load_falco_rules(rules_path: Path) -> dict[str, Any]:
    """Parse Falco YAML sequence into lists, macros, and rules."""
    items = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    if not isinstance(items, list):
        raise ValueError("Falco rules YAML must be a sequence")
    lists: dict[str, list[str]] = {}
    macros: dict[str, str] = {}
    rules: list[dict[str, Any]] = []
    for entry in items:
        if "list" in entry:
            lists[entry["list"]] = list(entry.get("items", []))
        elif "macro" in entry:
            macros[entry["macro"]] = str(entry.get("condition", ""))
        elif "rule" in entry:
            rules.append(entry)
    return {"lists": lists, "macros": macros, "rules": rules}


def lint_falco_rules(rules_path: Path) -> dict[str, Any]:
    """Validate modern Falco v0.45+ lists, operators & MITRE tags."""
    parsed = _load_falco_rules(rules_path)
    lists = parsed["lists"]
    rules = parsed["rules"]
    errors: list[str] = []

    for req_list in ("orderflow_ns", "orderflow_trusted_bins"):
        if req_list not in lists or not lists[req_list]:
            errors.append(f"Missing or empty Falco list: {req_list}")

    rule_names = {r["rule"] for r in rules}
    missing_rules = sorted(REQUIRED_RULES - rule_names)
    if missing_rules:
        errors.append(f"Missing required rules: {missing_rules}")

    all_conds = " ".join(
        str(r.get("condition", "")) for r in rules
    ) + " " + " ".join(parsed["macros"].values())
    ops_found = [op for op in REQUIRED_OPERATORS if op in all_conds]
    if set(ops_found) != set(REQUIRED_OPERATORS):
        errors.append(
            f"Expected operators {REQUIRED_OPERATORS}, got {ops_found}"
        )

    for rule in rules:
        tags = set(rule.get("tags", []))
        has_tactic = bool(
            tags & {"mitre_execution", "mitre_credential_access"}
        )
        has_tech = bool(tags & {"T1059", "T1003"})
        if not (has_tactic and has_tech):
            errors.append(f"Rule '{rule['rule']}' missing MITRE tags")

    return {
        "file": rules_path.name,
        "valid": len(errors) == 0,
        "rule_count": len(rules),
        "rule_names": sorted(rule_names),
        "operators_found": ops_found,
        "errors": errors,
    }


def default_syscall_events() -> list[dict[str, Any]]:
    """Return realistic OrderFlow syscall replay fixtures."""
    return [
        {
            "event_id": "ev-shadow-read",
            "k8s.ns.name": "orderflow-prod",
            "evt.type": "openat",
            "evt.is_open_read": True,
            "evt.dir": "<",
            "fd.name": "/etc/shadow",
            "proc.name": "cat",
            "proc.exepath": "/usr/bin/cat",
            "expected_alert": True,
        },
        {
            "event_id": "ev-tmp-dropper",
            "k8s.ns.name": "orderflow-prod",
            "evt.type": "execve",
            "evt.is_open_read": False,
            "evt.dir": "<",
            "fd.name": "",
            "proc.name": "dropper",
            "proc.exepath": "/tmp/dropper",
            "expected_alert": True,
        },
        {
            "event_id": "ev-shell-spawn",
            "k8s.ns.name": "orderflow-payments",
            "evt.type": "execve",
            "evt.is_open_read": False,
            "evt.dir": "<",
            "fd.name": "",
            "proc.name": "sh",
            "proc.exepath": "/bin/sh",
            "expected_alert": True,
        },
        {
            "event_id": "ev-uvicorn-health",
            "k8s.ns.name": "orderflow-prod",
            "evt.type": "execve",
            "evt.is_open_read": False,
            "evt.dir": "<",
            "fd.name": "/app/health.json",
            "proc.name": "uvicorn",
            "proc.exepath": "/usr/local/bin/uvicorn",
            "expected_alert": False,
        },
        {
            "event_id": "ev-api-read-cfg",
            "k8s.ns.name": "orderflow-prod",
            "evt.type": "openat",
            "evt.is_open_read": True,
            "evt.dir": "<",
            "fd.name": "/app/config.yaml",
            "proc.name": "orderflow-api",
            "proc.exepath": "/app/orderflow-api",
            "expected_alert": False,
        },
    ]


def replay_syscall_events(
    rules_path: Path,
    events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate syscall fixtures against loaded Falco lists & rules."""
    parsed = _load_falco_rules(rules_path)
    lists = parsed["lists"]
    rules_by_name = {r["rule"]: r for r in parsed["rules"]}
    allowed_ns = set(lists["orderflow_ns"])
    trusted_bins = set(lists["orderflow_trusted_bins"])
    shells = set(lists["orderflow_shells"])
    stream = events if events is not None else default_syscall_events()

    hits: list[dict[str, Any]] = []
    tp = fp = fn = tn = 0

    for ev in stream:
        ns_ok = ev.get("k8s.ns.name") in allowed_ns
        untrusted = ev.get("proc.exepath") not in trusted_bins
        matched: list[str] = []

        if ns_ok and untrusted:
            is_open = (
                ev.get("evt.type") in {"open", "openat", "openat2"}
                and ev.get("evt.is_open_read") is True
                and ev.get("evt.dir") == "<"
            )
            if is_open and ev.get("fd.name") in {
                "/etc/shadow",
                "/etc/gshadow",
            }:
                matched.append("OrderFlow Sensitive Shadow Read")

            is_exec = (
                ev.get("evt.type") in {"execve", "execveat"}
                and ev.get("evt.dir") == "<"
            )
            exepath = str(ev.get("proc.exepath", ""))
            if is_exec and exepath.startswith(
                ("/tmp/", "/dev/shm/", "/var/tmp/")
            ):
                matched.append("OrderFlow Temp Binary Exec")
            if is_exec and ev.get("proc.name") in shells:
                matched.append("OrderFlow Shell Spawn From Microservice")

        alerted = len(matched) > 0
        expected = bool(ev.get("expected_alert", False))
        if alerted and expected:
            tp += 1
        elif alerted and not expected:
            fp += 1
        elif not alerted and expected:
            fn += 1
        else:
            tn += 1

        if alerted:
            rule_obj = rules_by_name[matched[0]]
            hits.append(
                {
                    "event_id": ev["event_id"],
                    "rule": matched[0],
                    "priority": rule_obj["priority"],
                    "tags": rule_obj["tags"],
                }
            )

    return {
        "events_replayed": len(stream),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "hits": hits,
    }


def main() -> int:
    """Run Falco v0.45.2 linting and syscall replay verification."""
    cfg_ok = lint_falco_engine_config(VALID_CFG_PATH)
    cfg_bad = lint_falco_engine_config(NEG_CFG_PATH)
    rules_lint = lint_falco_rules(RULES_PATH)
    replay = replay_syscall_events(RULES_PATH)

    assert cfg_ok["valid"] is True
    assert cfg_bad["valid"] is False
    assert rules_lint["valid"] is True
    assert replay["false_positives"] == 0
    assert replay["false_negatives"] == 0

    print(
        json.dumps(
            {
                "engine_valid": cfg_ok,
                "engine_negative": cfg_bad,
                "rules_lint": rules_lint,
                "replay": replay,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
