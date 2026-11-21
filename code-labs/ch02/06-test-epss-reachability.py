#!/usr/bin/env python3
"""Pytest verification for Ch02 EPSS v4, KEV, Reachability & OpenVEX."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any


CH02_DIR = Path(__file__).resolve().parent


def _load_triage_module() -> Any:
    mod_path = CH02_DIR / "02-epss-kev-reachability-triage.py"
    spec = importlib.util.spec_from_file_location("ch02_triage", mod_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_triage_cuts_noise_by_85_percent() -> None:
    triage = _load_triage_module()
    sample = json.loads(
        (CH02_DIR / "01-trivy-sample-findings.json").read_text("utf-8")
    )
    result = triage.triage_findings(
        sample["findings"],
        epss_threshold=0.50,
        artifact=sample["artifact"],
    )
    assert result["total_findings"] == 20
    assert len(result["actionable"]) == 3
    assert len(result["suppressed"]) == 17
    assert result["noise_reduction_pct"] == 85.0


def test_sub7_kev_finding_is_elevated() -> None:
    triage = _load_triage_module()
    sample = json.loads(
        (CH02_DIR / "01-trivy-sample-findings.json").read_text("utf-8")
    )
    result = triage.triage_findings(
        sample["findings"], epss_threshold=0.5
    )
    by_id = {item["cve_id"]: item for item in result["actionable"]}
    assert "CVE-2026-4101" in by_id
    kev_item = by_id["CVE-2026-4101"]
    assert kev_item["cvss"] < 7.0
    assert kev_item["kev"] is True
    assert kev_item["priority"] == "P0_KEV_FLOOR"


def test_unreachable_critical_cvss_suppressed_with_openvex() -> None:
    triage = _load_triage_module()
    sample = json.loads(
        (CH02_DIR / "01-trivy-sample-findings.json").read_text("utf-8")
    )
    result = triage.triage_findings(
        sample["findings"], epss_threshold=0.5
    )
    suppressed_high = [
        item for item in result["suppressed"] if item["cvss"] >= 9.0
    ]
    assert len(suppressed_high) >= 3
    stmts = {
        stmt["vulnerability"]["name"]: stmt
        for stmt in result["openvex"]["statements"]
    }
    for item in suppressed_high:
        stmt = stmts[item["cve_id"]]
        assert stmt["status"] == "not_affected"
        assert (
            stmt["justification"] == "vulnerable_code_not_in_execute_path"
        )


def test_standalone_openvex_v020_valid_with_qualified_purls() -> None:
    vex = json.loads(
        (CH02_DIR / "03-orderflow-openvex-valid.json").read_text("utf-8")
    )
    assert vex["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert vex["author"] == "Kien Nguyen"
    assert vex["version"] == 1
    assert len(vex["statements"]) == 17
    for stmt in vex["statements"]:
        assert stmt["status"] == "not_affected"
        assert (
            stmt["justification"] == "vulnerable_code_not_in_execute_path"
        )
        prod = stmt["products"][0]
        assert prod["@id"].startswith("pkg:oci/orderflow-api@sha256:")
        assert "?" in prod["@id"]
        sub_id = prod["subcomponents"][0]["@id"]
        assert sub_id.startswith("pkg:")
