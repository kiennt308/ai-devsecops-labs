#!/usr/bin/env python3
"""Pytest verification for Ch05 AI-BOM & Kyverno v1.19 Admission."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any
import yaml


CH05_DIR = Path(__file__).resolve().parent


def _load_validator() -> Any:
    mod_path = CH05_DIR / "05-aibom-kyverno-validator.py"
    spec = importlib.util.spec_from_file_location("ch05_val", mod_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_valid_aibom_spdx_and_kyverno_v119_pass() -> None:
    val = _load_validator()
    cdx = json.loads(
        (CH05_DIR / "01-orderflow-cyclonedx17-aibom.json").read_text(
            "utf-8"
        )
    )
    spdx = json.loads(
        (CH05_DIR / "02-orderflow-spdx301-ai-profile.jsonld").read_text(
            "utf-8"
        )
    )
    cel_docs = list(
        yaml.safe_load_all(
            (CH05_DIR / "03-kyverno-v119-cel-policies-valid.yaml")
            .read_text("utf-8")
        )
    )

    assert val.validate_cyclonedx_aibom(cdx)["valid"] is True
    assert val.validate_spdx301_ai_profile(spdx)["valid"] is True
    kyv_res = val.validate_kyverno_policies(cel_docs)
    assert kyv_res["valid"] is True
    assert len(kyv_res["accepted_policies"]) == 2


def test_tampered_model_weight_hash_fails() -> None:
    val = _load_validator()
    cdx = json.loads(
        (CH05_DIR / "01-orderflow-cyclonedx17-aibom.json").read_text(
            "utf-8"
        )
    )
    tampered = copy.deepcopy(cdx)
    for comp in tampered["components"]:
        if comp["type"] == "machine-learning-model":
            comp["hashes"][0]["content"] = "0" * 64
    res = val.validate_cyclonedx_aibom(tampered)
    assert res["valid"] is False
    assert "MODEL_WEIGHT_HASH_MISMATCH" in res["errors"]


def test_missing_mcp_digest_fails() -> None:
    val = _load_validator()
    cdx = json.loads(
        (CH05_DIR / "01-orderflow-cyclonedx17-aibom.json").read_text(
            "utf-8"
        )
    )
    broken = copy.deepcopy(cdx)
    for comp in broken["components"]:
        if comp["type"] == "application":
            comp["purl"] = "pkg:oci/orderflow-mcp:latest"
            comp["hashes"] = []
    res = val.validate_cyclonedx_aibom(broken)
    assert res["valid"] is False
    assert "MISSING_MCP_PURL_SHA256_DIGEST" in res["errors"]
    assert "MISSING_MCP_SHA256_HASH" in res["errors"]


def test_deprecated_kyverno_clusterpolicy_fails() -> None:
    val = _load_validator()
    legacy_docs = list(
        yaml.safe_load_all(
            (CH05_DIR / "04-kyverno-legacy-clusterpolicy-negative.yaml")
            .read_text("utf-8")
        )
    )
    res = val.validate_kyverno_policies(legacy_docs)
    assert res["valid"] is False
    assert any(
        err.startswith("KYVERNO_CLUSTERPOLICY_DEPRECATED:")
        for err in res["errors"]
    )
