#!/usr/bin/env python3
"""Pytest verification for Ch04 SLSA v1.2, DSSE PAE, & Cosign v3."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any


CH04_DIR = Path(__file__).resolve().parent


def _load_verifier() -> Any:
    mod_path = CH04_DIR / "01-slsa-v12-dsse-cosign-verifier.py"
    spec = importlib.util.spec_from_file_location("ch04_ver", mod_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_valid_slsa_v12_dsse_cosign_v3_bundle_passes() -> None:
    ver = _load_verifier()
    digest = hashlib.sha256(b"orderflow-release-1.8.0").hexdigest()
    stmt = ver.build_slsa_v12_statement(
        "oci://registry.orderflow.internal/orderflow-api", digest
    )
    bundle, root = ver.sign_cosign_v3_bundle(stmt)
    assert bundle["mediaType"] == (
        "application/vnd.dev.sigstore.bundle.v0.3+json"
    )
    res = ver.verify_cosign_v3_bundle(bundle, digest, root)
    assert res["verified"] is True
    assert res["slsa_build_track"] == "SLSA v1.2 Build Track Level 3"
    assert res["slsa_source_track"] == "SLSA v1.2 Source Track Level 2"
    assert res["artifact_sha256"] == digest


def test_one_byte_payload_tamper_fails_closed() -> None:
    ver = _load_verifier()
    digest = hashlib.sha256(b"orderflow-release-1.8.0").hexdigest()
    stmt = ver.build_slsa_v12_statement(
        "oci://registry.orderflow.internal/orderflow-api", digest
    )
    bundle, root = ver.sign_cosign_v3_bundle(stmt)
    tampered = json.loads(json.dumps(bundle))
    tampered["dsseEnvelope"]["payload"] = ver.flip_one_base64_byte(
        tampered["dsseEnvelope"]["payload"]
    )
    res = ver.verify_cosign_v3_bundle(tampered, digest, root)
    assert res["verified"] is False
    assert res["reason"].startswith("DSSE_SIGNATURE_FAILED")


def test_one_byte_artifact_digest_tamper_fails_closed() -> None:
    ver = _load_verifier()
    digest = hashlib.sha256(b"orderflow-release-1.8.0").hexdigest()
    stmt = ver.build_slsa_v12_statement(
        "oci://registry.orderflow.internal/orderflow-api", digest
    )
    bundle, root = ver.sign_cosign_v3_bundle(stmt)
    bad_digest = ("a" if digest[0] != "a" else "b") + digest[1:]
    res = ver.verify_cosign_v3_bundle(bundle, bad_digest, root)
    assert res["verified"] is False
    assert res["reason"] == "ARTIFACT_DIGEST_MISMATCH"
