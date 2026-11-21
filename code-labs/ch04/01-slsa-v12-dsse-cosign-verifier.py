#!/usr/bin/env python3
"""SLSA v1.2, in-toto v1 DSSE, and Cosign v3.1.4 Bundle Verifier.

Generates an in-toto v1 SLSA v1.2 (Build Track L3 + Source Track L2)
attestation, wraps it in a DSSE PAE envelope signed with ECDSA P-256,
packages a Cosign v3.1.4 .bundle JSON with offline trusted_root, and
verifies fail-closed behavior against 1-byte payload or digest tampering.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


INTOTO_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
COSIGN_BUNDLE_MEDIA = "application/vnd.dev.sigstore.bundle.v0.3+json"
TRUSTED_ROOT_MEDIA = (
    "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
)
REPO_URL = "https://github.com/kiennt308/ai-devsecops-labs"
BUILD_TRACK_LABEL = "SLSA v1.2 Build Track Level 3"
SOURCE_TRACK_LABEL = "SLSA v1.2 Source Track Level 2"


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Encode Pre-Authentication Encoding (PAE) per DSSE v1 spec."""
    pt_bytes = payload_type.encode("utf-8")
    prefix = (
        f"DSSEv1 {len(pt_bytes)} ".encode("utf-8")
        + pt_bytes
        + f" {len(payload)} ".encode("utf-8")
    )
    return prefix + payload


def build_slsa_v12_statement(
    artifact_name: str, artifact_sha256: str
) -> dict[str, Any]:
    """Build an in-toto v1 statement with SLSA v1.2 provenance."""
    return {
        "_type": INTOTO_TYPE,
        "subject": [
            {
                "name": artifact_name,
                "digest": {"sha256": artifact_sha256},
            }
        ],
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://slsa.dev/container-build/v1",
                "externalParameters": {
                    "repository": REPO_URL,
                    "slsa_spec_version": "1.2",
                    "build_track": BUILD_TRACK_LABEL,
                    "source_track": SOURCE_TRACK_LABEL,
                },
                "internalParameters": {
                    "author": "Kien Nguyen",
                    "cosign_version": "v3.1.4",
                },
                "resolvedDependencies": [
                    {
                        "uri": f"git+{REPO_URL}",
                        "digest": {"gitCommit": "7e1b9c2a4d8f0123"},
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/kiennt308/slsa12-runner"
                },
                "metadata": {
                    "invocationId": "inv-orderflow-slsa12-001",
                    "startedOn": "2026-11-20T00:00:00Z",
                    "finishedOn": "2026-11-20T00:01:12Z",
                },
                "byproducts": [
                    {
                        "name": "orderflow-api.bundle",
                        "mediaType": COSIGN_BUNDLE_MEDIA,
                    }
                ],
            },
        },
    }


def sign_cosign_v3_bundle(
    statement: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Sign statement in DSSE PAE with ephemeral ECDSA P-256 key."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = hashlib.sha256(public_pem).hexdigest()[:16]

    payload_bytes = json.dumps(
        statement, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    pae = dsse_pae(DSSE_PAYLOAD_TYPE, payload_bytes)
    sig_bytes = private_key.sign(pae, ec.ECDSA(hashes.SHA256()))

    bundle = {
        "mediaType": COSIGN_BUNDLE_MEDIA,
        "verificationMaterial": {
            "publicKey": {"hint": f"orderflow-{key_id}"},
            "tlogEntries": [
                {
                    "logIndex": "904218",
                    "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                }
            ],
        },
        "dsseEnvelope": {
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "signatures": [
                {
                    "keyid": key_id,
                    "sig": base64.b64encode(sig_bytes).decode("ascii"),
                }
            ],
        },
    }
    trusted_root = {
        "mediaType": TRUSTED_ROOT_MEDIA,
        "keys": {
            key_id: {
                "algorithm": "ECDSA_P256_SHA256",
                "pem": public_pem.decode("ascii"),
            }
        },
    }
    return bundle, trusted_root


def verify_cosign_v3_bundle(
    bundle: dict[str, Any],
    expected_sha256: str,
    trusted_root: dict[str, Any],
) -> dict[str, Any]:
    """Fail-closed verifier for Cosign v3.1.4 bundle + SLSA v1.2."""
    if bundle.get("mediaType") != COSIGN_BUNDLE_MEDIA:
        return {"verified": False, "reason": "INVALID_BUNDLE_MEDIA_TYPE"}

    env = bundle.get("dsseEnvelope", {})
    if env.get("payloadType") != DSSE_PAYLOAD_TYPE:
        return {"verified": False, "reason": "INVALID_DSSE_PAYLOAD_TYPE"}

    sigs = env.get("signatures", [])
    if not sigs:
        return {"verified": False, "reason": "MISSING_DSSE_SIGNATURE"}

    key_id = sigs[0].get("keyid", "")
    key_entry = trusted_root.get("keys", {}).get(key_id)
    if not key_entry:
        return {"verified": False, "reason": "UNTRUSTED_KEY_ID"}

    try:
        payload_bytes = base64.b64decode(env["payload"], validate=True)
        sig_bytes = base64.b64decode(sigs[0]["sig"], validate=True)
        pub_key = serialization.load_pem_public_key(
            key_entry["pem"].encode("ascii")
        )
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            return {"verified": False, "reason": "INVALID_KEY_TYPE"}
        pae = dsse_pae(env["payloadType"], payload_bytes)
        pub_key.verify(sig_bytes, pae, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, KeyError, ValueError) as exc:
        return {
            "verified": False,
            "reason": f"DSSE_SIGNATURE_FAILED:{type(exc).__name__}",
        }

    try:
        stmt = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"verified": False, "reason": "CORRUPT_STATEMENT_JSON"}

    if stmt.get("_type") != INTOTO_TYPE:
        return {"verified": False, "reason": "INVALID_INTOTO_TYPE"}
    if stmt.get("predicateType") != SLSA_PREDICATE_TYPE:
        return {"verified": False, "reason": "INVALID_SLSA_PREDICATE"}

    pred = stmt.get("predicate", {})
    bdef = pred.get("buildDefinition", {})
    rdet = pred.get("runDetails", {})
    ext = bdef.get("externalParameters", {})
    if not bdef or not rdet:
        return {"verified": False, "reason": "MISSING_SLSA_SECTIONS"}
    if ext.get("build_track") != BUILD_TRACK_LABEL:
        return {"verified": False, "reason": "MISSING_SLSA_BUILD_TRACK"}
    if ext.get("source_track") != SOURCE_TRACK_LABEL:
        return {"verified": False, "reason": "MISSING_SLSA_SOURCE_TRACK"}

    subjects = stmt.get("subject", [])
    matched = any(
        s.get("digest", {}).get("sha256") == expected_sha256
        for s in subjects
    )
    if not matched:
        return {"verified": False, "reason": "ARTIFACT_DIGEST_MISMATCH"}

    return {
        "verified": True,
        "author": "Kien Nguyen",
        "slsa_build_track": BUILD_TRACK_LABEL,
        "slsa_source_track": SOURCE_TRACK_LABEL,
        "artifact_sha256": expected_sha256,
        "key_id": key_id,
    }


def flip_one_base64_byte(b64_text: str) -> str:
    """Mutate one decoded payload byte to simulate tampering."""
    raw = bytearray(base64.b64decode(b64_text))
    raw[len(raw) // 2] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def main() -> None:
    artifact_digest = hashlib.sha256(
        b"orderflow-api-v1.8.0-distroless-oci-image"
    ).hexdigest()
    stmt = build_slsa_v12_statement(
        "oci://registry.orderflow.internal/orderflow-api",
        artifact_digest,
    )
    bundle, trusted_root = sign_cosign_v3_bundle(stmt)

    clean_res = verify_cosign_v3_bundle(
        bundle, artifact_digest, trusted_root
    )

    tampered_bundle = json.loads(json.dumps(bundle))
    tampered_bundle["dsseEnvelope"]["payload"] = flip_one_base64_byte(
        tampered_bundle["dsseEnvelope"]["payload"]
    )
    payload_tamper_res = verify_cosign_v3_bundle(
        tampered_bundle, artifact_digest, trusted_root
    )

    tampered_digest = ("0" if artifact_digest[0] != "0" else "1") + (
        artifact_digest[1:]
    )
    digest_tamper_res = verify_cosign_v3_bundle(
        bundle, tampered_digest, trusted_root
    )

    print(
        json.dumps(
            {
                "clean_verify": clean_res,
                "payload_tamper_verify": payload_tamper_res,
                "digest_tamper_verify": digest_tamper_res,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
