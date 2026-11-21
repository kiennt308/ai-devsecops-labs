#!/usr/bin/env python3
"""CycloneDX 1.7 AI-BOM, SPDX 3.0.1, & Kyverno v1.19 CEL Validator.

Validates AI-BOM completeness (model weights, prompt data, MCP server
digest), SPDX 3.0.1 JSON-LD AI/Dataset profiles, and Kyverno v1.19
CEL policies while rejecting deprecated kyverno.io/v1 ClusterPolicy.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any
import yaml


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SPDX_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
EXPECTED_MODEL_SHA256 = (
    "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
)


def _extract_sha256(component: dict[str, Any]) -> str | None:
    for entry in component.get("hashes", []):
        if entry.get("alg") == "SHA-256":
            val = entry.get("content", "")
            if isinstance(val, str) and SHA256_RE.match(val):
                return val
    return None


def validate_cyclonedx_aibom(
    bom: dict[str, Any],
    expected_model_sha256: str | None = EXPECTED_MODEL_SHA256,
) -> dict[str, Any]:
    """Validate CycloneDX 1.7 AI-BOM required components and hashes."""
    errors: list[str] = []
    if bom.get("bomFormat") != "CycloneDX":
        errors.append("INVALID_BOM_FORMAT")
    if bom.get("specVersion") != "1.7":
        errors.append("INVALID_CYCLONEDX_VERSION")

    comps = bom.get("components", [])
    by_type: dict[str, list[dict[str, Any]]] = {}
    for comp in comps:
        by_type.setdefault(comp.get("type", ""), []).append(comp)

    models = by_type.get("machine-learning-model", [])
    if not models:
        errors.append("MISSING_ML_MODEL_COMPONENT")
    else:
        model_hash = _extract_sha256(models[0])
        if model_hash is None:
            errors.append("INVALID_MODEL_SHA256")
        elif (
            expected_model_sha256 is not None
            and model_hash != expected_model_sha256
        ):
            errors.append("MODEL_WEIGHT_HASH_MISMATCH")

    data_comps = by_type.get("data", [])
    if not data_comps or _extract_sha256(data_comps[0]) is None:
        errors.append("MISSING_OR_INVALID_PROMPT_DATA_HASH")

    apps = by_type.get("application", [])
    mcp_apps = [a for a in apps if "mcp" in a.get("name", "").lower()]
    if not mcp_apps:
        errors.append("MISSING_MCP_APPLICATION_COMPONENT")
    else:
        mcp = mcp_apps[0]
        purl = str(mcp.get("purl", ""))
        if "@sha256:" not in purl:
            errors.append("MISSING_MCP_PURL_SHA256_DIGEST")
        if _extract_sha256(mcp) is None:
            errors.append("MISSING_MCP_SHA256_HASH")

    return {
        "valid": len(errors) == 0,
        "spec": "CycloneDX-1.7",
        "component_count": len(comps),
        "errors": errors,
    }


def validate_spdx301_ai_profile(doc: dict[str, Any]) -> dict[str, Any]:
    """Validate SPDX 3.0.1 JSON-LD graph for AI & Dataset profiles."""
    errors: list[str] = []
    if doc.get("@context") != SPDX_CONTEXT:
        errors.append("INVALID_SPDX_301_CONTEXT")

    graph = doc.get("@graph", [])
    by_type = {node.get("type"): node for node in graph if "type" in node}
    if "SpdxDocument" not in by_type:
        errors.append("MISSING_SPDX_DOCUMENT")

    ai_pkg = by_type.get("ai_AIPackage")
    if not ai_pkg:
        errors.append("MISSING_AI_PACKAGE")
    else:
        if not ai_pkg.get("typeOfModel"):
            errors.append("MISSING_TYPE_OF_MODEL")
        if not ai_pkg.get("informationAboutTraining"):
            errors.append("MISSING_TRAINING_INFO")

    ds_pkg = by_type.get("dataset_DatasetPackage")
    if not ds_pkg:
        errors.append("MISSING_DATASET_PACKAGE")
    else:
        if not ds_pkg.get("datasetType"):
            errors.append("MISSING_DATASET_TYPE")
        lic = ds_pkg.get("declaredLicense") or ds_pkg.get("license")
        if lic != "Apache-2.0":
            errors.append("DATASET_LICENSE_NOT_APACHE_20")

    return {
        "valid": len(errors) == 0,
        "spec": "SPDX-3.0.1",
        "graph_nodes": len(graph),
        "errors": errors,
    }


def validate_kyverno_policies(
    docs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Accept Kyverno v1.19 CEL policies; reject legacy ClusterPolicy."""
    errors: list[str] = []
    accepted: list[str] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        api_ver = doc.get("apiVersion", "")
        kind = doc.get("kind", "")
        name = doc.get("metadata", {}).get("name", "unnamed")
        if api_ver == "kyverno.io/v1" or kind in {
            "ClusterPolicy",
            "Policy",
        }:
            errors.append(f"KYVERNO_CLUSTERPOLICY_DEPRECATED:{name}")
            continue
        if api_ver != "policies.kyverno.io/v1":
            errors.append(f"KYVERNO_CEL_GROUP_INVALID:{name}")
            continue

        spec = doc.get("spec", {})
        cel_exprs = " ".join(
            str(v.get("expression", ""))
            for v in spec.get("validations", [])
        )
        if kind == "ImageValidatingPolicy":
            if not spec.get("verifyImages"):
                errors.append(f"MISSING_VERIFY_IMAGES:{name}")
                continue
            if "@sha256:" not in cel_exprs:
                errors.append(f"MISSING_SHA256_CEL_RULE:{name}")
                continue
        elif kind == "ValidatingPolicy":
            if "orderflow.io/aibom-digest" not in cel_exprs:
                errors.append(f"MISSING_AIBOM_LABEL_CEL:{name}")
                continue
        else:
            errors.append(f"UNSUPPORTED_POLICY_KIND:{kind}")
            continue
        accepted.append(f"{kind}/{name}")

    return {
        "valid": len(errors) == 0 and len(accepted) > 0,
        "accepted_policies": accepted,
        "errors": errors,
    }


def main() -> None:
    ch05_dir = Path(__file__).resolve().parent
    cdx = json.loads(
        (ch05_dir / "01-orderflow-cyclonedx17-aibom.json").read_text(
            "utf-8"
        )
    )
    spdx = json.loads(
        (ch05_dir / "02-orderflow-spdx301-ai-profile.jsonld").read_text(
            "utf-8"
        )
    )
    cel_docs = list(
        yaml.safe_load_all(
            (ch05_dir / "03-kyverno-v119-cel-policies-valid.yaml")
            .read_text("utf-8")
        )
    )
    legacy_docs = list(
        yaml.safe_load_all(
            (ch05_dir / "04-kyverno-legacy-clusterpolicy-negative.yaml")
            .read_text("utf-8")
        )
    )

    summary = {
        "author": "Kien Nguyen",
        "cyclonedx_17": validate_cyclonedx_aibom(cdx),
        "spdx_301": validate_spdx301_ai_profile(spdx),
        "kyverno_v119_cel": validate_kyverno_policies(cel_docs),
        "kyverno_legacy_negative": validate_kyverno_policies(legacy_docs),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
