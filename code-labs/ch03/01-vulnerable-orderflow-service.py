#!/usr/bin/env python3
"""OrderFlow Discount Config Loader and Pin Verification Helpers.

Provides a deterministic safe-vs-unsafe YAML deserialization fixture
plus strict dependency pin verification used by the Ch03 multi-agent
remediation harness.
"""

from __future__ import annotations

from typing import Any
import yaml


VALID_DISCOUNT_YAML = "discount_pct: 15\nmin_subtotal: 50.0\n"
UNTRUSTED_TAG_PAYLOAD = (
    "discount_pct: !!python/object/apply:builtins.sum [[45, 50]]\n"
    "min_subtotal: 10.0\n"
)


def load_discount_config(
    raw_yaml: str, safe_mode: bool = False
) -> dict[str, Any]:
    """Load OrderFlow discount policy using safe or unsafe YAML loader."""
    if safe_mode:
        data = yaml.safe_load(raw_yaml)
    else:
        data = yaml.load(raw_yaml, Loader=yaml.Loader)
    if not isinstance(data, dict):
        raise ValueError("Discount config must decode to a mapping")
    return data


def compute_order_total(
    subtotal: float, raw_yaml: str, safe_mode: bool = False
) -> float:
    """Apply configured discount percentage to an OrderFlow subtotal."""
    cfg = load_discount_config(raw_yaml, safe_mode=safe_mode)
    min_sub = float(cfg.get("min_subtotal", 0.0))
    pct = float(cfg.get("discount_pct", 0.0))
    if pct < 0.0 or pct > 50.0:
        raise ValueError(f"Discount pct out of bounds: {pct}")
    if subtotal < min_sub:
        return round(subtotal, 2)
    return round(subtotal * (1.0 - pct / 100.0), 2)


def parse_pin(pin_spec: str) -> tuple[str, tuple[int, int, int]]:
    """Parse an exact pkg==major.minor.patch dependency pin."""
    if "==" not in pin_spec:
        raise ValueError(f"Exact '==' pin required, got: {pin_spec}")
    pkg, ver_str = pin_spec.split("==", maxsplit=1)
    parts = ver_str.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Expected major.minor.patch, got: {ver_str}")
    semver = (int(parts[0]), int(parts[1]), int(parts[2]))
    return pkg.strip().lower(), semver


def is_minimal_pin_upgrade(old_pin: str, new_pin: str) -> bool:
    """Allow only same-major security upgrades without downgrades."""
    old_pkg, old_ver = parse_pin(old_pin)
    new_pkg, new_ver = parse_pin(new_pin)
    if old_pkg != new_pkg:
        return False
    if new_ver[0] != old_ver[0]:
        return False
    return new_ver > old_ver


def run_security_assertion(safe_mode: bool) -> dict[str, Any]:
    """Verify untrusted YAML object tags fail on safe deserialization."""
    try:
        parsed = load_discount_config(
            UNTRUSTED_TAG_PAYLOAD, safe_mode=safe_mode
        )
    except yaml.constructor.ConstructorError as exc:
        return {
            "exploit_blocked": True,
            "safe_mode": safe_mode,
            "error": type(exc).__name__,
        }
    return {
        "exploit_blocked": False,
        "safe_mode": safe_mode,
        "decoded_pct": parsed.get("discount_pct"),
    }
