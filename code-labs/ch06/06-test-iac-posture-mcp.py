"""Live Streamable HTTP MCP test for OrderFlow IaC & Prowler CIS v8.1.

Copyright (c) 2026 Kien Nguyen
Repository: https://github.com/kiennt308/ai-devsecops-labs
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import asyncio
from importlib import util
import json
from pathlib import Path
import socket
import sys
import threading
import time
from typing import Any
from mcp import Client
import pytest
import uvicorn

CH06_DIR = Path(__file__).resolve().parent
SERVER_FILE = CH06_DIR / "03-prowler-mcp-posture-server.py"
SECURE_TF = CH06_DIR / "01-orderflow-iac-secure.tf"
FLAWED_TF = CH06_DIR / "02-orderflow-iac-flawed-negative.tf"
DEFAULT_PORT = 18806


def _load_server_module():
    """Dynamically load 03-prowler-mcp-posture-server.py."""
    spec = util.spec_from_file_location("prowler_mcp_srv", SERVER_FILE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {SERVER_FILE}")
    mod = util.module_from_spec(spec)
    sys.modules["prowler_mcp_srv"] = mod
    spec.loader.exec_module(mod)
    return mod


def _pick_port(preferred: int = DEFAULT_PORT) -> int:
    """Bind preferred port 18806 if free, else an ephemeral port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])


def _wait_port(host: str, port: int, timeout: float = 5.0) -> None:
    """Wait until background Uvicorn socket accepts connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"MCP server failed to bind {host}:{port}")


class LiveMcpServerRunner:
    """Thread-hosted Uvicorn lifecycle for Streamable HTTP MCP server."""

    def __init__(self, preferred_port: int = DEFAULT_PORT) -> None:
        self.mod = _load_server_module()
        self.port = _pick_port(preferred_port)
        app = self.mod.build_stateless_http_app()
        cfg = uvicorn.Config(
            app, host="127.0.0.1", port=self.port, log_level="error"
        )
        self.server = uvicorn.Server(cfg)
        self.thread = threading.Thread(
            target=self.server.run, daemon=True
        )

    def __enter__(self) -> str:
        self.thread.start()
        _wait_port("127.0.0.1", self.port)
        return f"http://127.0.0.1:{self.port}/mcp"

    def __exit__(self, *args: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=3.0)


@pytest.fixture(scope="module")
def mcp_url():
    """Boot live 03-prowler-mcp-posture-server.py for module tests."""
    with LiveMcpServerRunner(DEFAULT_PORT) as url:
        yield url


def test_mcp_iac_scan_and_prowler_pr_mapping(mcp_url: str) -> None:
    """Verify MCP 2026-07-28 posture scan and .tf PR mapping."""

    async def _run() -> dict[str, Any]:
        async with Client(mcp_url) as client:
            assert client.protocol_version == "2026-07-28"
            listed = await client.list_tools()
            names = sorted(t.name for t in listed.tools)
            assert names == [
                "map_prowler_cis81_to_terraform",
                "scan_iac_posture",
            ]

            secure_res = await client.call_tool(
                "scan_iac_posture",
                {"tf_content": SECURE_TF.read_text(encoding="utf-8")},
            )
            assert secure_res.is_error is False
            secure_data = json.loads(secure_res.content[0].text)

            flawed_res = await client.call_tool(
                "scan_iac_posture",
                {"tf_content": FLAWED_TF.read_text(encoding="utf-8")},
            )
            assert flawed_res.is_error is False
            flawed_data = json.loads(flawed_res.content[0].text)

            pr_oidc = await client.call_tool(
                "map_prowler_cis81_to_terraform",
                {"finding_id": "prowler-aws-iam-oidc-wildcard"},
            )
            pr_kms = await client.call_tool(
                "map_prowler_cis81_to_terraform",
                {"finding_id": "prowler-aws-kms-rotation"},
            )
            pr_s3 = await client.call_tool(
                "map_prowler_cis81_to_terraform",
                {"finding_id": "prowler-aws-s3-public"},
            )
            return {
                "secure": secure_data,
                "flawed": flawed_data,
                "pr_oidc": json.loads(pr_oidc.content[0].text),
                "pr_kms": json.loads(pr_kms.content[0].text),
                "pr_s3": json.loads(pr_s3.content[0].text),
            }

    res = asyncio.run(_run())
    assert res["secure"]["passed"] is True
    assert res["secure"]["finding_count"] == 0
    assert res["secure"]["findings"] == []

    assert res["flawed"]["passed"] is False
    ids = {f["rule_id"] for f in res["flawed"]["findings"]}
    checkov_ids = {f["checkov_id"] for f in res["flawed"]["findings"]}
    assert "CKV_AWS_393" in checkov_ids
    assert "CKV_AWS_304" in checkov_ids
    assert "AVD-AWS-0092" in ids
    assert "AVD-AWS-0086" in ids
    assert "AVD-AWS-0057" in ids

    for pr_key in ("pr_oidc", "pr_kms", "pr_s3"):
        pr = res[pr_key]
        assert pr["mapped"] is True
        assert pr["patch_live_aws_clickops"] is False
        assert pr["hitl_pr_required"] is True
        assert pr["source_tf_path"].endswith(".tf")
        assert "@@" in pr["pr_patch_hunk"]


def main() -> int:
    """Run live MCP IaC posture checks as standalone script."""

    async def _run(url: str) -> dict[str, Any]:
        async with Client(url) as client:
            secure = await client.call_tool(
                "scan_iac_posture",
                {"tf_content": SECURE_TF.read_text(encoding="utf-8")},
            )
            flawed = await client.call_tool(
                "scan_iac_posture",
                {"tf_content": FLAWED_TF.read_text(encoding="utf-8")},
            )
            mapped = await client.call_tool(
                "map_prowler_cis81_to_terraform",
                {"finding_id": "prowler-aws-iam-oidc-wildcard"},
            )
            return {
                "protocol": client.protocol_version,
                "secure": json.loads(secure.content[0].text),
                "flawed": json.loads(flawed.content[0].text),
                "mapped_pr": json.loads(mapped.content[0].text),
            }

    with LiveMcpServerRunner(DEFAULT_PORT) as url:
        report = asyncio.run(_run(url))

    assert report["secure"]["finding_count"] == 0
    assert report["flawed"]["passed"] is False
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
