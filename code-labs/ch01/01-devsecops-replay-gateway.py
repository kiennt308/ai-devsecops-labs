#!/usr/bin/env python3
"""Deterministic Replay Mock Gateway for OrderFlow DevSecOps Labs.

Supports offline reproducible replay for remediation, posture, and
SecOps triage agents at $0.00 cost, or delegates via LLM_BASE_URL
to a local Ollama or OpenAI-compatible server.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
import urllib.request
from typing import Any


def build_replay_response(prompt: str) -> dict[str, Any]:
    """Return deterministic security action matched to task prompt."""
    low = prompt.lower()
    if "cve" in low or "openvex" in low or "remediate" in low:
        action = "SYNTHESIZE_MINIMAL_SANDBOX_PATCH"
        evidence = "pin dependency + run unit/sast suite before PR"
    elif "prowler" in low or "terraform" in low or "oidc" in low:
        action = "OPEN_IAC_POSTURE_REMEDIATION_PR"
        evidence = "scope CKV_AWS_393 OIDC subject and KMS rotation"
    elif "tetragon" in low or "falco" in low or "ocsf" in low:
        action = "DRAFT_HITL_QUARANTINE_NETWORKPOLICY_PR"
        evidence = "correlate OCSF 1007 + 2002 + 2004 runtime trace"
    else:
        action = "ROUTE_CLOSED_LOOP_TRIAGE"
        evidence = "evaluate policy gates before code promotion"

    return {
        "id": "chatcmpl-orderflow-devsecops-replay-09",
        "model": os.environ.get("LLM_MODEL", "orderflow-devsecops-v1"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(
                        {"action": action, "evidence": evidence}
                    ),
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 640, "completion_tokens": 48},
    }


def forward_or_replay(payload: dict[str, Any]) -> dict[str, Any]:
    """Forward payload when LLM_BASE_URL is configured; else replay."""
    base = os.environ.get("LLM_BASE_URL", "").strip()
    if base:
        url = base.rstrip("/") + "/chat/completions"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    msgs = payload.get("messages", [])
    last_text = msgs[-1].get("content", "") if msgs else ""
    return build_replay_response(last_text)


class GatewayHandler(BaseHTTPRequestHandler):
    """Minimal HTTP JSON handler for offline DevSecOps agent CI."""

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, code: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"status": "REPLAY_GATEWAY_READY", "vol": 9})
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self._send(404, {"error": "not_found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        self._send(200, forward_or_replay(body))


def run_self_test() -> None:
    """Start ephemeral localhost gateway, query endpoints, and exit."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), GatewayHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/health", timeout=3
        ) as resp:
            health = json.loads(resp.read().decode("utf-8"))
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps(
                {
                    "messages": [
                        {
                            "role": "user",
                            "content": "Triage CVE OpenVEX in OrderFlow",
                        }
                    ]
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            reply = json.loads(resp.read().decode("utf-8"))
        verdict = json.loads(reply["choices"][0]["message"]["content"])
        print(
            json.dumps(
                {
                    "status": health["status"],
                    "action": verdict["action"],
                    "tokens": reply["usage"],
                },
                indent=2,
            )
        )
    finally:
        srv.shutdown()
        srv.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="DevSecOps Replay GW")
    parser.add_argument("--serve", action="store_true", help="Serve API")
    parser.add_argument("--port", type=int, default=18089)
    args = parser.parse_args()
    if args.serve:
        addr = ("127.0.0.1", args.port)
        srv = ThreadingHTTPServer(addr, GatewayHandler)
        print(f"Listening on http://127.0.0.1:{args.port}")
        srv.serve_forever()
    else:
        run_self_test()


if __name__ == "__main__":
    main()
