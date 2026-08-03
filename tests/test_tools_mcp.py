"""MCP protocol-level end-to-end tests.

Spawns the actual server (``python -m tshark_mcp``) and drives it over stdio
JSON-RPC — the full client -> MCPServer -> tool -> tshark -> pcap -> response
chain. Complements test_tools_smoke (which exercises tool logic directly,
without the MCP wire protocol).

These need tshark AND the package importable by the spawned interpreter, so
they run under the project venv (``sys.executable``).
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration


class _MCPSession:
    """A minimal stdio JSON-RPC client driving one server process."""

    def __init__(self, python: str) -> None:
        self.p = subprocess.Popen(
            [python, "-m", "tshark_mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self._next_id = 1

    def _send(self, req: dict, read: bool = True) -> dict | None:
        assert self.p.stdin is not None and self.p.stdout is not None
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        if not read:
            return None
        return json.loads(self.p.stdout.readline())

    def call(self, method: str, params: dict | None = None) -> dict:
        req = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        self._next_id += 1
        if params is not None:
            req["params"] = params
        return self._send(req)  # type: ignore[return-value]

    def notify(self, method: str, params: dict | None = None) -> None:
        req = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            req["params"] = params
        self._send(req, read=False)

    def close(self) -> None:
        try:
            if self.p.stdin:
                self.p.stdin.close()
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


def _result_payload(result: dict) -> dict:
    """Extract the tool's return value from a tools/call result."""
    if "structuredContent" in result:
        return result["structuredContent"]
    return json.loads(result["content"][0]["text"])


@pytest.fixture(scope="module")
def session():
    s = _MCPSession(sys.executable)
    s.call(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1"},
        },
    )
    s.notify("notifications/initialized")
    yield s
    s.close()


def test_get_pcap_overview_via_mcp(session, small_pcap):
    resp = session.call(
        "tools/call",
        {"name": "get_pcap_overview", "arguments": {"pcap_file": str(small_pcap)}},
    )
    assert resp["id"] is not None
    result = resp["result"]
    assert result["isError"] is False
    ov = _result_payload(result)
    assert ov["total_packets"] == 50
    assert ov["encapsulation"] == "Ethernet"
    assert {"ftp", "tls"} <= {p["protocol"] for p in ov["protocol_hierarchy"]}


def test_list_conversations_via_mcp(session, small_pcap):
    resp = session.call(
        "tools/call",
        {"name": "list_conversations", "arguments": {"pcap_file": str(small_pcap)}},
    )
    conv = _result_payload(resp["result"])
    assert conv["total"] >= 2
    first = conv["conversations"][0]
    assert first["src_address"] == "10.62.18.9"


def test_invalid_protocol_rejected_via_mcp(session, small_pcap):
    """A crafted protocol token must be rejected and surface as is_error."""
    resp = session.call(
        "tools/call",
        {
            "name": "extract_packets",
            "arguments": {
                "params": {
                    "pcap_file": str(small_pcap),
                    "protocol": "tcp and tcp.reset",
                }
            },
        },
    )
    assert resp["result"]["isError"] is True
