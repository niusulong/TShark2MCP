"""Unit tests for the protocol allowlist (no external deps)."""

from __future__ import annotations

import pytest

from tshark_mcp.security import PROTOCOL_ALLOWLIST, is_allowed_protocol


def test_known_protocols_allowed():
    for proto in ("tcp", "udp", "http", "dns", "tls", "ftp", "mqtt"):
        assert is_allowed_protocol(proto), proto


def test_case_insensitive():
    assert is_allowed_protocol("TCP")
    assert is_allowed_protocol("Http")
    assert is_allowed_protocol("MQTT")


def test_injection_payloads_rejected():
    # These must never pass — they would alter display-filter semantics.
    assert not is_allowed_protocol("tcp and tcp.reset")
    assert not is_allowed_protocol("tcp; rm -rf /")
    assert not is_allowed_protocol("tcp) or (ip")
    assert not is_allowed_protocol("")
    assert not is_allowed_protocol("tcp\x00")


def test_allowlist_is_immutable():
    # frozenset — guards against accidental mutation at runtime.
    with pytest.raises(AttributeError):
        PROTOCOL_ALLOWLIST.add("evil")  # type: ignore[attr-defined]
