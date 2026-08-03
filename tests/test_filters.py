"""Unit tests for display-filter construction (no external deps).

These lock in the two security/regression properties:
  - relative windows emit ``frame.time_relative`` numeric comparisons
    (the original ``frame.time >= "14:00:00"`` could never match ISO timestamps),
  - injection tokens are rejected before reaching a filter.
"""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address

import pytest

from tshark_mcp.filters import (
    build_protocol_filter,
    build_stream_filter,
    build_time_filter,
    combine,
)
from tshark_mcp.models import (
    AbsoluteWindow,
    Endpoint,
    RelativeWindow,
    StreamParams,
)


# --- build_time_filter ------------------------------------------------------

def test_relative_window_uses_time_relative():
    flt = build_time_filter(RelativeWindow(start_seconds=0.0, end_seconds=1.5))
    assert flt is not None
    assert "frame.time_relative" in flt
    assert ">= 0.0" in flt and "<= 1.5" in flt


def test_absolute_window_uses_frame_time_quoted():
    flt = build_time_filter(
        AbsoluteWindow(start=datetime(2024, 1, 1, 12, 0, 0), end=datetime(2024, 1, 1, 12, 5, 0))
    )
    assert flt is not None
    assert 'frame.time >=' in flt and 'frame.time <=' in flt
    assert '"' in flt  # absolute times are quoted literals


def test_none_window_returns_none():
    assert build_time_filter(None) is None


# --- build_protocol_filter --------------------------------------------------

def test_protocol_rejects_injection():
    with pytest.raises(ValueError):
        build_protocol_filter("tcp and tcp.reset")
    with pytest.raises(ValueError):
        build_protocol_filter("rm -rf /")


def test_protocol_lowercased_and_validated():
    assert build_protocol_filter("HTTP") == "http"
    assert build_protocol_filter("mqtt") == "mqtt"


def test_protocol_none_returns_none():
    assert build_protocol_filter(None) is None


# --- combine ----------------------------------------------------------------

def test_combine_parenthesizes_multiple():
    assert combine("a", "b") == "(a) and (b)"
    assert combine("a", None, "b") == "(a) and (b)"


def test_combine_single_passthrough():
    assert combine("a") == "a"
    assert combine(None, "b", None) == "b"


def test_combine_all_none_returns_none():
    assert combine(None, None) is None


# --- build_stream_filter ----------------------------------------------------

def _stream() -> StreamParams:
    return StreamParams(
        pcap_file="x",
        protocol="tcp",
        endpoint_a=Endpoint(address=IPv4Address("10.0.0.1"), port=1234),
        endpoint_b=Endpoint(address=IPv4Address("10.0.0.2"), port=80),
    )


def test_stream_filter_is_bidirectional():
    flt = build_stream_filter(_stream())
    # both endpoints present, both directions matched via `or`
    assert "10.0.0.1" in flt and "10.0.0.2" in flt
    assert "1234" in flt and "80" in flt
    assert " or " in flt


def test_stream_filter_uses_validated_port_int():
    flt = build_stream_filter(_stream())
    # port is an int field — no quoting, plain numeric token
    assert "srcport == 1234" in flt
    assert "dstport == 80" in flt
