"""Unit tests for tshark/capinfos text parsers.

The conv test is the regression guard for the original ``split('|')`` bug:
tshark 4.x conv data rows have no pipe separators, so the old parser returned
``[]`` for every real capture.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tshark_mcp.parsers import parse_capinfos, parse_conversations, parse_io_phs, parse_packet_json

FIXTURES = Path(__file__).parent / "fixtures"


# --- parse_capinfos ---------------------------------------------------------

def test_parse_capinfos_basic_fields():
    text = (FIXTURES / "capinfos_123.txt").read_text(encoding="utf-8")
    d = parse_capinfos(text)
    assert d["total_packets"] == 50
    assert d["capture_duration"] == pytest.approx(2.385)
    assert d["earliest_time"].startswith("2000-01-02")
    assert d["latest_time"].startswith("2000-01-02")
    assert d["encapsulation"] == "Ethernet"


# --- parse_io_phs -----------------------------------------------------------

def test_parse_io_phs_extracts_all_layers():
    text = (FIXTURES / "io_phs_123.txt").read_text(encoding="utf-8")
    stats = parse_io_phs(text)
    protos = {s.protocol for s in stats}
    assert {"frame", "eth", "ip", "tcp", "ftp", "tls"} <= protos

    ftp = next(s for s in stats if s.protocol == "ftp")
    assert ftp.frames == 28
    assert ftp.bytes == 4553

    tls = next(s for s in stats if s.protocol == "tls")
    assert tls.frames == 5


# --- parse_conversations (regression for split('|') bug) --------------------

def test_parse_conversations_regression_no_pipe():
    """Original parser split on '|' and returned [] — these rows have none."""
    text = (FIXTURES / "conv_tcp_123.txt").read_text(encoding="utf-8")
    convs = parse_conversations(text, "tcp")
    assert len(convs) == 2

    first = convs[0]
    assert first.protocol == "tcp"
    assert first.src_address == "10.62.18.9"
    assert first.src_port == 34933
    assert first.dst_address == "120.86.64.161"
    assert first.dst_port == 10020
    # '->' (forward = src->dst) is the SECOND numeric pair in the row
    assert first.packets_forward == 22
    assert first.bytes_forward == 2097
    # '<-' (reverse = dst->src) is the FIRST numeric pair
    assert first.packets_reverse == 17
    assert first.bytes_reverse == 3058
    assert first.relative_start == pytest.approx(0.0)
    assert first.duration == pytest.approx(2.385)

    second = convs[1]
    assert second.src_port == 34934
    assert second.dst_port == 10510


def test_parse_conversations_empty_udp():
    text = "================================================================================\nUDP Conversations\nFilter:<No Filter>\n================================================================================\n"
    assert parse_conversations(text, "udp") == []


# --- parse_packet_json ------------------------------------------------------

def test_parse_packet_json_array():
    assert parse_packet_json('[{"a": 1}, {"a": 2}]') == [{"a": 1}, {"a": 2}]


def test_parse_packet_json_empty():
    assert parse_packet_json("") == []
    assert parse_packet_json("   \n  ") == []


def test_parse_packet_json_single_object_wrapped():
    assert parse_packet_json('{"a": 1}') == [{"a": 1}]


def test_parse_packet_json_ndjson_fallback():
    # Not a single JSON array -> parsed line by line.
    assert parse_packet_json('{"a": 1}\n{"a": 2}') == [{"a": 1}, {"a": 2}]


def test_parse_packet_json_skips_garbage_lines():
    assert parse_packet_json('{"a": 1}\nnot json\n{"a": 2}') == [{"a": 1}, {"a": 2}]
