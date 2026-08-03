"""Unit tests for tool pure logic with a mock executor (no tshark needed).

Covers branches the integration suite can't cheaply reach: short-row handling
in _row_to_packet, metric dispatch, per-metric error tolerance, limit
truncation, and the is_float helper.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

from tshark_mcp.models import ExtractPacketsParams, StatParams
from tshark_mcp.tools.conversations import get_conversations
from tshark_mcp.tools.extract import _row_to_packet, extract_packets
from tshark_mcp.tools.statistics import _selected_metrics, get_statistics
from tshark_mcp.utils import is_float


# --- is_float ---------------------------------------------------------------

def test_is_float_truthy():
    assert is_float("1.5")
    assert is_float("0")
    assert is_float("-3.2")
    assert is_float(" 1.0 ")  # tolerates whitespace


def test_is_float_falsy():
    assert not is_float("abc")
    assert not is_float("")
    assert not is_float(None)  # type: ignore[arg-type]


# --- _row_to_packet ---------------------------------------------------------

def test_row_to_packet_full_row():
    p = _row_to_packet(["5", "1.234", "10.0.0.1", "10.0.0.2", "TCP", "60", "SYN"])
    assert p.frame_number == 5
    assert p.time_relative == 1.234
    assert p.source == "10.0.0.1" and p.destination == "10.0.0.2"
    assert p.protocol == "TCP"
    assert p.length == 60
    assert p.info == "SYN"


def test_row_to_packet_short_row_defaults_safely():
    # Only frame.number present; the rest must default, not raise.
    p = _row_to_packet(["7"])
    assert p.frame_number == 7
    assert p.time_relative == 0.0
    assert p.source == ""
    assert p.length == 0


def test_row_to_packet_non_numeric_fields_become_zero():
    p = _row_to_packet(["abc", "xyz", "", "", "", "NaN", ""])
    assert p.frame_number == 0
    assert p.time_relative == 0.0
    assert p.length == 0


# --- _selected_metrics ------------------------------------------------------

def test_selected_metrics_all():
    assert _selected_metrics("all") == {
        "throughput", "retransmission", "packet_loss", "tcp", "latency"
    }


def test_selected_metrics_latency_expands_to_tcp():
    # latency shares the conv,tcp query with tcp
    assert _selected_metrics("latency") == {"latency", "tcp"}


def test_selected_metrics_single():
    assert _selected_metrics("throughput") == {"throughput"}
    assert _selected_metrics("tcp") == {"tcp"}


# --- get_statistics error tolerance ----------------------------------------

async def test_get_statistics_records_metric_error():
    """A failing metric is captured in .errors, not raised."""
    ex = AsyncMock()
    ex.tshark.return_value = ""  # empty io,phs / conv
    ex.capinfos.side_effect = RuntimeError("capinfos boom")  # throughput needs it
    ex.packets_fields.return_value = []
    res = await get_statistics(ex, StatParams(pcap_file="x", metric="throughput"))
    assert res.throughput is None
    assert "throughput" in res.errors
    assert "capinfos boom" in res.errors["throughput"]


# --- get_conversations limit truncation ------------------------------------

async def test_get_conversations_truncates_to_limit():
    conv_text = (
        "1.1.1.1:1 <-> 2.2.2.2:2    1 10 bytes   1 10 bytes   2 20 bytes   0.0 1.0\n"
        "1.1.1.1:3 <-> 2.2.2.2:4    1 10 bytes   1 10 bytes   2 20 bytes   0.0 1.0\n"
        "1.1.1.1:5 <-> 2.2.2.2:6    1 10 bytes   1 10 bytes   2 20 bytes   0.0 1.0\n"
    )
    ex = AsyncMock()
    ex.tshark.return_value = conv_text
    res = await get_conversations(ex, "x", "tcp", limit=2)
    assert res.total == 3
    assert len(res.conversations) == 2


# --- extract_packets with mock ---------------------------------------------

async def test_extract_packets_summary_truncation():
    ex = AsyncMock()
    ex.packets_fields.return_value = [
        ["1", "0.0", "a", "b", "TCP", "60", "info1"],
        ["2", "1.0", "a", "b", "TCP", "60", "info2"],
    ]
    res = await extract_packets(ex, ExtractPacketsParams(pcap_file="x", limit=1))
    assert res.total_returned == 1
    assert res.truncated is True
    assert res.packets[0].frame_number == 1
