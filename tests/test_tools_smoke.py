"""End-to-end smoke tests: every tool on real pcap files.

Requires tshark. Guards the full executor -> parser -> tool chain against
regressions, including the three bugs fixed in the rewrite (conv parsing,
time filtering, bidirectional stream matching) and input injection rejection.
"""

from __future__ import annotations

import time
from ipaddress import IPv4Address

import pytest

from tshark_mcp.config import resolve_tshark_paths
from tshark_mcp.executor import TSharkExecutor
from tshark_mcp.models import (
    Endpoint,
    ExtractPacketsParams,
    RelativeWindow,
    StatParams,
    StreamParams,
)
from tshark_mcp.tools.conversations import get_conversations
from tshark_mcp.tools.extract import extract_packets, extract_stream
from tshark_mcp.tools.overview import get_overview
from tshark_mcp.tools.statistics import get_statistics

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def executor():
    tshark, capinfos = resolve_tshark_paths()
    return TSharkExecutor(tshark, capinfos)


async def test_overview_small(executor, small_pcap):
    ov = await get_overview(executor, str(small_pcap))
    assert ov.total_packets == 50
    assert ov.encapsulation == "Ethernet"
    assert ov.capture_duration_seconds == pytest.approx(2.385)
    assert "ftp" in {p.protocol for p in ov.protocol_hierarchy}


async def test_conversations_small(executor, small_pcap):
    res = await get_conversations(executor, str(small_pcap), "both", limit=100)
    assert res.total >= 2
    assert all(c.protocol in ("tcp", "udp") for c in res.conversations)


async def test_extract_packets_protocol_and_limit(executor, small_pcap):
    res = await extract_packets(
        executor, ExtractPacketsParams(pcap_file=str(small_pcap), protocol="ftp", limit=10)
    )
    assert 0 < res.total_returned <= 10


async def test_extract_packets_rejects_injection(executor, small_pcap):
    """Allowlist must reject a crafted protocol token before it reaches a filter."""
    with pytest.raises(ValueError):
        await extract_packets(
            executor,
            ExtractPacketsParams(
                pcap_file=str(small_pcap), protocol="tcp and tcp.reset"
            ),
        )


async def test_extract_packets_time_window(executor, small_pcap):
    """Regression: relative window must use frame.time_relative (numeric)."""
    res = await extract_packets(
        executor,
        ExtractPacketsParams(
            pcap_file=str(small_pcap),
            time_window=RelativeWindow(start_seconds=0.0, end_seconds=1.0),
            limit=100,
        ),
    )
    assert res.total_returned > 0


async def test_extract_stream_bidirectional(executor, small_pcap):
    """Regression: both directions of the 5-tuple must be matched."""
    res = await extract_stream(
        executor,
        StreamParams(
            pcap_file=str(small_pcap),
            protocol="tcp",
            endpoint_a=Endpoint(address=IPv4Address("10.62.18.9"), port=34933),
            endpoint_b=Endpoint(address=IPv4Address("120.86.64.161"), port=10020),
            limit=100,
        ),
    )
    assert res.total_returned > 0


async def test_statistics_all(executor, small_pcap):
    stats = await get_statistics(
        executor, StatParams(pcap_file=str(small_pcap), metric="all")
    )
    # get_statistics now returns a typed StatisticsResult (not a dict)
    assert stats.throughput is not None
    assert stats.throughput.total_frames == 50
    assert stats.tcp is not None and stats.tcp.total_connections >= 2


@pytest.mark.slow
async def test_overview_big_pcapng_stays_fast(executor, pcap_paths):
    """Guard against the original full-packet-load regression on a bigger file."""
    big = pcap_paths["ftpsfota"]
    if not big.exists():
        pytest.skip("big pcapng missing")
    start = time.monotonic()
    ov = await get_overview(executor, str(big))
    elapsed = time.monotonic() - start
    assert ov.total_packets > 0
    # capinfos + io,phs must stay well under this on any reasonable file
    assert elapsed < 15.0, f"overview too slow ({elapsed:.1f}s) — full-packet load regression?"
