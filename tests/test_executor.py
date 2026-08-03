"""Integration tests for TSharkExecutor — require real tshark + pcap files.

Included by default ``pytest``. Skip in tshark-less CI with
``pytest -m "not integration"``.
"""

from __future__ import annotations

import pytest

from tshark_mcp.config import resolve_tshark_paths
from tshark_mcp.executor import TSharkExecutor
from tshark_mcp.parsers import parse_capinfos, parse_conversations, parse_io_phs

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def executor():
    tshark, capinfos = resolve_tshark_paths()
    return TSharkExecutor(tshark, capinfos)


async def test_capinfos(executor, small_pcap):
    d = parse_capinfos(await executor.capinfos(str(small_pcap)))
    assert d["total_packets"] == 50
    assert d["encapsulation"] == "Ethernet"


async def test_tshark_io_phs(executor, small_pcap):
    stats = parse_io_phs(await executor.tshark(str(small_pcap), ["-q", "-z", "io,phs"]))
    protos = {s.protocol for s in stats}
    assert "ftp" in protos and "tls" in protos


async def test_tshark_conv_tcp(executor, small_pcap):
    convs = parse_conversations(
        await executor.tshark(str(small_pcap), ["-q", "-z", "conv,tcp"]), "tcp"
    )
    assert len(convs) >= 2
    first = convs[0]
    assert first.packets_forward + first.packets_reverse > 0


async def test_packets_json(executor, small_pcap):
    pkts = await executor.packets_json(str(small_pcap), display_filter="ftp")
    assert len(pkts) > 0
    assert "_source" in pkts[0]


async def test_packets_fields(executor, small_pcap):
    rows = await executor.packets_fields(
        str(small_pcap),
        fields=["frame.number", "ip.src"],
        display_filter="ftp",
    )
    assert len(rows) > 0
    assert rows[0][0].strip().isdigit()
