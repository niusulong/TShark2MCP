"""tshark_mcp.tools — tool registration onto an MCPServer.

Each tool module exposes a pure ``async`` function ``(executor, ...) -> result``.
:func:`register_all` wraps them as ``@mcp.tool()`` closures that inject a shared
:class:`TSharkExecutor`, so tool logic stays unit-testable with a mock executor
(no MCP server needed).
"""

from __future__ import annotations

from typing import Annotated, Literal

from mcp.server import MCPServer
from pydantic import Field

from ..executor import TSharkExecutor
from . import conversations, extract, overview, statistics


def register_all(
    mcp: MCPServer, *, tshark_path: str, capinfos_path: str | None
) -> None:
    """Register all pcap-analysis tools onto ``mcp``."""
    executor = TSharkExecutor(tshark_path, capinfos_path)

    @mcp.tool()
    async def get_pcap_overview(pcap_file: str) -> overview.OverviewResult:
        """Get file-level metadata and protocol distribution of a pcap/pcapng.

        Use this FIRST to understand a capture: packet count, duration, time
        range, encapsulation, and per-protocol frame/byte breakdown. Cheap to
        run (capinfos + io,phs; loads no individual packet).
        """
        return await overview.get_overview(executor, pcap_file)

    @mcp.tool()
    async def list_conversations(
        pcap_file: str,
        protocol: Literal["tcp", "udp", "both"] = "both",
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
    ) -> conversations.ConversationsResult:
        """List network conversations (TCP streams / UDP sessions).

        Returns endpoint pairs with per-direction packet/byte counts. Use after
        overview to see who talked to whom; pick a conversation's 5-tuple for
        extract_stream.
        """
        return await conversations.get_conversations(
            executor, pcap_file, protocol, limit
        )

    @mcp.tool()
    async def extract_packets(
        params: extract.ExtractPacketsParams,
    ) -> extract.ExtractResult:
        """Extract packets matching a protocol and/or time window (composable).

        Use to narrow scope, e.g. 'only MQTT in the first 30s'. truncated=True
        means more matches exist beyond limit — narrow filters or raise limit.
        """
        return await extract.extract_packets(executor, params)

    @mcp.tool()
    async def extract_stream(params: extract.StreamParams) -> extract.ExtractResult:
        """Extract all packets of one TCP stream / UDP session (5-tuple).

        Pass endpoints in either order; both directions are matched. Typically
        called after list_conversations to deep-dive one conversation.
        """
        return await extract.extract_stream(executor, params)

    @mcp.tool()
    async def get_statistics(
        params: statistics.StatParams,
    ) -> statistics.StatisticsResult:
        """Compute traffic statistics: retransmission rate, throughput, per-connection counts, duplicate ACKs, out-of-order, HTTP latency.

        metric selects a subset ('all', 'latency', 'throughput',
        'retransmission', 'tcp', 'packet_loss'). time_window restricts scope
        before computing.
        """
        return await statistics.get_statistics(executor, params)
