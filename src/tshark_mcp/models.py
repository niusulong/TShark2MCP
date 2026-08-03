"""Pydantic request/response models for all MCP tools.

These models are the single source of truth for each tool's ``inputSchema``
(FastMCP derives JSON Schema from type hints + ``Field`` constraints) and for
structured output. Field constraints (``ge``/``le``/``Literal``) cause invalid
arguments to be rejected *before* the tool body runs, and the rejection is
automatically surfaced to the model as an error.
"""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Literal, Union

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Time windows (shared by extract_* and get_statistics)
# ---------------------------------------------------------------------------


class RelativeWindow(BaseModel):
    """Capture-relative time range, measured in seconds from the first packet.

    Preferred over absolute time: robust across timezones and matches how
    analysts describe anomalies ("30s before the disconnect").
    """

    start_seconds: float = Field(ge=0.0, description="Start offset in seconds from capture start")
    end_seconds: float = Field(ge=0.0, description="End offset in seconds from capture start")


class AbsoluteWindow(BaseModel):
    """Absolute wall-clock time range."""

    start: datetime = Field(description="Inclusive start time (ISO 8601)")
    end: datetime = Field(description="Inclusive end time (ISO 8601)")


# FastMCP emits this as a oneOf; the two members are distinguished by field set.
TimeWindow = Union[RelativeWindow, AbsoluteWindow]


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------


class ProtocolStat(BaseModel):
    protocol: str = Field(description="Protocol/dissector layer name, e.g. tcp, http, tls")
    frames: int = Field(ge=0)
    bytes: int = Field(ge=0)


class OverviewResult(BaseModel):
    file_path: str
    file_size_bytes: int = Field(ge=0)
    total_packets: int = Field(ge=0)
    capture_duration_seconds: float = Field(ge=0.0)
    time_range: dict[str, str] = Field(description="{'start': ISO8601, 'end': ISO8601}")
    encapsulation: str
    protocol_hierarchy: list[ProtocolStat]


# ---------------------------------------------------------------------------
# Conversations
# ---------------------------------------------------------------------------


class Conversation(BaseModel):
    protocol: Literal["tcp", "udp"]
    src_address: str
    src_port: int
    dst_address: str
    dst_port: int
    packets_forward: int = Field(ge=0)
    packets_reverse: int = Field(ge=0)
    bytes_forward: int = Field(ge=0)
    bytes_reverse: int = Field(ge=0)
    relative_start: float | None = Field(default=None, description="Seconds from capture start")
    duration: float | None = Field(default=None, description="Seconds")


class ConversationsResult(BaseModel):
    conversations: list[Conversation]
    total: int = Field(ge=0)


# ---------------------------------------------------------------------------
# Extract packets (protocol + time + limit)
# ---------------------------------------------------------------------------


class ExtractPacketsParams(BaseModel):
    pcap_file: str = Field(description="Path to the pcap/pcapng file")
    protocol: str | None = Field(
        default=None,
        description="Protocol display-filter token, e.g. tcp/http/dns/tls/ftp/mqtt. Validated against an allowlist.",
    )
    time_window: TimeWindow | None = Field(default=None, description="Optional time range filter")
    limit: int = Field(default=500, ge=1, le=2000, description="Max packets to return")
    output_format: Literal["summary", "full"] = Field(
        default="summary",
        description="'summary' returns key fields per packet; 'full' returns the complete per-packet JSON",
    )


class ExtractedPacket(BaseModel):
    frame_number: int
    time_relative: float
    source: str
    destination: str
    protocol: str
    length: int
    info: str


class ExtractResult(BaseModel):
    """Per-packet extraction result.

    ``packets`` is ``ExtractedPacket`` in summary mode, raw ``dict`` in full
    mode — declared as a union so the summary schema is exposed to clients
    (rather than an opaque ``list``).
    """

    packets: list[ExtractedPacket | dict[str, Any]]
    total_returned: int = Field(ge=0)
    truncated: bool = Field(description="True if more matching packets exist beyond the limit")
    filter_applied: str = Field(description="The display filter that was applied")


# ---------------------------------------------------------------------------
# Extract stream (5-tuple deep-dive)
# ---------------------------------------------------------------------------


class Endpoint(BaseModel):
    address: IPv4Address | IPv6Address = Field(description="IPv4 or IPv6 address")
    port: int = Field(ge=0, le=65535)


class StreamParams(BaseModel):
    pcap_file: str
    protocol: Literal["tcp", "udp"]
    endpoint_a: Endpoint = Field(description="One endpoint; order vs endpoint_b is irrelevant")
    endpoint_b: Endpoint
    time_window: TimeWindow | None = None
    limit: int = Field(default=500, ge=1, le=2000)
    output_format: Literal["summary", "full"] = "summary"


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


class StatParams(BaseModel):
    pcap_file: str
    metric: Literal[
        "all", "latency", "throughput", "retransmission", "tcp", "packet_loss"
    ] = "all"
    time_window: TimeWindow | None = None


class ThroughputStat(BaseModel):
    total_frames: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    capture_duration_seconds: float = Field(ge=0.0)
    average_frames_per_second: float
    average_bps: float


class Retransmission(BaseModel):
    frame: str
    src: str
    src_port: str
    dst: str
    dst_port: str


class RetransmissionStat(BaseModel):
    retransmission_count: int = Field(ge=0)
    total_tcp_packets: int = Field(ge=0)
    retransmission_rate_percent: float
    retransmissions: list[Retransmission]


class PacketLossEvent(BaseModel):
    frame: str
    info: str


class PacketLossStat(BaseModel):
    total_events: int = Field(ge=0)
    duplicate_acks: int = Field(ge=0)
    fast_retransmissions: int = Field(ge=0)
    out_of_order: int = Field(ge=0)
    events: list[PacketLossEvent]


class TcpConnection(BaseModel):
    src: str
    src_port: int
    dst: str
    dst_port: int
    packets: int


class TcpConnectionsStat(BaseModel):
    total_connections: int = Field(ge=0)
    total_packets: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    average_packets_per_connection: float
    connections: list[TcpConnection]


class LatencyStat(BaseModel):
    count: int = Field(ge=0)
    average_ms: float | None = None
    min_ms: float | None = None
    max_ms: float | None = None


class StatisticsResult(BaseModel):
    """Aggregated traffic statistics. Only requested metrics are populated."""

    throughput: ThroughputStat | None = None
    retransmission: RetransmissionStat | None = None
    packet_loss: PacketLossStat | None = None
    tcp: TcpConnectionsStat | None = None
    latency: LatencyStat | None = None
    errors: dict[str, str] = Field(
        default_factory=dict, description="Per-metric error messages (keyed by metric name)"
    )
    time_window: dict[str, Any] | None = None
