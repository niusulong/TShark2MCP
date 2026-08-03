"""get_statistics tool logic.

Migrated from the original six ``_calculate_*`` helpers. Every tshark call now
goes through the async :class:`TSharkExecutor`, and the selected metrics run
concurrently via ``asyncio.gather``. Results are typed pydantic models
(:class:`StatisticsResult`) so the output schema is exposed to clients.

When a ``time_window`` is given, a time-filtered temp pcap is produced first
(via :meth:`TSharkExecutor.export_filtered`) because ``-z conv`` / ``-z io,phs``
don't accept a ``-Y`` display filter of their own.
"""

from __future__ import annotations

import asyncio
import os

from ..executor import TSharkExecutor
from ..filters import build_time_filter
from ..models import (
    LatencyStat,
    PacketLossEvent,
    PacketLossStat,
    Retransmission,
    RetransmissionStat,
    StatParams,
    StatisticsResult,
    TcpConnection,
    TcpConnectionsStat,
    ThroughputStat,
)
from ..parsers import parse_capinfos, parse_conversations, parse_io_phs
from ..utils import is_float


async def _throughput(executor: TSharkExecutor, pcap: str) -> ThroughputStat:
    io_text, capinfos_text = await asyncio.gather(
        executor.tshark(pcap, ["-q", "-z", "io,phs"]),
        executor.capinfos(pcap),
    )
    layers = parse_io_phs(io_text)
    frame = next((s for s in layers if s.protocol == "frame"), None)
    total_frames = frame.frames if frame else 0
    total_bytes = frame.bytes if frame else 0
    # duration from capinfos (consistent with get_pcap_overview, no full scan)
    duration = parse_capinfos(capinfos_text)["capture_duration"]
    return ThroughputStat(
        total_frames=total_frames,
        total_bytes=total_bytes,
        capture_duration_seconds=duration,
        average_frames_per_second=round(total_frames / duration, 2) if duration else 0,
        average_bps=round(total_bytes * 8 / duration, 0) if duration else 0,
    )


async def _retransmission(executor: TSharkExecutor, pcap: str) -> RetransmissionStat:
    retrans_rows = await executor.packets_fields(
        pcap,
        fields=["frame.number", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport"],
        display_filter="tcp.analysis.retransmission",
    )
    total_rows = await executor.packets_fields(
        pcap, fields=["frame.number"], display_filter="tcp"
    )
    total_tcp = len(total_rows)
    retrans = [
        Retransmission(frame=r[0], src=r[1], src_port=r[2], dst=r[3], dst_port=r[4])
        for r in retrans_rows[:10]
        if len(r) >= 5
    ]
    rate = (len(retrans_rows) / total_tcp * 100) if total_tcp else 0.0
    return RetransmissionStat(
        retransmission_count=len(retrans_rows),
        total_tcp_packets=total_tcp,
        retransmission_rate_percent=round(rate, 2),
        retransmissions=retrans,
    )


async def _packet_loss(executor: TSharkExecutor, pcap: str) -> PacketLossStat:
    rows = await executor.packets_fields(
        pcap,
        fields=["frame.number", "_ws.col.Info"],
        display_filter=(
            "tcp.analysis.duplicate_ack || tcp.analysis.fast_retransmission "
            "|| tcp.analysis.out_of_order"
        ),
    )
    events = [
        PacketLossEvent(frame=r[0], info=r[1] if len(r) > 1 else "") for r in rows[:10]
    ]

    def _count(needle: str) -> int:
        return sum(1 for r in rows if len(r) > 1 and needle in r[1])

    return PacketLossStat(
        total_events=len(rows),
        duplicate_acks=_count("Duplicate ACK"),
        fast_retransmissions=_count("Fast retransmission"),
        out_of_order=_count("Out-of-Order"),
        events=events,
    )


async def _tcp_connections(executor: TSharkExecutor, pcap: str) -> TcpConnectionsStat:
    text = await executor.tshark(pcap, ["-q", "-z", "conv,tcp"])
    convs = parse_conversations(text, "tcp")
    total_packets = sum(c.packets_forward + c.packets_reverse for c in convs)
    total_bytes = sum(c.bytes_forward + c.bytes_reverse for c in convs)
    return TcpConnectionsStat(
        total_connections=len(convs),
        total_packets=total_packets,
        total_bytes=total_bytes,
        average_packets_per_connection=round(total_packets / len(convs), 2) if convs else 0,
        connections=[
            TcpConnection(
                src=c.src_address,
                src_port=c.src_port,
                dst=c.dst_address,
                dst_port=c.dst_port,
                packets=c.packets_forward + c.packets_reverse,
            )
            for c in convs[:20]
        ],
    )


async def _http_latency(executor: TSharkExecutor, pcap: str) -> LatencyStat:
    rows = await executor.packets_fields(
        pcap,
        fields=["http.time"],
        display_filter="http.request && http.response_in",
    )
    times = [float(r[0]) for r in rows if r and is_float(r[0])]
    if not times:
        return LatencyStat(count=0)
    return LatencyStat(
        count=len(times),
        # http.time is in seconds; report milliseconds
        average_ms=round(sum(times) / len(times) * 1000, 2),
        min_ms=round(min(times) * 1000, 2),
        max_ms=round(max(times) * 1000, 2),
    )


# metric name -> coroutine factory
_METRIC_FUNCS = {
    "throughput": _throughput,
    "retransmission": _retransmission,
    "packet_loss": _packet_loss,
    "tcp": _tcp_connections,
    "latency": _http_latency,
}


def _selected_metrics(metric: str) -> set[str]:
    """Resolve which metric functions to run for a given metric arg.

    ``latency`` also pulls in ``tcp`` (they share the conv,tcp query).
    """
    if metric == "all":
        return set(_METRIC_FUNCS)
    if metric == "latency":
        return {"latency", "tcp"}
    return {metric}


async def get_statistics(executor: TSharkExecutor, params: StatParams) -> StatisticsResult:
    """Compute the requested metrics concurrently.

    Each sub-metric that errors is recorded in ``errors`` rather than aborting
    the whole call, so a partial result is still useful.
    """
    time_f = build_time_filter(params.time_window)
    tmp_path: str | None = None
    try:
        target = params.pcap_file
        if time_f:
            tmp_path = await executor.export_filtered(params.pcap_file, time_f)
            target = tmp_path

        selected = _selected_metrics(params.metric)
        coros = {
            name: fn(executor, target)
            for name, fn in _METRIC_FUNCS.items()
            if name in selected
        }
        keys = list(coros.keys())
        results = await asyncio.gather(*coros.values(), return_exceptions=True)

        fields: dict[str, object] = {}
        errors: dict[str, str] = {}
        for key, val in zip(keys, results):
            if isinstance(val, Exception):
                errors[key] = str(val)
            else:
                fields[key] = val
        if errors:
            fields["errors"] = errors
        if params.time_window is not None:
            fields["time_window"] = params.time_window.model_dump(mode="json")
        return StatisticsResult(**fields)  # type: ignore[arg-type]
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
