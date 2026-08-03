"""extract_packets + extract_stream tool logic.

Both share :func:`_extract` (build filter -> fetch -> cap at limit); they differ
only in filter construction:

  - ``extract_packets`` composes a protocol token (allowlisted) with an optional
    time window — two orthogonal filters that compose cleanly.
  - ``extract_stream`` builds a bidirectional 5-tuple filter (both directions),
    optionally narrowed by a time window.

``-c`` is intentionally NOT used to limit output: it caps packets READ
(before the display filter), so it cannot precisely cap matched output.
Instead we read all matches and slice in Python, reporting ``truncated``.
"""

from __future__ import annotations

from ..executor import TSharkExecutor
from ..filters import (
    build_protocol_filter,
    build_stream_filter,
    build_time_filter,
    combine,
)
from ..models import ExtractPacketsParams, ExtractResult, ExtractedPacket, StreamParams
from ..utils import is_float

# Summary fields — _row_to_packet zips these with each tshark row, so this list
# is the single source of truth for column meaning (no magic indices).
_SUMMARY_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ip.dst",
    "_ws.col.Protocol",
    "frame.len",
    "_ws.col.Info",
]


def _row_to_packet(row: list[str]) -> ExtractedPacket:
    # Zip field names with row values; pad short rows via dict.get default "".
    # Robust to tshark emitting fewer columns when a field is absent.
    pairs = dict(zip(_SUMMARY_FIELDS, row))
    num = pairs.get("frame.number", "").strip()
    rel = pairs.get("frame.time_relative", "").strip()
    length = pairs.get("frame.len", "").strip()
    return ExtractedPacket(
        frame_number=int(num) if num.isdigit() else 0,
        time_relative=float(rel) if is_float(rel) else 0.0,
        source=pairs.get("ip.src", "").strip(),
        destination=pairs.get("ip.dst", "").strip(),
        protocol=pairs.get("_ws.col.Protocol", "").strip(),
        length=int(length) if length.isdigit() else 0,
        info=pairs.get("_ws.col.Info", ""),
    )


async def _extract(
    executor: TSharkExecutor,
    pcap_file: str,
    flt: str | None,
    output_format: str,
    limit: int,
) -> ExtractResult:
    if output_format == "summary":
        rows = await executor.packets_fields(
            pcap_file, fields=_SUMMARY_FIELDS, display_filter=flt
        )
        packets = [_row_to_packet(r) for r in rows]
    else:
        packets = await executor.packets_json(pcap_file, display_filter=flt)

    truncated = len(packets) > limit
    sliced = packets[:limit]
    return ExtractResult(
        packets=sliced,
        total_returned=len(sliced),
        truncated=truncated,
        filter_applied=flt or "(none)",
    )


async def extract_packets(
    executor: TSharkExecutor, params: ExtractPacketsParams
) -> ExtractResult:
    """Extract packets by protocol and/or time window."""
    proto = build_protocol_filter(params.protocol)  # raises ValueError if disallowed
    time_f = build_time_filter(params.time_window)
    flt = combine(proto, time_f)
    return await _extract(
        executor, params.pcap_file, flt, params.output_format, params.limit
    )


async def extract_stream(
    executor: TSharkExecutor, params: StreamParams
) -> ExtractResult:
    """Extract all packets of one TCP stream / UDP session (both directions)."""
    stream_f = build_stream_filter(params)
    time_f = build_time_filter(params.time_window)
    flt = combine(stream_f, time_f)
    return await _extract(
        executor, params.pcap_file, flt, params.output_format, params.limit
    )
