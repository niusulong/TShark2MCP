"""Parsers for tshark / capinfos text output.

Replaces the two divergent, buggy parsers in the original ``list_conversations``
and ``_calculate_tcp_connection_stats``. The critical fix: tshark 4.x
``conv,tcp``/``conv,udp`` *data* rows contain NO ``|`` separator (only the
header row does), so the original ``line.split('|')`` skipped every data row
and always returned ``[]``.
"""

from __future__ import annotations

import json
import re

from .models import Conversation, ProtocolStat

# ---------------------------------------------------------------------------
# capinfos
# ---------------------------------------------------------------------------


def parse_capinfos(text: str) -> dict:
    """Parse ``capinfos <pcap>`` output.

    Returns: total_packets (int), capture_duration (float),
    earliest_time (str), latest_time (str), encapsulation (str).
    """
    result: dict = {
        "total_packets": 0,
        "capture_duration": 0.0,
        "earliest_time": "",
        "latest_time": "",
        "encapsulation": "",
    }

    m = re.search(r"^Number of packets:\s*(\d+)", text, re.MULTILINE)
    if m:
        result["total_packets"] = int(m.group(1))

    m = re.search(r"^Capture duration:\s*([\d.]+)", text, re.MULTILINE)
    if m:
        result["capture_duration"] = float(m.group(1))

    m = re.search(r"^Earliest packet time:\s*(.+)$", text, re.MULTILINE)
    if m:
        result["earliest_time"] = m.group(1).strip()

    m = re.search(r"^Latest packet time:\s*(.+)$", text, re.MULTILINE)
    if m:
        result["latest_time"] = m.group(1).strip()

    # Multi-encapsulation files list "Ethernet (50)" under "Encapsulation in use".
    m = re.search(r"^\s+(\w+)\s+\(\d+\)\s*$", text, re.MULTILINE)
    if m:
        result["encapsulation"] = m.group(1)
    else:
        m = re.search(r"^File encapsulation:\s*(.+)$", text, re.MULTILINE)
        if m:
            enc = m.group(1).strip()
            if enc and enc != "Per packet":
                result["encapsulation"] = enc

    return result


# ---------------------------------------------------------------------------
# io,phs (protocol hierarchy)
# ---------------------------------------------------------------------------

_IO_PHS_ROW = re.compile(
    r"^(?P<indent>\s*)(?P<proto>\S+)\s+frames:(?P<frames>\d+)\s+bytes:(?P<bytes>\d+)"
)


def parse_io_phs(text: str) -> list[ProtocolStat]:
    """Parse ``tshark -q -z io,phs`` output into per-protocol frame/byte stats."""
    stats: list[ProtocolStat] = []
    for line in text.splitlines():
        m = _IO_PHS_ROW.match(line)
        if m:
            stats.append(
                ProtocolStat(
                    protocol=m.group("proto"),
                    frames=int(m.group("frames")),
                    bytes=int(m.group("bytes")),
                )
            )
    return stats


# ---------------------------------------------------------------------------
# conv,tcp / conv,udp
# ---------------------------------------------------------------------------

# Data rows look like (NO pipe separators):
#   10.62.18.9:34933 <-> 120.86.64.161:10020   17 3058 bytes  22 2097 bytes  39 5155 bytes  0.000000000  2.3850
# Column order per tshark header:  <- (reverse) | -> (forward) | Total | Relative start | Duration
# src_addr/S+ may be IPv4 or bracketed IPv6; \S+ before the last :port handles both.
_CONV_ROW = re.compile(
    r"(?P<src_addr>\S+):(?P<src_port>\d+)\s*<->\s*"
    r"(?P<dst_addr>\S+):(?P<dst_port>\d+)\s+"
    r"(?P<rev_frames>\d+)\s+(?P<rev_bytes>\d+)\s+bytes\s+"
    r"(?P<fwd_frames>\d+)\s+(?P<fwd_bytes>\d+)\s+bytes\s+"
    r"(?:\d+)\s+(?:\d+)\s+bytes\s+"  # total frames/bytes (re-derivable, ignored)
    r"(?P<rel_start>[\d.]+)\s+(?P<duration>[\d.]+)"
)


def parse_conversations(text: str, protocol: str) -> list[Conversation]:
    """Parse ``tshark -q -z conv,<tcp|udp>`` output into Conversation records.

    ``protocol`` is the literal ``"tcp"``/``"udp"`` tag attached to each record.
    """
    convs: list[Conversation] = []
    for line in text.splitlines():
        m = _CONV_ROW.search(line)
        if not m:
            continue
        convs.append(
            Conversation(
                protocol=protocol,  # type: ignore[arg-type]
                src_address=m.group("src_addr"),
                src_port=int(m.group("src_port")),
                dst_address=m.group("dst_addr"),
                dst_port=int(m.group("dst_port")),
                # '->' (forward = src->dst) is the second numeric pair
                packets_forward=int(m.group("fwd_frames")),
                bytes_forward=int(m.group("fwd_bytes")),
                # '<-' (reverse = dst->src) is the first numeric pair
                packets_reverse=int(m.group("rev_frames")),
                bytes_reverse=int(m.group("rev_bytes")),
                relative_start=float(m.group("rel_start")),
                duration=float(m.group("duration")),
            )
        )
    return convs


# ---------------------------------------------------------------------------
# tshark -T json (packet list)
# ---------------------------------------------------------------------------


def parse_packet_json(raw: str) -> list[dict]:
    """Parse ``tshark -T json`` output into a list of packet dicts.

    tshark normally emits a single JSON array, but fall back to line-by-line
    parsing for the streaming NDJSON mode. Returns ``[]`` for empty output.
    """
    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if line:
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if isinstance(data, list):
        return data
    return [data] if data else []
