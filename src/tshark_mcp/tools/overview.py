"""get_pcap_overview tool logic.

File-level metadata + protocol distribution, WITHOUT loading individual packets.
Uses capinfos (cheap) + ``tshark -z io,phs`` instead of the original
``executor.execute(pcap_file)`` which parsed every packet as JSON.
"""

from __future__ import annotations

import asyncio
import os

from ..executor import TSharkExecutor
from ..models import OverviewResult
from ..parsers import parse_capinfos, parse_io_phs


async def get_overview(executor: TSharkExecutor, pcap_file: str) -> OverviewResult:
    """Build the file overview from capinfos + io,phs (concurrent)."""
    capinfos_text, io_phs_text = await asyncio.gather(
        executor.capinfos(pcap_file),
        executor.tshark(pcap_file, ["-q", "-z", "io,phs"]),
    )
    info = parse_capinfos(capinfos_text)
    hierarchy = parse_io_phs(io_phs_text)
    return OverviewResult(
        file_path=pcap_file,
        file_size_bytes=os.path.getsize(pcap_file),
        total_packets=info["total_packets"],
        capture_duration_seconds=info["capture_duration"],
        time_range={"start": info["earliest_time"], "end": info["latest_time"]},
        encapsulation=info["encapsulation"] or "unknown",
        protocol_hierarchy=hierarchy,
    )
