"""list_conversations tool logic."""

from __future__ import annotations

import asyncio
from typing import Literal

from ..executor import TSharkExecutor
from ..models import Conversation, ConversationsResult
from ..parsers import parse_conversations


async def get_conversations(
    executor: TSharkExecutor,
    pcap_file: str,
    protocol: Literal["tcp", "udp", "both"] = "both",
    limit: int = 100,
) -> ConversationsResult:
    """List TCP and/or UDP conversations, capped at ``limit``.

    ``protocol`` is ``"tcp"``, ``"udp"`` or ``"both"``. The selected protocols
    are queried concurrently; results are concatenated then truncated.
    """
    wanted = ("tcp", "udp") if protocol == "both" else (protocol,)
    texts = await asyncio.gather(
        *(executor.tshark(pcap_file, ["-q", "-z", f"conv,{p}"]) for p in wanted)
    )
    convs: list[Conversation] = []
    for proto, text in zip(wanted, texts):
        convs.extend(parse_conversations(text, proto))
    sliced = convs[:limit]
    return ConversationsResult(conversations=sliced, total=len(convs))
