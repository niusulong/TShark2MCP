"""Async tshark / capinfos subprocess executor.

All tshark invocations go through here, unifying the original two divergent
code paths. Uses ``asyncio.create_subprocess_exec`` so the MCP server's event
loop is never blocked by a long tshark run.

Encoding: tshark emits UTF-8 for both ``-T json`` and ``-T fields`` / ``-z``
statistics — verified empirically (the U+2192 arrow in ``_ws.col.Info`` is the
bytes ``E2 86 92`` even on a cp936 system). ``_run`` therefore defaults to
UTF-8; the ``encoding`` arg lets a caller override if a future build changes
this.
"""

from __future__ import annotations

import asyncio
import logging

from .config import DEFAULT_TIMEOUT_SECONDS
from .parsers import parse_packet_json

logger = logging.getLogger(__name__)


class TSharkExecutor:
    """Async wrapper around the tshark and capinfos executables."""

    def __init__(
        self,
        tshark_path: str,
        capinfos_path: str | None = None,
        default_timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.tshark_path = tshark_path
        self.capinfos_path = capinfos_path
        self.default_timeout = default_timeout

    async def _run(
        self,
        args: list[str],
        timeout: float | None = None,
        encoding: str = "utf-8",
    ) -> str:
        """Run ``args`` and return decoded stdout (UTF-8 by default).

        Raises ``TimeoutError`` (process killed) or ``RuntimeError`` on non-zero
        exit; causation preserved via ``raise ... from``.
        """
        logger.debug("exec: %s", " ".join(args))
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=timeout or self.default_timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise TimeoutError(f"command timed out: {args[0]}") from None

        if proc.returncode != 0:
            err = (stderr_b or b"").decode(errors="replace")[:500]
            raise RuntimeError(f"{args[0]} failed (rc={proc.returncode}): {err}")

        return (stdout_b or b"").decode(encoding, errors="replace")

    async def tshark(
        self,
        pcap: str,
        extra: list[str] | None = None,
        timeout: float | None = None,
        encoding: str = "utf-8",
    ) -> str:
        """Run ``tshark -r <pcap> [extra...]`` and return raw stdout text."""
        args = [self.tshark_path, "-r", pcap, *(extra or [])]
        return await self._run(args, timeout, encoding)

    async def capinfos(self, pcap: str, timeout: float | None = None) -> str:
        """Run ``capinfos <pcap>`` and return raw stdout text."""
        if not self.capinfos_path:
            raise RuntimeError("capinfos not available; cannot gather file overview")
        return await self._run([self.capinfos_path, pcap], timeout)

    async def packets_json(
        self,
        pcap: str,
        display_filter: str | None = None,
        timeout: float | None = None,
    ) -> list[dict]:
        """Run ``tshark -T json`` and return parsed packets.

        Parsing is delegated to :func:`parsers.parse_packet_json` so the
        executor stays focused on process management.
        """
        extra = ["-T", "json"]
        if display_filter:
            extra += ["-Y", display_filter]
        raw = await self.tshark(pcap, extra, timeout)
        return parse_packet_json(raw)

    async def packets_fields(
        self,
        pcap: str,
        fields: list[str],
        display_filter: str | None = None,
        timeout: float | None = None,
    ) -> list[list[str]]:
        """Run ``tshark -T fields`` and return rows of field values.

        Uses ``\\x01`` (SOH) as the field separator: it never appears in
        protocol field values, avoiding the ``|`` collision risk (a ``|`` in
        ``_ws.col.Info`` would have been mis-split). Missing fields become
        empty strings; callers should tolerate short rows.
        """
        extra = ["-T", "fields", "-E", "separator=\x01"]
        for f in fields:
            extra += ["-e", f]
        if display_filter:
            extra += ["-Y", display_filter]
        raw = await self.tshark(pcap, extra, timeout)
        return [line.split("\x01") for line in raw.splitlines() if line]

    async def export_filtered(
        self, pcap: str, display_filter: str, timeout: float | None = None
    ) -> str:
        """Write packets matching ``display_filter`` to a temp pcap; return path.

        Caller MUST delete the temp file. Used by get_statistics to scope
        ``-z conv`` / ``-z io,phs`` (which don't accept ``-Y``) to a window.
        """
        import os
        import tempfile

        fd, tmp_path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            await self._run(
                [self.tshark_path, "-r", pcap, "-Y", display_filter, "-w", tmp_path],
                timeout,
            )
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        return tmp_path
