"""Programmatic display-filter construction.

SECURITY MODEL: no raw user string ever enters a display filter. Every value
is one of:
  - a pydantic-validated object (``IPv4Address``/``IPv6Address``, ``int`` port,
    ``datetime``) whose ``str()`` is a safe literal,
  - the output of ``float()`` / ``strftime()``, or
  - an allowlisted protocol token (lowercased).

This closes the injection surface of the original ``f'ip.src == {src_ip}...'``
implementation, where a crafted ``protocol``/``src_ip`` could alter filter
semantics.
"""

from __future__ import annotations

from .models import AbsoluteWindow, RelativeWindow, StreamParams, TimeWindow
from .security import is_allowed_protocol


def build_time_filter(tw: TimeWindow | None) -> str | None:
    """Build a relative (``frame.time_relative``) or absolute (``frame.time``) filter.

    The original code embedded raw time strings like ``"14:00:00"`` into
    ``frame.time >= "..."``, which cannot match tshark's ISO absolute timestamps
    (e.g. ``2000-01-02T02:17:15...+0800``). Relative windows use numeric
    comparison here, which is the correct and robust form.
    """
    if tw is None:
        return None
    if isinstance(tw, RelativeWindow):
        return (
            f"frame.time_relative >= {float(tw.start_seconds)} "
            f"and frame.time_relative <= {float(tw.end_seconds)}"
        )
    if isinstance(tw, AbsoluteWindow):
        fmt = '"%Y-%m-%d %H:%M:%S.%f"'
        start = tw.start.strftime(fmt)
        end = tw.end.strftime(fmt)
        return f"frame.time >= {start} and frame.time <= {end}"
    raise ValueError(f"unknown time window type: {type(tw)!r}")


def build_protocol_filter(protocol: str | None) -> str | None:
    """Return the lowercased protocol token after allowlist validation."""
    if protocol is None:
        return None
    if not is_allowed_protocol(protocol):
        raise ValueError(f"protocol not allowed: {protocol!r}")
    return protocol.lower()


def build_stream_filter(p: StreamParams) -> str:
    """Build a bidirectional 5-tuple filter (matches both directions).

    The original ``extract_stream`` matched only one direction and silently
    dropped return packets; this matches both.
    """
    proto = p.protocol
    a, b = p.endpoint_a, p.endpoint_b
    fwd = (
        f"ip.src == {a.address} and {proto}.srcport == {a.port} "
        f"and ip.dst == {b.address} and {proto}.dstport == {b.port}"
    )
    rev = (
        f"ip.src == {b.address} and {proto}.srcport == {b.port} "
        f"and ip.dst == {a.address} and {proto}.dstport == {b.port}"
    )
    return f"({fwd}) or ({rev})"


def combine(*parts: str | None) -> str | None:
    """AND-combine non-empty filter parts, parenthesizing when more than one."""
    real = [p for p in parts if p]
    if not real:
        return None
    if len(real) == 1:
        return real[0]
    return "(" + ") and (".join(real) + ")"
