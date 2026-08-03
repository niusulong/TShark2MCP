"""Small shared helpers used across tool modules."""

from __future__ import annotations


def is_float(s: str) -> bool:
    """Return True if ``s`` parses as a float (tolerates surrounding whitespace)."""
    try:
        float(s)
        return True
    except (ValueError, TypeError):
        return False
