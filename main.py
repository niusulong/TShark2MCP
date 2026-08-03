#!/usr/bin/env python3
"""Thin backward-compatible entry point.

Delegates to the installed ``tshark_mcp`` package. Kept so existing MCP client
configs using ``python main.py`` keep working. Prefer ``python -m tshark_mcp``
or the ``tshark-mcp`` console script for new setups.
"""

from tshark_mcp import run

if __name__ == "__main__":
    run()
