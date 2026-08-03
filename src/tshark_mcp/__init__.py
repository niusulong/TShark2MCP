"""TShark2MCP — MCP server for AI-assisted pcap analysis via Wireshark's tshark."""

from __future__ import annotations

__version__ = "2.0.0"


def run() -> None:
    """Run the MCP server over stdio (blocking).

    Equivalent to ``python -m tshark_mcp`` or the ``tshark-mcp`` console script.
    """
    from .server import create_server

    create_server().run()


__all__ = ["run", "__version__"]
