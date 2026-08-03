"""MCP server definition and tool registration."""

from __future__ import annotations

import logging

from mcp.server import MCPServer

from . import __version__
from .config import resolve_tshark_paths
from .tools import register_all

logger = logging.getLogger(__name__)


def create_server() -> MCPServer:
    """Create the MCPServer, resolve tshark paths, register all tools.

    Logging goes to stderr so stdout stays clean for JSON-RPC, as required by
    the MCP stdio transport.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    tshark_path, capinfos_path = resolve_tshark_paths()
    logger.info("resolved tshark=%s capinfos=%s", tshark_path, capinfos_path)

    mcp = MCPServer("TShark2MCP", version=__version__)
    register_all(mcp, tshark_path=tshark_path, capinfos_path=capinfos_path)
    return mcp
