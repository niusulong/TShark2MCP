# TShark2MCP

AI-assisted pcap/pcapng analysis over the
[Model Context Protocol](https://modelcontextprotocol.io). Wraps Wireshark's
`tshark` / `capinfos` as 5 typed MCP tools so AI clients (Claude Desktop,
Cursor, VS Code) can analyze network captures through a standardized interface.

All processing is local — captures never leave the machine.

## Tools

Each tool exposes a full JSON Schema (auto-generated from typed parameters),
so the AI client knows exactly what to pass and what comes back.

| Tool | Purpose |
|---|---|
| `get_pcap_overview` | File metadata + protocol hierarchy (`capinfos` + `io,phs` — loads no individual packet) |
| `list_conversations` | TCP streams / UDP sessions with per-direction packet/byte counts |
| `extract_packets` | Filter by protocol and/or capture-relative time window |
| `extract_stream` | Deep-dive one TCP stream / UDP session by 5-tuple (matches both directions) |
| `get_statistics` | Retransmission rate, throughput, duplicate ACKs, out-of-order, HTTP latency |

## Requirements

- **Python ≥ 3.10**
- **Wireshark ≥ 4.0** (provides `tshark` and `capinfos`)

## Install

```bash
cd TShark2MCP
python -m venv .venv
.venv\Scripts\activate                 # Windows; `source .venv/bin/activate` on Unix
pip install -e ".[dev]"
```

`tshark` is found by cascading lookup:
1. `TSHARK_PATH` env var (executable file **or** Wireshark install directory)
2. Common Windows install dirs (`C:\Program Files\Wireshark`, ...)
3. System `PATH`

## Run

```bash
python -m tshark_mcp                    # stdio transport (default)
# or the console script the editable install registered:
tshark-mcp
```

## Configure an MCP client

Claude Desktop / Cursor (`claude_desktop_config.json` or equivalent). Point
`command` at your project venv's python:

```json
{
  "mcpServers": {
    "tshark": {
      "command": "D:\\<path>\\TShark2MCP\\.venv\\Scripts\\python.exe",
      "args": ["-m", "tshark_mcp"],
      "env": {
        "TSHARK_PATH": "C:\\Program Files\\Wireshark\\tshark.exe"
      }
    }
  }
}
```

`TSHARK_PATH` is optional if `tshark` is already on `PATH`.

## Test

```bash
pytest                                  # all tests (integration ones need tshark)
pytest -m "not integration"             # pure unit tests only (no tshark)
```

Integration tests use the sample `.pcap` / `.pcapng` files in the repository
root.

## Architecture

```
src/tshark_mcp/
  server.py     MCPServer + register_all
  config.py     tshark/capinfos path resolution
  executor.py   async tshark/capinfos subprocess wrapper (non-blocking)
  filters.py    display-filter construction (typed, injection-safe)
  parsers.py    capinfos / io,phs / conv text parsing
  security.py   protocol allowlist
  models.py     pydantic request/response models  (= each tool's inputSchema)
  tools/        overview, conversations, extract, statistics
```

**Design**: tool logic is pure `async (executor, params) -> result`;
`register_all` wires each onto `@mcp.tool()` with a shared `TSharkExecutor`
closure, so tools stay unit-testable with a mock executor and no MCP server.
