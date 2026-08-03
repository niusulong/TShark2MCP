# TShark2MCP 配置说明

## 环境要求

- **Python ≥ 3.10**
- **Wireshark ≥ 4.0**（提供 `tshark` 和 `capinfos`）

## 安装

```bash
cd TShark2MCP
python -m venv .venv
.venv\Scripts\activate                 # Windows；Unix 用 source .venv/bin/activate
pip install -e ".[dev]"
```

editable install 会注册 `tshark-mcp` 命令，并让 `tshark_mcp` 包可被 import。

## MCP 客户端配置

将以下配置添加到支持 MCP 协议的 AI 助手（Claude Desktop / Cursor / VS Code）：

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

### 字段说明

- `command`：项目 venv 的 python（editable install 后才能 `import tshark_mcp`）
- `args`：`-m tshark_mcp` 启动 server；也可改用 console script `tshark-mcp`
- `env.TSHARK_PATH`：可选。未设置时按优先级查找：`TSHARK_PATH` → 常见 Windows 安装目录 → 系统 PATH

> **不再需要 `PYTHONPATH`** —— 包已通过 `pip install -e .` 安装。

## tshark 路径查找优先级

`config.resolve_tshark_paths()` 级联查找：

1. 环境变量 `TSHARK_PATH`（可指向 tshark 可执行文件，或 Wireshark 安装目录）
2. 常见 Windows 路径（`C:\Program Files\Wireshark\`、`C:\Program Files (x86)\Wireshark\`）
3. 系统 PATH（`tshark` / `capinfos`）

`capinfos` 在 tshark 同目录推导。

## 工具列表（5 个）

| 工具 | 作用 |
|---|---|
| `get_pcap_overview` | 文件概览 + 协议层次分布（capinfos + io,phs，不加载单包）|
| `list_conversations` | TCP 流 / UDP 会话（双向包/字节统计）|
| `extract_packets` | 按协议 + 时间窗组合过滤提取报文 |
| `extract_stream` | 按五元组提取单条 TCP 流 / UDP 会话（双向）|
| `get_statistics` | 吞吐 / 重传率 / 丢包 / TCP 连接 / HTTP 延迟 |

每个工具的 inputSchema / outputSchema 由 pydantic 模型自动生成，客户端能完整感知参数与返回结构。

## 协议支持

通过 tshark 原生协议过滤器支持广泛的协议。`extract_packets` 的 `protocol` 参数经白名单（`security.PROTOCOL_ALLOWLIST`）校验，常用协议已内置：

- 传输/网络：tcp、udp、ip、ipv6、arp、icmp、icmpv6、eth
- 应用层：http、http2、dns、tls、ssl、ftp、ftps、mqtt、coap、ssh、telnet、smtp、pop、imap、ntp、dhcp、snmp、rtsp、sip、ldap、websocket ...

新协议只需在 `PROTOCOL_ALLOWLIST` 添加一项即可，无需改其他代码。非法协议名会被拒绝（防止 display-filter 注入）。

## 验证安装

```bash
python -m tshark_mcp          # 应启动并等待 stdio 输入（JSON-RPC）
pytest                        # 跑全部测试（integration 需 tshark）
```
