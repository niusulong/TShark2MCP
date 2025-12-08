# TShark2MCP 配置说明

## MCP 服务器配置

要将 TShark2MCP 集成到支持 MCP 协议的 AI 助手（如 Cursor、VS Code 等）中，需要在设置中添加以下配置：

```json
{
  "mcpServers": {
    "tshark2mcp": {
      "command": "python",
      "args": [
        "D:\\niusulong\\wireshark_mcp\\TShark2MCP\\main.py"
      ],
      "env": {
        "PYTHONPATH": "D:\\niusulong\\wireshark_mcp\\TShark2MCP\\src",
        "TSHARK_PATH": "D:\\niusulong\\wireshark_mcp\\Wireshark\\tshark.exe"
      }
    }
  }
}
```

**注意**：
- TShark2MCP 已内置 TShark 路径自动检测功能，如果未设置 `TSHARK_PATH` 环境变量，会自动尝试使用项目内置的 Wireshark 目录中的 tshark.exe
- 建议显式设置 `TSHARK_PATH` 以确保稳定性

## 配置说明

- `command`: 启动服务器的命令（python）
- `args`: 命令行参数（使用绝对路径的main.py是服务器入口）
- `env`: 环境变量
  - `PYTHONPATH`: 确保Python能找到项目模块
  - `TSHARK_PATH`: 指定TShark可执行文件路径

## 环境要求

- Python 3.8+
- TShark 4.0+ （已包含在项目 Wireshark 目录中）
- 项目依赖：`pip install -r requirements.txt`

## 使用说明

1. 确保 TShark 已正确安装或使用项目内置版本
2. 在项目根目录运行 `pip install -r requirements.txt`
3. 将配置添加到 AI 助手的设置中
4. AI 助手将能够自动发现并调用以下工具：
   - get_pcap_overview: 获取 pcap 文件概览
   - list_conversations: 列出网络会话
   - extract_by_time: 按时间范围提取报文
   - extract_by_protocol: 按协议类型提取报文
   - extract_stream: 提取特定网络流
   - compare_streams: 比较两个网络流
   - get_statistics: 获取统计信息