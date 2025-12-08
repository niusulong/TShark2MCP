# TShark2MCP - AI 辅助报文分析的 MCP 协议工具

基于 Wireshark 的 TShark 命令行工具，构建一个支持 Model Context Protocol (MCP) 的 AI 辅助报文分析服务器，让 AI 助手能够通过标准化的 MCP 协议调用报文提取工具，辅助用户快速定位和分析网络通信异常。

## 功能概述

提供6个核心报文分析工具，支持：
- pcap 文件概览分析
- 网络会话提取
- 时间范围过滤
- 协议类型过滤
- 特定网络流分析
- 统计指标计算

## 环境要求

- **Python 3.8+**
- **Wireshark/TShark 4.0+**

## 安装步骤

### 1. 安装 Wireshark

**Windows:**
- 下载并安装 [Wireshark](https://www.wireshark.org/download.html)
- 确保 TShark 被添加到系统 PATH，或记录安装路径


### 2. 安装 Python 依赖

```bash
pip install -r requirements.txt
```

## MCP 服务器配置

将以下配置添加到支持 MCP 协议的 AI 助手（如 Cursor、VS Code、Claude Desktop）中：

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
        "TSHARK_PATH": "C:\\Program Files\\Wireshark\\tshark.exe"
      }
    }
  }
}
```

### 配置说明

- **command**: 启动服务器的命令（python）
- **args**: 服务器入口文件的绝对路径
- **env**: 环境变量配置
  - `PYTHONPATH`: 确保 Python 能找到项目模块
  - `TSHARK_PATH`: TShark 可执行文件路径

**重要**: 请根据实际安装路径修改 `args` 和 `TSHARK_PATH` 的值。

### TShark 路径配置

项目支持多种 TShark 路径配置方式，按优先级排序：

1. **环境变量 TSHARK_PATH** (推荐)
   ```bash
   export TSHARK_PATH="C:\Program Files\Wireshark\tshark.exe"
   ```

2. **系统 PATH 中的 tshark**
   - 确保 Wireshark 安装时添加到系统 PATH

3. **自动检测** (备用)
   - 项目会尝试在常见位置查找 TShark

## 启动服务器

```bash
python main.py
```

## 贡献

欢迎提交 Issue 和 Pull Request 来改进项目。

## 许可证

[项目许可证]