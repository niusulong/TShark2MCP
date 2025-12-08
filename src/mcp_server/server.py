import asyncio
import json
import logging
import os
from typing import Dict, Any, Callable, Optional
import sys


class TSharkMCPServer:
    """
    TShark2MCP服务器核心类
    实现MCP协议服务器，注册和管理报文提取工具
    """
    
    def __init__(self, tshark_path: Optional[str] = None, skip_tshark_check: bool = False):
        """
        初始化MCP服务器

        Args:
            tshark_path: TShark可执行文件路径，默认从PATH查找
            skip_tshark_check: 是否跳过TShark可用性检查（用于测试）
        """
        # 优先使用环境变量中的TSHARK_PATH，其次是传入的参数，最后才是默认值
        self.tshark_path = tshark_path or os.environ.get('TSHARK_PATH', 'tshark')
        self.tools: Dict[str, Callable] = {}
        self.logger = logging.getLogger(__name__)

        # 检测TShark是否可用
        if not skip_tshark_check:
            self._check_tshark_availability()
    
    def _check_tshark_availability(self):
        """
        检测TShark是否可用
        """
        import subprocess
        try:
            result = subprocess.run([self.tshark_path, "--version"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise RuntimeError(f"TShark不可用: {result.stderr}")
            self.logger.info(f"TShark版本信息: {result.stdout.split('\\n')[0]}")
        except FileNotFoundError:
            raise RuntimeError(f"未找到TShark，请确保{self.tshark_path}在系统PATH中")
        except Exception as e:
            raise RuntimeError(f"TShark检查失败: {str(e)}")
    
    def register_tool(self, name: str, func: Callable):
        """
        注册工具函数
        
        Args:
            name: 工具名称
            func: 工具函数
        """
        self.tools[name] = func
        self.logger.debug(f"工具已注册: {name}")
    
    def _handle_initialize(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理MCP初始化请求
        
        Args:
            request: 初始化请求
            
        Returns:
            初始化响应
        """
        params = request.get('params', {})
        client_info = params.get('clientInfo', {})
        
        self.logger.info(f"MCP客户端初始化: {client_info}")
        
        # initialize响应的id字段处理：如果请求没有id，则不包含id字段
        response = {
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "TShark2MCP",
                    "version": "1.0.0"
                }
            }
        }
        
        # 只有当请求包含id时，响应才包含id
        if 'id' in request:
            response['id'] = request['id']
            
        return response
    
    def get_tool(self, name: str) -> Optional[Callable]:
        """
        获取工具函数
        
        Args:
            name: 工具名称
            
        Returns:
            工具函数或None
        """
        return self.tools.get(name)
    
    def list_tools(self) -> list:
        """
        获取工具列表
        
        Returns:
            工具信息列表
        """
        return [
            {
                "name": name,
                "description": getattr(func, '__doc__', 'No description') or 'No description'
            }
            for name, func in self.tools.items()
        ]
    
    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理来自AI客户端的请求
        
        Args:
            request: MCP请求字典
            
        Returns:
            MCP响应字典
        """
        try:
            method = request.get('method')
            
            if method == 'initialize':
                return self._handle_initialize(request)
            
            elif method == 'tools/list':
                return self._handle_list_tools(request)
            
            elif method == 'tools/call':
                return await self._handle_call_tool(request)
            
            else:
                return self._create_error_response(
                    request.get('id'),
                    f"不支持的方法: {method}",
                    -32601  # Method not found
                )
        except Exception as e:
            self.logger.error(f"处理请求时发生错误: {str(e)}", exc_info=True)
            return self._create_error_response(
                request.get('id'),
                f"内部服务器错误: {str(e)}",
                -32603  # Internal error
            )
    
    def _handle_list_tools(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理工具列表请求
        
        Args:
            request: MCP请求字典
            
        Returns:
            工具列表响应
        """
        tools = []
        for name, func in self.tools.items():
            # 获取input_schema，如果没有则提供默认的JSON Schema
            input_schema = getattr(func, 'input_schema', None)
            if input_schema is None:
                input_schema = {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            
            # 获取工具描述，使用简化的英文描述
            doc = getattr(func, '__doc__', '') or ''
            if doc:
                # 提取第一行作为简短描述
                first_line = doc.strip().split('\n')[0].strip()
                # 为每个工具提供简化的英文描述
                descriptions = {
                    'get_pcap_overview': 'Get basic information and statistics overview of pcap file',
                    'list_conversations': 'List all network conversations (TCP streams, UDP sessions) in pcap',
                    'extract_by_time': 'Extract packets within specified time range',
                    'extract_by_protocol': 'Extract packets by protocol type',
                    'extract_stream': 'Extract all packets from specific network stream',
                    'get_statistics': 'Get statistical metrics (latency, throughput, retransmission rate)'
                }
                description = descriptions.get(name, first_line)
            else:
                description = 'No description'
            
            tool_info = {
                "name": name,
                "description": description,
                "inputSchema": input_schema
            }
            tools.append(tool_info)
        
        return {
            "jsonrpc": "2.0",
            "result": {
                "tools": tools
            },
            "id": request.get('id')
        }
    
    async def _handle_call_tool(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理工具调用请求
        
        Args:
            request: 调用工具的请求
            
        Returns:
            工具执行结果响应
        """
        params = request.get('params', {})
        tool_name = params.get('name')
        tool_args = params.get('arguments', {})
        
        if not tool_name:
            return self._create_error_response(
                request.get('id'),
                "缺少工具名称参数",
                -32602  # Invalid params
            )
        
        tool_func = self.get_tool(tool_name)
        if not tool_func:
            return self._create_error_response(
                request.get('id'),
                f"未知工具: {tool_name}",
                -32602  # Invalid params
            )
        
        try:
            # 执行工具函数
            result = await self._execute_tool(tool_func, tool_args)
            return {
                "jsonrpc": "2.0",
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": str(result)
                        }
                    ]
                },
                "id": request.get('id')
            }
        except Exception as e:
            self.logger.error(f"执行工具 {tool_name} 时发生错误: {str(e)}", exc_info=True)
            return self._create_error_response(
                request.get('id'),
                f"工具执行错误: {str(e)}",
                -32603  # Internal error
            )
    
    async def _execute_tool(self, tool_func: Callable, args: Dict[str, Any]) -> Any:
        """
        执行工具函数
        
        Args:
            tool_func: 工具函数
            args: 工具参数
            
        Returns:
            工具执行结果
        """
        # 如果工具函数不是协程，则包装为协程
        import inspect
        if inspect.iscoroutinefunction(tool_func):
            return await tool_func(**args)
        else:
            return tool_func(**args)
    
    def _create_error_response(self, request_id: Optional[str], 
                             message: str, code: int) -> Dict[str, Any]:
        """
        创建错误响应
        
        Args:
            request_id: 请求ID
            message: 错误消息
            code: 错误代码
            
        Returns:
            错误响应字典
        """
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message
            },
            "id": request_id
        }
    
    def register_all_tools(self):
        """
        注册所有预定义的工具
        """
        # 动态导入工具并注册
        import sys
        import os
        # 添加src目录到Python路径以解决导入问题
        src_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)))
        if src_dir not in sys.path:
            sys.path.insert(0, src_dir)

        from tools import (
            get_pcap_overview,
            list_conversations,
            extract_by_time,
            extract_by_protocol,
            extract_stream,
            get_statistics
        )

        # 注册所有工具
        self.register_tool("get_pcap_overview", get_pcap_overview)
        self.register_tool("list_conversations", list_conversations)
        self.register_tool("extract_by_time", extract_by_time)
        self.register_tool("extract_by_protocol", extract_by_protocol)
        self.register_tool("extract_stream", extract_stream)
        self.register_tool("get_statistics", get_statistics)

    async def run_forever(self):
        """
        运行服务器循环，从stdin读取请求
        """
        # 注册所有工具
        self.register_all_tools()
        self.logger.info("TShark2MCP服务器启动...")
        self.logger.info(f"已注册工具: {list(self.tools.keys())}")
        # 移除非JSON格式的就绪信号，MCP协议要求所有通信都是JSON-RPC格式

        while True:
            try:
                # 从stdin读取一行
                line = await self._read_line()
                if not line.strip():
                    continue

                self.logger.debug(f"收到请求: {line[:200]}...")  # 记录收到的请求

                # 解析JSON请求
                try:
                    request = json.loads(line)
                except json.JSONDecodeError as e:
                    self.logger.error(f"JSON解析错误: {str(e)}, 输入: {line[:100]}...")
                    continue

                # 处理请求
                response = await self.handle_request(request)

                # 发送响应到stdout
                await self._send_response(response)

            except KeyboardInterrupt:
                self.logger.info("收到中断信号，关闭服务器...")
                break
            except EOFError:
                self.logger.info("输入流结束，关闭服务器...")
                break
            except Exception as e:
                self.logger.error(f"服务器运行时错误: {str(e)}", exc_info=True)
                break
    
    async def _read_line(self) -> str:
        """
        异步读取一行输入
        
        Returns:
            读取的字符串行
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, sys.stdin.readline)
    
    async def _send_response(self, response: Dict[str, Any]):
        """
        异步发送响应到stdout
        
        Args:
            response: 要发送的响应字典
        """
        try:
            response_json = json.dumps(response, ensure_ascii=False, separators=(',', ':'))
            print(response_json, flush=True)
        except Exception as e:
            self.logger.error(f"发送响应回失败: {str(e)}")


def create_server(tshark_path: Optional[str] = None) -> TSharkMCPServer:
    """
    创建TShark MCP服务器实例

    Args:
        tshark_path: TShark可执行文件路径

    Returns:
        TSharkMCP服务器实例
    """
    # 如果没有显式提供tshark_path，则尝试从环境变量获取
    if tshark_path is None:
        tshark_path = os.environ.get('TSHARK_PATH')
    return TSharkMCPServer(tshark_path)