"""
TShark2MCP工具集合
实现7个核心报文提取工具
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

# 获取当前模块的路径，并添加到系统路径中
import sys
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(os.path.dirname(current_dir))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from utils import TSharkExecutor, global_cache
from utils.tshark_executor import validate_pcap_file


class ToolError(Exception):
    """工具执行异常"""
    pass


def _generate_cache_key(tool_name: str, **kwargs) -> str:
    """
    生成缓存键
    """
    import json
    key_data = {
        'tool': tool_name,
        'params': kwargs
    }
    return json.dumps(key_data, sort_keys=True, default=str)


# 全局TShark执行器实例，优先使用环境变量，然后是本地路径
_global_tshark_path = os.environ.get('TSHARK_PATH', 'tshark')
if _global_tshark_path == 'tshark':
    # 如果使用默认值，尝试查找本地TShark
    # 计算路径：__file__ -> tools -> src -> TShark2MCP -> wireshark_mcp (父目录) -> Wireshark -> tshark.exe
    tools_dir = os.path.dirname(os.path.abspath(__file__))          # .../tools
    src_dir = os.path.dirname(tools_dir)                           # .../src
    tshark2mcp_dir = os.path.dirname(src_dir)                      # .../TShark2MCP
    project_parent_dir = os.path.dirname(tshark2mcp_dir)           # .../wireshark_mcp (父目录)
    local_tshark_path = os.path.join(project_parent_dir, 'Wireshark', 'tshark.exe')
    print(f"DEBUG: 尝试本地TShark路径: {local_tshark_path}", file=sys.stderr)  # 调试输出
    if os.path.exists(local_tshark_path):
        _global_tshark_path = local_tshark_path

TSHARK_EXECUTOR = TSharkExecutor(_global_tshark_path)


async def get_pcap_overview(pcap_file: str) -> Dict[str, Any]:
    """
    获取pcap文件的基本信息和统计概览
    用途: 首次分析文件时使用，了解文件基本概况
    使用场景: "帮我看看这个pcap文件"
    
    Args:
        pcap_file: pcap文件路径
    
    Returns:
        文件概览信息
    """
    if not validate_pcap_file(pcap_file):
        raise ToolError(f"文件不存在或无效: {pcap_file}")
    
    cache_key = _generate_cache_key('get_pcap_overview', pcap_file=pcap_file)
    cached_result = global_cache.get(cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        executor = TSHARK_EXECUTOR  # 使用全局实例
        
        # 获取基本统计信息
        # 先获取所有包的基本信息
        all_packets = executor.execute(pcap_file)
        
        # 统计协议分布 - 使用更通用的方法
        protocol_stats = {}
        total_packets = len(all_packets)
        
        for packet in all_packets:
            if "_source" in packet and "layers" in packet["_source"]:
                layers = packet["_source"]["layers"]
                # 简单统计顶层协议
                for layer_key in layers:
                    if layer_key not in ["frame", "encap"]:
                        protocol = layer_key.split('.')[-1] if '.' in layer_key else layer_key
                        protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
                        break
        
        # 获取时间范围（如果包中包含时间信息）
        start_time = None
        end_time = None
        if all_packets:
            # 从第一个和最后一个数据包中提取时间
            first_pkt = all_packets[0]
            last_pkt = all_packets[-1]
            
            if "_source" in first_pkt and "layers" in first_pkt["_source"]:
                frame_info = first_pkt["_source"]["layers"].get("frame", {})
                start_time = frame_info.get("frame.time", "Unknown")
            
            if "_source" in last_pkt and "layers" in last_pkt["_source"]:
                frame_info = last_pkt["_source"]["layers"].get("frame", {})
                end_time = frame_info.get("frame.time", "Unknown")
        
        result = {
            "file_path": pcap_file,
            "file_size_bytes": Path(pcap_file).stat().st_size,
            "total_packets": total_packets,
            "time_range": {
                "start": start_time,
                "end": end_time
            },
            "protocol_distribution": protocol_stats,
            "total_conversations": 0  # 这个需要后续通过专门的命令获取
        }
        
        # 缓存结果
        global_cache.set(cache_key, result)
        return result
        
    except Exception as e:
        raise ToolError(f"获取文件概览失败: {str(e)}")


async def list_conversations(pcap_file: str) -> List[Dict[str, Any]]:
    """
    列出pcap中所有的网络会话（TCP流、UDP会话）
    用途: 需要了解有哪些网络连接时使用
    使用场景: "有哪些TCP连接？"
    
    Args:
        pcap_file: pcap文件路径
    
    Returns:
        会话列表
    """
    if not validate_pcap_file(pcap_file):
        raise ToolError(f"文件不存在或无效: {pcap_file}")
    
    cache_key = _generate_cache_key('list_conversations', pcap_file=pcap_file)
    cached_result = global_cache.get(cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        executor = TSHARK_EXECUTOR  # 使用全局实例
        
        # 使用tshark的conv功能来获取会话信息 - 先尝试tcp会话
        import subprocess
        # 首先尝试获取TCP会话
        tcp_cmd = [
            executor.tshark_path,
            "-r", pcap_file,
            "-q",  # 安静模式，只输出统计
            "-z", "conv,tcp"  # TCP会话统计
        ]
        
        tcp_result = subprocess.run(tcp_cmd, capture_output=True, text=True, timeout=30)
        conversations = []
        
        # 解析TCP会话
        if tcp_result.returncode == 0:
            output_lines = tcp_result.stdout.strip().split('\n')
            data_started = False
            for line in output_lines:
                line = line.strip()
                
                # 检查是否是标题行
                if 'Src Address' in line and 'Port' in line:
                    data_started = True
                    continue
                
                if not data_started:
                    continue
                    
                if line and '|' in line:
                    # 用 | 分隔的表格数据
                    parts = [p.strip() for p in line.split('|') if p.strip()]
                    if len(parts) >= 5:  # 至少有src, dst, packets, bytes等字段
                        try:
                            conv = {
                                "source": {
                                    "address": parts[0],
                                    "port": parts[1] if len(parts) > 1 else "N/A"
                                },
                                "destination": {
                                    "address": parts[2],
                                    "port": parts[3] if len(parts) > 3 else "N/A"
                                },
                                "protocol": "TCP",
                                "packets_forward": int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
                                "packets_reverse": int(parts[5]) if len(parts) > 5 and len(parts) > 5 and parts[5].isdigit() else 0,
                                "bytes_forward": int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0,
                                "bytes_reverse": int(parts[7]) if len(parts) > 7 and len(parts) > 7 and parts[7].isdigit() else 0,
                            }
                            conversations.append(conv)
                        except (ValueError, IndexError):
                            continue  # 跳过无法解析的行
        
        # 然后尝试UDP会话
        udp_cmd = [
            executor.tshark_path,
            "-r", pcap_file,
            "-q",
            "-z", "conv,udp"
        ]
        
        udp_result = subprocess.run(udp_cmd, capture_output=True, text=True, timeout=30)
        if udp_result.returncode == 0:
            output_lines = udp_result.stdout.strip().split('\n')
            data_started = False
            for line in output_lines:
                line = line.strip()
                
                # 检查是否是标题行
                if 'Src Address' in line and 'Port' in line:
                    data_started = True
                    continue
                
                if not data_started:
                    continue
                    
                if line and '|' in line:
                    # 用 | 分隔的表格数据
                    parts = [p.strip() for p in line.split('|') if p.strip()]
                    if len(parts) >= 5:  # 至少有src, dst, packets, bytes等字段
                        try:
                            conv = {
                                "source": {
                                    "address": parts[0],
                                    "port": parts[1] if len(parts) > 1 else "N/A"
                                },
                                "destination": {
                                    "address": parts[2],
                                    "port": parts[3] if len(parts) > 3 else "N/A"
                                },
                                "protocol": "UDP",
                                "packets_forward": int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
                                "packets_reverse": int(parts[5]) if len(parts) > 5 and len(parts) > 5 and parts[5].isdigit() else 0,
                                "bytes_forward": int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0,
                                "bytes_reverse": int(parts[7]) if len(parts) > 7 and len(parts) > 7 and parts[7].isdigit() else 0,
                            }
                            # 检查是否已存在相同的会话（避免重复）
                            exists = False
                            for existing_conv in conversations:
                                if (existing_conv['source']['address'] == conv['source']['address'] and
                                    existing_conv['source']['port'] == conv['source']['port'] and
                                    existing_conv['destination']['address'] == conv['destination']['address'] and
                                    existing_conv['destination']['port'] == conv['destination']['port']):
                                    exists = True
                                    break
                            if not exists:
                                conversations.append(conv)
                        except (ValueError, IndexError):
                            continue  # 跳过无法解析的行
        
        # 缓存结果
        global_cache.set(cache_key, conversations)
        return conversations
        
    except Exception as e:
        raise ToolError(f"列出会话失败: {str(e)}")


async def extract_by_time(pcap_file: str, start_time: str, end_time: str) -> List[Dict[str, Any]]:
    """
    根据时间范围提取报文
    用途: 用户提供了异常时间点，需要缩小分析范围
    使用场景: "14:32:15时连接断了" -> AI提取该时间点前后30秒报文
    
    Args:
        pcap_file: pcap文件路径
        start_time: 开始时间 (格式如 "2023-01-01 12:00:00" 或相对时间如 "-30s", "+30s")
        end_time: 结束时间 (格式如 "2023-01-01 12:05:00" 或相对时间如 "-30s", "+30s")
    
    Returns:
        指定时间范围内的报文列表
    """
    if not validate_pcap_file(pcap_file):
        raise ToolError(f"文件不存在或无效: {pcap_file}")
    
    cache_key = _generate_cache_key('extract_by_time', pcap_file=pcap_file, 
                                    start_time=start_time, end_time=end_time)
    cached_result = global_cache.get(cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        executor = TSHARK_EXECUTOR  # 使用全局实例
        
        # 对于相对时间格式的处理（如 "-30s", "+30s"）需要特殊处理
        # TShark直接支持绝对时间格式，如 "Jan  1, 2023 12:00:00"
        # 这里简化处理，直接使用原始时间字符串
        time_filter = f'frame.time >= "{start_time}" && frame.time <= "{end_time}"'
        
        result = executor.execute(pcap_file, display_filter=time_filter)
        
        # 缓存结果
        global_cache.set(cache_key, result)
        return result
        
    except Exception as e:
        raise ToolError(f"按时间提取报文失败: {str(e)}")


async def extract_by_protocol(pcap_file: str, protocol: str, 
                             start_time: Optional[str] = None, 
                             end_time: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    按协议类型提取报文
    用途: AI需要集中分析某类协议，减少无关协议的干扰
    使用场景: "只分析MQTT协议的报文" 或 "分析14:00-14:10期间的MQTT报文"
    
    Args:
        pcap_file: pcap文件路径
        protocol: 协议名称（如 "mqtt", "http", "ftp", "tcp", "udp"）
        start_time: 可选，开始时间（格式如 "14:00:00" 或 "2023-01-01 14:00:00"）
        end_time: 可选，结束时间（格式如 "14:10:00" 或 "2023-01-01 14:10:00"）
    
    Returns:
        指定协议的报文列表
    """
    if not validate_pcap_file(pcap_file):
        raise ToolError(f"文件不存在或无效: {pcap_file}")
    
    # 验证时间参数：要么都提供，要么都不提供
    if (start_time is None) != (end_time is None):
        raise ToolError("start_time 和 end_time 必须同时提供或同时为空")
    
    cache_key = _generate_cache_key('extract_by_protocol', pcap_file=pcap_file, 
                                    protocol=protocol, start_time=start_time, end_time=end_time)
    cached_result = global_cache.get(cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        executor = TSHARK_EXECUTOR  # 使用全局实例
        
        # 构建协议过滤器
        protocol_filter = protocol.lower()
        
        # 如果提供了时间参数，组合过滤
        if start_time and end_time:
            time_filter = f'frame.time >= "{start_time}" && frame.time <= "{end_time}"'
            combined_filter = f"({protocol_filter}) && ({time_filter})"
        else:
            combined_filter = protocol_filter
        
        result = executor.execute(pcap_file, display_filter=combined_filter)
        
        # 缓存结果
        global_cache.set(cache_key, result)
        return result
        
    except Exception as e:
        raise ToolError(f"按协议提取报文失败: {str(e)}")


async def extract_stream(pcap_file: str, src_ip: str, src_port: str, 
                        dst_ip: str, dst_port: str, protocol: str,
                        start_time: Optional[str] = None, 
                        end_time: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    提取特定网络流的全部报文
    用途: 需要深度分析某个连接的问题
    使用场景: "分析一下192.168.1.100:55021到服务器的连接" 或 "分析14:00-14:10期间的特定连接"
    
    Args:
        pcap_file: pcap文件路径
        src_ip: 源IP地址
        src_port: 源端口
        dst_ip: 目标IP地址
        dst_port: 目标端口
        protocol: 协议类型
        start_time: 可选，开始时间（格式如 "14:00:00" 或 "2023-01-01 14:00:00"）
        end_time: 可选，结束时间（格式如 "14:10:00" 或 "2023-01-01 14:10:00"）
    
    Returns:
        指定流的报文列表
    """
    if not validate_pcap_file(pcap_file):
        raise ToolError(f"文件不存在或无效: {pcap_file}")
    
    # 验证时间参数：要么都提供，要么都不提供
    if (start_time is None) != (end_time is None):
        raise ToolError("start_time 和 end_time 必须同时提供或同时为空")
    
    cache_key = _generate_cache_key('extract_stream', pcap_file=pcap_file, src_ip=src_ip,
                                    src_port=src_port, dst_ip=dst_ip, dst_port=dst_port, 
                                    protocol=protocol, start_time=start_time, end_time=end_time)
    cached_result = global_cache.get(cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        executor = TSHARK_EXECUTOR  # 使用全局实例
        
        # 构建流过滤器 - 使用tcp.stream或udp.stream等
        if protocol.lower() in ['tcp', 'udp']:
            # 尝试使用流ID（如果知道流ID的话）或地址端口对
            stream_filter = f"{protocol.lower()}.src == {src_ip} and {protocol.lower()}.srcport == {src_port} and " \
                           f"{protocol.lower()}.dst == {dst_ip} and {protocol.lower()}.dstport == {dst_port}"
        else:
            # 对于其他协议，使用地址匹配
            stream_filter = f"ip.src == {src_ip} and ip.dst == {dst_ip}"
        
        # 如果提供了时间参数，组合过滤
        if start_time and end_time:
            time_filter = f'frame.time >= "{start_time}" && frame.time <= "{end_time}"'
            combined_filter = f"({stream_filter}) && ({time_filter})"
        else:
            combined_filter = stream_filter
        
        result = executor.execute(pcap_file, display_filter=combined_filter)
        
        # 缓存结果
        global_cache.set(cache_key, result)
        return result
        
    except Exception as e:
        raise ToolError(f"提取网络流失败: {str(e)}")





async def get_statistics(pcap_file: str, metric: str = "all", 
                        start_time: Optional[str] = None, 
                        end_time: Optional[str] = None) -> Dict[str, Any]:
    """
    获取统计指标（延迟、吞吐、重传率等）
    用途: AI需要量化数据支持分析
    使用场景: "统计下MQTT消息的平均延迟" 或 "统计14:00-14:10期间的统计指标"
    
    Args:
        pcap_file: pcap文件路径
        metric: 统计指标类型
        start_time: 可选，开始时间（格式如 "14:00:00" 或 "2023-01-01 14:00:00"）
        end_time: 可选，结束时间（格式如 "14:10:00" 或 "2023-01-01 14:10:00"）
    
    Returns:
        统计指标结果
    """
    if not validate_pcap_file(pcap_file):
        raise ToolError(f"文件不存在或无效: {pcap_file}")
    
    # 验证时间参数：要么都提供，要么都不提供
    if (start_time is None) != (end_time is None):
        raise ToolError("start_time 和 end_time 必须同时提供或同时为空")
    
    cache_key = _generate_cache_key('get_statistics', pcap_file=pcap_file, 
                                    metric=metric, start_time=start_time, end_time=end_time)
    cached_result = global_cache.get(cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        import subprocess
        
        executor = TSHARK_EXECUTOR  # 使用全局实例
        stats = {}
        
        # 构建时间过滤器（如果提供了时间参数）
        time_filter_args = []
        if start_time and end_time:
            # 对于统计命令，使用 -a (autostop) 和 -Y 组合来限制时间范围
            # 注意：TShark的统计命令(-z)与显示过滤器(-Y)的组合使用有限制
            # 这里先提取时间范围内的包，再进行统计
            time_filtered_file = None
            try:
                # 创建临时文件存储时间过滤后的包
                import tempfile
                with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp_file:
                    time_filtered_file = tmp_file.name
                
                # 先提取时间范围内的包
                time_filter = f'frame.time >= "{start_time}" && frame.time <= "{end_time}"'
                export_cmd = [
                    executor.tshark_path,
                    "-r", pcap_file,
                    "-Y", time_filter,
                    "-w", time_filtered_file
                ]
                export_result = subprocess.run(export_cmd, capture_output=True, text=True, timeout=30)
                
                if export_result.returncode != 0:
                    raise ToolError(f"时间过滤失败: {export_result.stderr}")
                
                # 使用过滤后的文件进行统计
                stats_file = time_filtered_file
            finally:
                # 清理临时文件
                if time_filtered_file and os.path.exists(time_filtered_file):
                    os.unlink(time_filtered_file)
        else:
            stats_file = pcap_file
        
        if metric == "all" or metric == "tcp":
            # 获取TCP统计
            cmd = [
                executor.tshark_path,
                "-r", stats_file,
                "-q",
                "-z", "tcp,stat"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                stats['tcp_stats'] = result.stdout
        
        if metric == "all" or metric == "throughput":
            # 获取吞吐量统计
            cmd = [
                executor.tshark_path,
                "-r", stats_file,
                "-q",
                "-z", "io,stat", "1"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                stats['throughput'] = result.stdout
        
        # 提取基本统计信息
        if start_time and end_time:
            time_filter = f'frame.time >= "{start_time}" && frame.time <= "{end_time}"'
            all_packets = executor.execute(pcap_file, display_filter=time_filter)
        else:
            all_packets = executor.execute(pcap_file)
        
        stats['total_packets'] = len(all_packets)
        stats['file_size_bytes'] = Path(pcap_file).stat().st_size
        
        # 添加时间范围信息
        if start_time and end_time:
            stats['time_range'] = {
                'start': start_time,
                'end': end_time
            }
        
        # 缓存结果
        global_cache.set(cache_key, stats)
        return stats
        
    except Exception as e:
        raise ToolError(f"获取统计信息失败: {str(e)}")


# 导出工具函数
__all__ = [
    'get_pcap_overview',
    'list_conversations',
    'extract_by_time',
    'extract_by_protocol',
    'extract_stream',
    'get_statistics',
    'ToolError'
]