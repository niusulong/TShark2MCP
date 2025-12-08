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


# 全局TShark执行器实例，优先使用环境变量，然后是常见安装路径
_global_tshark_path = os.environ.get('TSHARK_PATH', 'tshark')
if _global_tshark_path == 'tshark':
    # 尝试常见的Wireshark安装路径
    common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]
    
    # 检查常见路径
    for path in common_paths:
        if os.path.exists(path):
            _global_tshark_path = path
            print(f"DEBUG: 找到TShark路径: {path}", file=sys.stderr)
            break
    
    

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
        
        # 构建流过滤器 - 使用正确的TShark字段名
        if protocol.lower() in ['tcp', 'udp']:
            # 使用正确的字段名：ip.src/ip.dst 和 tcp.srcport/tcp.dstport
            # 注意：IP地址不需要引号
            stream_filter = f'ip.src == {src_ip} and {protocol.lower()}.srcport == {src_port} and ' \
                           f'ip.dst == {dst_ip} and {protocol.lower()}.dstport == {dst_port}'
        else:
            # 对于其他协议，使用地址匹配
            # 注意：IP地址不需要引号
            stream_filter = f'ip.src == {src_ip} and ip.dst == {dst_ip}'
        
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
        metric: 统计指标类型 ("all", "latency", "throughput", "retransmission", "tcp", "packet_loss")
        start_time: 可选，开始时间（格式如 "14:00:00" 或 "2023-01-01 14:00:00"）
        end_time: 可选，结束时间（格式如 "14:10:00" 或 "2023-01-01 14:10:00"）
    
    Returns:
        统计指标结果
    """
    # 验证时间参数：要么都提供，要么都不提供
    if (start_time is None) != (end_time is None):
        raise ToolError("start_time 和 end_time 必须同时提供或同时为空")
    
    if not validate_pcap_file(pcap_file):
        raise ToolError(f"文件不存在或无效: {pcap_file}")
    
    cache_key = _generate_cache_key('get_statistics', pcap_file=pcap_file, 
                                    metric=metric, start_time=start_time, end_time=end_time)
    cached_result = global_cache.get(cache_key)
    if cached_result is not None:
        return cached_result
    
    try:
        import subprocess
        import tempfile
        import re
        
        executor = TSHARK_EXECUTOR  # 使用全局实例
        stats = {}
        
        # 构建时间过滤器
        time_filter = None
        if start_time and end_time:
            time_filter = f'frame.time >= "{start_time}" && frame.time <= "{end_time}"'
        
        # 创建临时文件用于时间过滤（如果需要）
        temp_file = None
        try:
            if time_filter:
                # 创建临时文件存储时间过滤后的包
                with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp_file:
                    temp_file = tmp_file.name
                
                # 导出时间范围内的包
                export_cmd = [
                    executor.tshark_path,
                    "-r", pcap_file,
                    "-Y", time_filter,
                    "-w", temp_file
                ]
                export_result = subprocess.run(export_cmd, capture_output=True, text=True, timeout=30)
                
                if export_result.returncode != 0:
                    raise ToolError(f"时间过滤失败: {export_result.stderr}")
                
                stats_file = temp_file
            else:
                stats_file = pcap_file
            
            # 根据metric参数执行不同的统计
            if metric == "all" or metric == "latency":
                # 延迟统计 - 使用TCP流分析
                stats['latency'] = await _calculate_latency_stats(executor, stats_file)
            
            if metric == "all" or metric == "throughput":
                # 吞吐量统计
                stats['throughput'] = await _calculate_throughput_stats(executor, stats_file)
            
            if metric == "all" or metric == "retransmission":
                # 重传统计
                stats['retransmission'] = await _calculate_retransmission_stats(executor, stats_file)
            
            if metric == "all" or metric == "tcp":
                # TCP连接统计
                stats['tcp_connections'] = await _calculate_tcp_connection_stats(executor, stats_file)
            
            if metric == "all" or metric == "packet_loss":
                # 丢包统计
                stats['packet_loss'] = await _calculate_packet_loss_stats(executor, stats_file)
            
            # 基本统计信息
            if time_filter:
                all_packets = executor.execute(pcap_file, display_filter=time_filter)
            else:
                all_packets = executor.execute(pcap_file)
            
            stats['basic'] = {
                'total_packets': len(all_packets),
                'file_size_bytes': Path(pcap_file).stat().st_size,
                'capture_duration': await _calculate_capture_duration(executor, stats_file)
            }
            
            # 添加时间范围信息
            if start_time and end_time:
                stats['time_range'] = {
                    'start': start_time,
                    'end': end_time
                }
            
        finally:
            # 清理临时文件
            if temp_file and os.path.exists(temp_file):
                os.unlink(temp_file)
        
        # 缓存结果
        global_cache.set(cache_key, stats)
        return stats
        
    except Exception as e:
        raise ToolError(f"获取统计信息失败: {str(e)}")


async def _calculate_latency_stats(executor, pcap_file) -> Dict[str, Any]:
    """计算延迟统计"""
    try:
        import subprocess
        
        latency_stats = {}
        
        # 尝试获取TCP流统计，包含RTT信息
        cmd_tcp = [
            executor.tshark_path,
            "-r", pcap_file,
            "-q",
            "-z", "conv,tcp"
        ]
        result_tcp = subprocess.run(cmd_tcp, capture_output=True, text=True, timeout=30)
        
        if result_tcp.returncode == 0:
            # 解析TCP会话统计，获取基本的TCP信息
            output = result_tcp.stdout
            lines = output.split('\n')
            
            # 查找TCP流信息 - 使用正则表达式解析
            tcp_streams = []
            import re
            
            # 正则表达式匹配TCP会话行
            # 格式如: 10.206.134.192:25520 <-> 120.86.64.161:10020 85 8326 bytes 108 6958 bytes
            stream_pattern = r'(\d+\.\d+\.\d+\.\d+:\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+:\d+)\s+(\d+)\s+(\d+)\s+bytes\s+(\d+)\s+(\d+)\s+bytes'
            
            for line in lines:
                match = re.search(stream_pattern, line)
                if match:
                    try:
                        src_packets = int(match.group(3))
                        src_bytes = int(match.group(4))
                        dst_packets = int(match.group(5))
                        dst_bytes = int(match.group(6))
                        
                        tcp_streams.append({
                            'src': match.group(1),
                            'dst': match.group(2),
                            'packets': src_packets + dst_packets,
                            'bytes': src_bytes + dst_bytes
                        })
                    except (ValueError, IndexError):
                        continue
            
            if tcp_streams:
                total_packets = sum(s['packets'] for s in tcp_streams)
                total_bytes = sum(s['bytes'] for s in tcp_streams)
                latency_stats['tcp_streams'] = {
                    'total_streams': len(tcp_streams),
                    'total_packets': total_packets,
                    'total_bytes': total_bytes,
                    'avg_packets_per_stream': total_packets / len(tcp_streams),
                    'avg_bytes_per_stream': total_bytes / len(tcp_streams),
                    'streams': tcp_streams[:5]  # 返回前5个流的详细信息
                }
            
            # 如果没有解析到数据，至少记录原始输出的一部分
            if not tcp_streams:
                latency_stats['parse_error'] = '无法解析TCP流数据'
                latency_stats['raw_output_sample'] = output[:500] + "..." if len(output) > 500 else output
        
        # 获取HTTP响应时间
        cmd_http = [
            executor.tshark_path,
            "-r", pcap_file,
            "-Y", "http.request && http.response_in",
            "-T", "fields",
            "-e", "http.time",
            "-E", "separator=,"
        ]
        result_http = subprocess.run(cmd_http, capture_output=True, text=True, timeout=30)
        
        if result_http.returncode == 0:
            http_times = []
            for line in result_http.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        http_times.append(float(line.strip()))
                    except ValueError:
                        continue
            
            if http_times:
                latency_stats['http_response'] = {
                    'average_ms': sum(http_times) / len(http_times),
                    'min_ms': min(http_times),
                    'max_ms': max(http_times),
                    'count': len(http_times)
                }
        
        return latency_stats
        
    except Exception as e:
        return {"error": f"延迟统计失败: {str(e)}"}


async def _calculate_throughput_stats(executor, pcap_file) -> Dict[str, Any]:
    """计算吞吐量统计"""
    try:
        import subprocess
        import re
        
        # 获取I/O统计 - 使用简单格式
        cmd = [
            executor.tshark_path,
            "-r", pcap_file,
            "-q",
            "-z", "io,phs"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        throughput_stats = {}
        
        if result.returncode == 0:
            output = result.stdout
            lines = output.split('\n')
            
            # 解析协议层次统计
            protocol_stats = {}
            total_frames = 0
            total_bytes = 0
            
            # 正则表达式匹配协议统计行
            # 格式如: frame frames:11221 bytes:1656881
            protocol_pattern = r'^(\s*\w+)\s+frames:(\d+)\s+bytes:(\d+)'
            
            for line in lines:
                match = re.search(protocol_pattern, line)
                if match:
                    protocol = match.group(1).strip()
                    frames = int(match.group(2))
                    bytes_data = int(match.group(3))
                    
                    protocol_stats[protocol] = {
                        'frames': frames,
                        'bytes': bytes_data
                    }
                    
                    # 累计总数
                    total_frames += frames
                    total_bytes += bytes_data
            
            # 获取捕获持续时间
            duration = 1.0  # 默认1秒
            try:
                # 尝试从文件获取实际持续时间
                cmd_duration = [
                    executor.tshark_path,
                    "-r", pcap_file,
                    "-T", "fields",
                    "-e", "frame.time_relative",
                    "-2"  # 只获取最后一个包的时间
                ]
                result_duration = subprocess.run(cmd_duration, capture_output=True, text=True, timeout=10)
                if result_duration.returncode == 0 and result_duration.stdout.strip():
                    duration = float(result_duration.stdout.strip().split('\n')[-1])
            except:
                pass
            
            if total_frames > 0 and duration > 0:
                avg_frames_per_sec = total_frames / duration
                avg_bytes_per_sec = total_bytes / duration
                
                throughput_stats = {
                    'total_frames': total_frames,
                    'total_bytes': total_bytes,
                    'capture_duration_seconds': duration,
                    'average_frames_per_second': avg_frames_per_sec,
                    'average_bytes_per_second': avg_bytes_per_sec,
                    'average_bps': avg_bytes_per_sec * 8,  # 转换为bps
                    'protocol_distribution': protocol_stats
                }
        
        return throughput_stats
        
    except Exception as e:
        return {"error": f"吞吐量统计失败: {str(e)}"}


async def _calculate_retransmission_stats(executor, pcap_file) -> Dict[str, Any]:
    """计算重传统计"""
    try:
        import subprocess
        
        # 获取TCP重传统计
        cmd = [
            executor.tshark_path,
            "-r", pcap_file,
            "-Y", "tcp.analysis.retransmission",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "ip.src",
            "-e", "tcp.srcport",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-E", "separator=,"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        retransmission_stats = {}
        
        if result.returncode == 0:
            retransmissions = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 5:
                        retransmissions.append({
                            'frame': parts[0],
                            'src_ip': parts[1],
                            'src_port': parts[2],
                            'dst_ip': parts[3],
                            'dst_port': parts[4]
                        })
            
            # 获取总TCP包数
            cmd_total = [
                executor.tshark_path,
                "-r", pcap_file,
                "-Y", "tcp",
                "-T", "fields",
                "-e", "frame.number"
            ]
            result_total = subprocess.run(cmd_total, capture_output=True, text=True, timeout=30)
            
            total_tcp_packets = 0
            if result_total.returncode == 0:
                total_tcp_packets = len([line for line in result_total.stdout.strip().split('\n') if line.strip()])
            
            if total_tcp_packets > 0:
                retransmission_rate = (len(retransmissions) / total_tcp_packets) * 100
                retransmission_stats = {
                    'retransmission_count': len(retransmissions),
                    'total_tcp_packets': total_tcp_packets,
                    'retransmission_rate_percent': round(retransmission_rate, 2),
                    'retransmissions': retransmissions[:10]  # 只返回前10个重传包的详细信息
                }
        
        return retransmission_stats
        
    except Exception as e:
        return {"error": f"重传统计失败: {str(e)}"}


async def _calculate_tcp_connection_stats(executor, pcap_file) -> Dict[str, Any]:
    """计算TCP连接统计"""
    try:
        import subprocess
        
        # 获取TCP流统计
        cmd = [
            executor.tshark_path,
            "-r", pcap_file,
            "-q",
            "-z", "conv,tcp"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        tcp_stats = {}
        
        if result.returncode == 0:
            output = result.stdout
            connections = []
            
            lines = output.split('\n')
            data_started = False
            for line in lines:
                if 'Src Address' in line and 'Port' in line:
                    data_started = True
                    continue
                
                if not data_started:
                    continue
                    
                if line and '|' in line:
                    parts = [p.strip() for p in line.split('|') if p.strip()]
                    if len(parts) >= 8:
                        try:
                            conn = {
                                'src_ip': parts[0],
                                'src_port': parts[1],
                                'dst_ip': parts[2],
                                'dst_port': parts[3],
                                'packets': int(parts[4]) + int(parts[5]),
                                'bytes': int(parts[6]) + int(parts[7]),
                                'duration': parts[8] if len(parts) > 8 else 'N/A'
                            }
                            connections.append(conn)
                        except (ValueError, IndexError):
                            continue
            
            if connections:
                total_connections = len(connections)
                total_packets = sum(conn['packets'] for conn in connections)
                total_bytes = sum(conn['bytes'] for conn in connections)
                
                tcp_stats = {
                    'total_connections': total_connections,
                    'total_packets': total_packets,
                    'total_bytes': total_bytes,
                    'average_packets_per_connection': total_packets / total_connections,
                    'average_bytes_per_connection': total_bytes / total_connections,
                    'connections': connections[:20]  # 返回前20个连接的详细信息
                }
        
        return tcp_stats
        
    except Exception as e:
        return {"error": f"TCP连接统计失败: {str(e)}"}


async def _calculate_packet_loss_stats(executor, pcap_file) -> Dict[str, Any]:
    """计算丢包统计"""
    try:
        import subprocess
        
        # 获取丢包相关事件
        cmd = [
            executor.tshark_path,
            "-r", pcap_file,
            "-Y", "tcp.analysis.duplicate_ack || tcp.analysis.fast_retransmission || tcp.analysis.out_of_order",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "_ws.col.Info",
            "-E", "separator=|"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        packet_loss_stats = {}
        
        if result.returncode == 0:
            events = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split('|')
                    if len(parts) >= 2:
                        events.append({
                            'frame': parts[0],
                            'info': parts[1]
                        })
            
            # 统计不同类型的丢包事件
            duplicate_acks = [e for e in events if 'Duplicate ACK' in e['info']]
            fast_retrans = [e for e in events if 'Fast retransmission' in e['info']]
            out_of_order = [e for e in events if 'Out-of-Order' in e['info']]
            
            packet_loss_stats = {
                'total_loss_events': len(events),
                'duplicate_acks': len(duplicate_acks),
                'fast_retransmissions': len(fast_retrans),
                'out_of_order_packets': len(out_of_order),
                'events': events[:10]  # 返回前10个事件的详细信息
            }
        
        return packet_loss_stats
        
    except Exception as e:
        return {"error": f"丢包统计失败: {str(e)}"}


async def _calculate_capture_duration(executor, pcap_file) -> Dict[str, Any]:
    """计算捕获持续时间"""
    try:
        import subprocess
        
        # 获取第一个和最后一个包的时间
        cmd = [
            executor.tshark_path,
            "-r", pcap_file,
            "-T", "fields",
            "-e", "frame.time_relative",
            "-E", "separator=,"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            times = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        times.append(float(line.strip()))
                    except ValueError:
                        continue
            
            if times:
                return {
                    'start_time_seconds': 0.0,
                    'end_time_seconds': max(times),
                    'duration_seconds': max(times),
                    'total_frames': len(times)
                }
        
        return {"error": "无法计算捕获持续时间"}
        
    except Exception as e:
        return {"error": f"持续时间计算失败: {str(e)}"}


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