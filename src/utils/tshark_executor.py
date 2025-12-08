import json
import subprocess
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path


class TSharkExecutor:
    """
    TShark执行器，封装TShark命令行工具调用
    """

    def __init__(self, tshark_path: str = "tshark"):
        """
        初始化TShark执行器

        Args:
            tshark_path: TShark可执行文件路径
        """
        self.tshark_path = tshark_path
        self.logger = logging.getLogger(__name__)
    
    def _build_command(self, pcap_file: str, display_filter: Optional[str] = None, 
                      time_range: Optional[str] = None, fields: Optional[List[str]] = None,
                      packet_count: Optional[int] = None) -> List[str]:
        """
        构建TShark命令

        Args:
            pcap_file: pcap文件路径
            display_filter: 显示过滤器
            time_range: 时间范围过滤
            fields: 要提取的字段列表
            packet_count: 限制报文数量

        Returns:
            命令参数列表
        """
        command = [self.tshark_path, "-r", pcap_file, "-T", "json"]
        
        # 添加显示过滤器
        if display_filter:
            command.extend(["-Y", display_filter])
        
        # 添加报文数量限制（防止大文件导致内存溢出）
        if packet_count:
            command.extend(["-c", str(packet_count)])
        
        # 添加字段提取（如果指定）
        if fields:
            for field in fields:
                command.extend(["-e", field])
        
        return command
    
    def execute(self, pcap_file: str, display_filter: Optional[str] = None,
                time_range: Optional[str] = None, fields: Optional[List[str]] = None,
                packet_count: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        执行TShark命令并解析结果

        Args:
            pcap_file: pcap文件路径
            display_filter: 显示过滤器
            time_range: 时间范围过滤
            fields: 要提取的字段列表
            packet_count: 限制报文数量

        Returns:
            解析后的报文数据列表
        """
        command = self._build_command(pcap_file, display_filter, time_range, fields, packet_count)

        try:
            self.logger.debug(f"执行命令: {' '.join(command)}")

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,  # 30秒超时
                encoding='utf-8'  # 确保使用UTF-8编码
            )

            if result.returncode != 0:
                raise RuntimeError(f"TShark执行失败: {result.stderr}")

            # 解析JSON输出，处理可能为None的情况
            if not result.stdout or not result.stdout.strip():
                return []

            # TShark输出可能包含多个JSON数组，需要特殊处理
            # 实际输出通常是单个JSON数组
            try:
                packets = json.loads(result.stdout)
                if isinstance(packets, list):
                    return packets
                else:
                    return [packets] if packets else []
            except json.JSONDecodeError:
                # 如果直接解析失败，尝试处理可能的多行JSON
                lines = result.stdout.strip().split('\n')
                packets = []
                for line in lines:
                    line = line.strip()
                    if line:
                        try:
                            packet = json.loads(line)
                            packets.append(packet)
                        except json.JSONDecodeError:
                            continue
                return packets

        except subprocess.TimeoutExpired:
            raise RuntimeError("TShark执行超时")
        except Exception as e:
            self.logger.error(f"TShark执行错误: {str(e)}")
            raise


def validate_pcap_file(pcap_file: str) -> bool:
    """
    验证pcap文件是否存在且有效

    Args:
        pcap_file: pcap文件路径

    Returns:
        文件是否有效
    """
    path = Path(pcap_file)
    return path.exists() and path.is_file()