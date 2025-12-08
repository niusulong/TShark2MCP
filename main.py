#!/usr/bin/env python3
"""
TShark2MCP服务器主入口
"""

import asyncio
import sys
import os
import logging
from pathlib import Path

# 添加src目录到路径
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))

from mcp_server.server import create_server


def main():
    """
    主函数，启动MCP服务器
    """
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger = logging.getLogger(__name__)

    try:
        # 检查TSHARK_PATH环境变量
        tshark_path = os.environ.get('TSHARK_PATH')
        if tshark_path:
            logger.info(f"使用TSHARK_PATH环境变量: {tshark_path}")
        else:
            logger.info("未设置TSHARK_PATH环境变量，将尝试从系统PATH查找tshark")

        # 创建服务器实例
        server = create_server()

        # 启动服务器
        logger.info("启动TShark2MCP服务器...")
        asyncio.run(server.run_forever())

    except KeyboardInterrupt:
        logger.info("接收到中断信号，正在关闭服务器...")
    except Exception as e:
        logger.error(f"服务器运行出错: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()