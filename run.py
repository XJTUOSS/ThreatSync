#!/usr/bin/env python3
"""
ThreatSync 启动脚本
运行方式: python run.py [参数]
"""
import sys
import os
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

# 导入并运行主程序
from src.main import main

if __name__ == "__main__":
    main()
