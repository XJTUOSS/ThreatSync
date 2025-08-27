#!/usr/bin/env python3
"""
ThreatSync 简单启动脚本
直接调用主程序，避免模块导入问题
"""
import sys
import os
from pathlib import Path

# 添加项目根目录到Python路径
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# 确保工作目录正确
os.chdir(current_dir)

if __name__ == "__main__":
    # 导入并运行主程序
    from ThreatSync.main import main
    sys.exit(main())
