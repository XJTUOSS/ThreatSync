#!/usr/bin/env python3
"""
ThreatSync 新版本使用示例
演示更新后的主程序功能
"""
import sys
import subprocess
from pathlib import Path

def run_command(cmd, description):
    """运行命令并显示结果"""
    print(f"\n{'='*60}")
    print(f"示例: {description}")
    print(f"命令: {cmd}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8')
        if result.stdout:
            print("输出:")
            print(result.stdout)
        if result.stderr:
            print("错误:")
            print(result.stderr)
        if result.returncode != 0:
            print(f"退出码: {result.returncode}")
    except Exception as e:
        print(f"执行失败: {e}")

def main():
    """主函数"""
    print("ThreatSync 新版本功能演示")
    print("基于文件存储的威胁情报采集系统")
    
    # 切换到项目目录
    project_root = Path(__file__).parent
    original_cwd = Path.cwd()
    
    try:
        import os
        os.chdir(project_root)
        
        # 1. 显示帮助信息
        run_command("python run.py --help", "显示命令行帮助")
        
        # 2. 显示数据存储配置信息
        run_command("python run.py --info", "显示数据存储配置信息")
        
        # 3. 显示当前统计信息
        run_command("python run.py --stats", "显示当前数据统计")
        
        # 4. 执行NVD数据采集（1天）
        run_command("python run.py --sources nvd --days 1", "采集NVD最近1天数据")
        
        # 5. 再次显示统计信息
        run_command("python run.py --stats", "采集后的数据统计")
        
        # 6. 导出数据
        run_command("python run.py --export exports/demo_export.json --sources nvd", "导出NVD数据到文件")
        
        # 7. 清理过期文件
        run_command("python run.py --cleanup", "清理过期文件")
        
        print(f"\n{'='*60}")
        print("演示完成！新版本主要特性:")
        print("✅ 移除数据库依赖，改为文件存储")
        print("✅ 遵循NVD官方最佳实践")
        print("✅ 统一配置管理")
        print("✅ 丰富的命令行功能")
        print("✅ 自动文件组织和清理")
        print("✅ 完整的数据导出功能")
        print(f"{'='*60}")
        
    finally:
        os.chdir(original_cwd)

if __name__ == "__main__":
    main()
