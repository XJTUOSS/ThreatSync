#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ThreatSync 威胁情报采集工具启动脚本
方便调用项目的Python启动器
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path


class ThreatSyncRunner:
    """ThreatSync 启动器"""
    
    def __init__(self):
        self.script_dir = Path(__file__).parent.absolute()
        self.python_cmd = self._get_python_command()
        
    def _get_python_command(self):
        """获取Python命令"""
        # 检查虚拟环境
        venv_paths = [
            self.script_dir / "venv" / "Scripts" / "python.exe",  # Windows venv
            self.script_dir / "venv" / "bin" / "python",          # Linux/macOS venv
            self.script_dir / ".venv" / "Scripts" / "python.exe", # Windows .venv
            self.script_dir / ".venv" / "bin" / "python",         # Linux/macOS .venv
        ]
        
        for venv_python in venv_paths:
            if venv_python.exists():
                return str(venv_python)
        
        # 使用系统Python
        return sys.executable
    
    def show_banner(self):
        """显示横幅"""
        print("\033[36m" + "=" * 50)
        print("    ThreatSync 威胁情报采集工具")
        print("=" * 50 + "\033[0m")
        print()
    
    def check_dependencies(self):
        """检查依赖"""
        print("\033[33m检查Python环境和依赖...\033[0m")
        
        # 检查Python版本
        try:
            result = subprocess.run([self.python_cmd, "--version"], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print(f"\033[32m✓ Python: {result.stdout.strip()}\033[0m")
            else:
                raise Exception("Python版本检查失败")
        except Exception as e:
            print(f"\033[31m✗ 错误: {e}\033[0m")
            return False
        
        # 检查关键依赖
        try:
            result = subprocess.run([
                self.python_cmd, "-c", 
                "import requests, yaml, pandas; print('依赖检查通过')"
            ], capture_output=True, text=True, cwd=self.script_dir)
            
            if result.returncode == 0:
                print(f"\033[32m✓ {result.stdout.strip()}\033[0m")
            else:
                print("\033[33m⚠ 依赖未完全安装，正在安装...\033[0m")
                self._install_dependencies()
        except Exception as e:
            print(f"\033[31m✗ 依赖检查失败: {e}\033[0m")
            return False
        
        print()
        return True
    
    def _install_dependencies(self):
        """安装依赖"""
        requirements_file = self.script_dir / "requirements.txt"
        if not requirements_file.exists():
            print("\033[31m✗ 未找到requirements.txt文件\033[0m")
            return False
        
        try:
            result = subprocess.run([
                self.python_cmd, "-m", "pip", "install", "-r", str(requirements_file)
            ], cwd=self.script_dir)
            
            if result.returncode == 0:
                print("\033[32m✓ 依赖安装完成\033[0m")
                return True
            else:
                print("\033[31m✗ 依赖安装失败\033[0m")
                return False
        except Exception as e:
            print(f"\033[31m✗ 安装过程出错: {e}\033[0m")
            return False
    
    def show_interactive_menu(self):
        """显示交互式菜单"""
        print("\033[36m交互式启动模式\033[0m")
        print("\033[36m" + "=" * 16 + "\033[0m")
        print()
        print("请选择运行模式:")
        print("1. 单次采集 (默认)")
        print("2. 定时调度")
        print("3. 显示统计信息")
        print("4. 显示存储信息")
        print("5. 清理过期文件")
        print("6. 导出数据")
        print("7. 帮助信息")
        print("0. 退出")
        print()
        
        while True:
            try:
                choice = input("请输入选项 (0-7): ").strip()
                if choice in ['0', '1', '2', '3', '4', '5', '6', '7']:
                    return choice
                else:
                    print("\033[31m无效选项，请重新输入\033[0m")
            except KeyboardInterrupt:
                print("\n\033[33m用户取消操作\033[0m")
                return '0'
    
    def handle_interactive_choice(self, choice):
        """处理交互式选择"""
        if choice == '0':
            print("退出程序")
            return
        elif choice == '1':
            self._handle_single_collection()
        elif choice == '2':
            self._handle_schedule_mode()
        elif choice == '3':
            self._run_main(["--stats"])
        elif choice == '4':
            self._run_main(["--info"])
        elif choice == '5':
            self._handle_cleanup()
        elif choice == '6':
            self._handle_export()
        elif choice == '7':
            self._show_help()
    
    def _handle_single_collection(self):
        """处理单次采集"""
        print()
        print("\033[33m可选数据源: nvd, github, osv, cnvd\033[0m")
        sources_input = input("请输入数据源 (逗号分隔，留空则采集所有): ").strip()
        days_input = input("请输入回溯天数 (默认7天): ").strip()
        
        args = ["--mode", "once"]
        
        if days_input:
            try:
                days = int(days_input)
                args.extend(["--days", str(days)])
            except ValueError:
                print("\033[33m⚠ 无效的天数，使用默认值7天\033[0m")
                args.extend(["--days", "7"])
        else:
            args.extend(["--days", "7"])
        
        if sources_input:
            sources = [s.strip() for s in sources_input.split(',') if s.strip()]
            valid_sources = ['nvd', 'github', 'osv', 'cnvd']
            filtered_sources = [s for s in sources if s in valid_sources]
            if filtered_sources:
                args.extend(["--sources"] + filtered_sources)
                
                # OSV数据源说明
                if 'osv' in filtered_sources:
                    print("\033[32m✓ OSV将自动下载ZIP包并解压到相应目录\033[0m")
            else:
                print("\033[33m⚠ 无效的数据源，将采集所有数据源\033[0m")
        
        self._run_main(args)
    
    def _handle_schedule_mode(self):
        """处理定时调度模式"""
        print("\033[32m启动定时调度模式...\033[0m")
        self._run_main(["--mode", "schedule"])
    
    def _handle_cleanup(self):
        """处理清理操作"""
        print("\033[33m清理过期文件...\033[0m")
        self._run_main(["--cleanup"])
    
    def _handle_export(self):
        """处理数据导出"""
        print()
        export_path = input("请输入导出路径: ").strip()
        if not export_path:
            print("\033[31m✗ 导出路径不能为空\033[0m")
            return
        
        export_source = input("请输入数据源 (可选: nvd, github, osv, cnvd): ").strip()
        
        args = ["--export", export_path]
        if export_source and export_source in ['nvd', 'github', 'osv', 'cnvd']:
            args.extend(["--sources", export_source])
        
        self._run_main(args)
    
    def _show_help(self):
        """显示帮助信息"""
        help_text = """
\033[36mThreatSync 威胁情报采集工具使用说明\033[0m
\033[36m===================================\033[0m

\033[33m使用方法:\033[0m
  python run.py [选项]

\033[33m基本选项:\033[0m
  -h, --help         显示此帮助信息
  -i, --interactive  交互式启动模式

\033[33m功能选项:\033[0m
  -c, --config       指定配置文件路径
  -m, --mode         运行模式 (once/schedule，默认: once)
  -s, --sources      指定数据源 (nvd github osv cnvd)
  -e, --export       导出数据到指定路径
  --stats            显示统计信息
  --info             显示数据存储信息
  --cleanup          清理过期文件
  -d, --days         回溯天数 (默认: 7)

\033[33m示例:\033[0m
  python run.py                                    # 交互式启动
  python run.py -m once -s nvd github              # 采集指定数据源
  python run.py -m once -s osv                     # 采集OSV本地数据
  python run.py --stats                            # 显示统计信息
  python run.py -m schedule                        # 启动定时调度
  python run.py -e output.json -s nvd              # 导出NVD数据
  python run.py --cleanup                          # 清理过期文件

\033[33mOSV数据源说明:\033[0m
  OSV数据源支持自动下载ZIP包并解压到指定目录
  数据存储路径: data/structured/osv/zip/{ecosystem}/
  可指定生态系统，如不指定则下载所有可用生态系统

\033[33m直接传递参数给main.py:\033[0m
  python run.py -- --custom-arg value              # 传递自定义参数
"""
        print(help_text)
    
    def _run_main(self, args):
        """运行主程序"""
        try:
            # 方法1：直接导入并调用main函数
            import sys
            old_argv = sys.argv[:]
            try:
                # 设置sys.argv以便argparse能正确解析
                sys.argv = ['main.py'] + args
                
                # 添加项目根目录到Python路径
                if str(self.script_dir) not in sys.path:
                    sys.path.insert(0, str(self.script_dir))
                
                # 导入并运行main函数
                from ThreatSync.main import main
                result = main()
                return result == 0
                
            finally:
                # 恢复原始sys.argv
                sys.argv = old_argv
                
        except KeyboardInterrupt:
            print("\n\033[33m用户中断程序执行\033[0m")
            return False
        except ImportError as e:
            print(f"\033[31m✗ 导入失败: {e}\033[0m")
            print("尝试使用subprocess方式运行...")
            return self._run_main_subprocess(args)
        except Exception as e:
            print(f"\033[31m✗ 执行失败: {e}\033[0m")
            return False
    
    def _run_main_subprocess(self, args):
        """使用subprocess运行主程序"""
        try:
            # 构建完整的Python路径
            main_file = self.script_dir / "ThreatSync" / "main.py"
            if not main_file.exists():
                print(f"\033[31m✗ 主程序文件不存在: {main_file}\033[0m")
                return False
            
            cmd = [self.python_cmd, str(main_file)] + args
            print(f"\033[36m执行命令: python {main_file.name} {' '.join(args)}\033[0m")
            print()
            
            # 设置环境变量
            env = os.environ.copy()
            env['PYTHONPATH'] = str(self.script_dir)
            
            result = subprocess.run(cmd, cwd=self.script_dir, env=env)
            return result.returncode == 0
        except Exception as e:
            print(f"\033[31m✗ subprocess执行失败: {e}\033[0m")
            return False
    
    def parse_and_run(self, args=None):
        """解析参数并运行"""
        if args is None:
            args = sys.argv[1:]
        
        parser = argparse.ArgumentParser(
            description='ThreatSync 威胁情报采集工具启动器',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
示例:
  python run.py                                    # 交互式启动
  python run.py -m once -s nvd github              # 采集指定数据源
  python run.py --stats                            # 显示统计信息
  python run.py -m schedule                        # 启动定时调度
  python run.py -e output.json -s nvd              # 导出NVD数据
"""
        )
        
        parser.add_argument('-i', '--interactive', action='store_true',
                          help='交互式启动模式')
        parser.add_argument('-c', '--config', 
                          help='指定配置文件路径')
        parser.add_argument('-m', '--mode', choices=['once', 'schedule'],
                          help='运行模式 (once/schedule)')
        parser.add_argument('-s', '--sources', nargs='+',
                          choices=['nvd', 'github', 'osv', 'cnvd'],
                          help='指定数据源')
        parser.add_argument('-e', '--export',
                          help='导出数据到指定路径')
        parser.add_argument('--stats', action='store_true',
                          help='显示统计信息')
        parser.add_argument('--info', action='store_true',
                          help='显示数据存储信息')
        parser.add_argument('--cleanup', action='store_true',
                          help='清理过期文件')
        parser.add_argument('-d', '--days', type=int, default=7,
                          help='回溯天数 (默认: 7)')
        
        # 解析已知参数，剩余参数传递给main.py
        parsed_args, remaining_args = parser.parse_known_args(args)
        
        # 检查环境
        if not self.check_dependencies():
            print("\033[31m环境检查失败，程序退出\033[0m")
            return 1
        
        # 交互式模式或无参数时启动交互式
        if parsed_args.interactive or (not any([
            parsed_args.config, parsed_args.mode, parsed_args.sources,
            parsed_args.export, parsed_args.stats, parsed_args.info,
            parsed_args.cleanup
        ]) and not remaining_args):
            choice = self.show_interactive_menu()
            self.handle_interactive_choice(choice)
            return 0
        
        # 构建传递给main.py的参数
        main_args = []
        
        if parsed_args.config:
            main_args.extend(['--config', parsed_args.config])
        if parsed_args.mode:
            main_args.extend(['--mode', parsed_args.mode])
        if parsed_args.sources:
            main_args.extend(['--sources'] + parsed_args.sources)
        if parsed_args.export:
            main_args.extend(['--export', parsed_args.export])
        if parsed_args.stats:
            main_args.append('--stats')
        if parsed_args.info:
            main_args.append('--info')
        if parsed_args.cleanup:
            main_args.append('--cleanup')
        if parsed_args.days != 7:
            main_args.extend(['--days', str(parsed_args.days)])
        
        # 添加剩余参数
        main_args.extend(remaining_args)
        
        # 如果没有指定功能参数，默认执行单次采集
        if not any([parsed_args.stats, parsed_args.info, parsed_args.cleanup, 
                   parsed_args.export]) and '--mode' not in main_args:
            main_args.extend(['--mode', 'once'])
        
        # 运行主程序
        success = self._run_main(main_args)
        return 0 if success else 1


def main():
    """主函数"""
    try:
        runner = ThreatSyncRunner()
        runner.show_banner()
        
        return runner.parse_and_run()
        
    except KeyboardInterrupt:
        print("\n\033[33m程序被用户中断\033[0m")
        return 130
    except Exception as e:
        print(f"\033[31m程序执行出错: {e}\033[0m")
        return 1
    finally:
        print("\n\033[37m程序执行完成\033[0m")


if __name__ == "__main__":
    sys.exit(main())
