"""
ThreatSync主程序入口
"""
import sys
from pathlib import Path

# 确保正确的模块路径
if __name__ == "__main__":
    # 当作为模块运行时，调整模块路径
    current_dir = Path(__file__).parent
    parent_dir = current_dir.parent
    if str(parent_dir) not in sys.path:
        sys.path.insert(0, str(parent_dir))

from ThreatSync.modules.threat_engine import ThreatSyncEngine
from ThreatSync.utils.logger import logger
import argparse

 
def main():
    """主函数"""
   
    
    parser = argparse.ArgumentParser(description='ThreatSync - 威胁情报采集工具')
    parser.add_argument('--config', '-c', help='配置文件路径')
    parser.add_argument('--mode', '-m', choices=['once', 'schedule'], 
                       default='once', help='运行模式')
    parser.add_argument('--sources', '-s', nargs='+', 
                       choices=['nvd', 'github', 'osv', 'cnvd'],
                       help='指定数据源')
    parser.add_argument('--github-method', choices=['rest', 'graphql', 'database'], 
                       default='rest', help='GitHub数据采集方式')
    parser.add_argument('--all', action='store_true', 
                       help='采集所有数据（不限时间范围）')
    parser.add_argument('--export', '-e', help='导出数据到指定路径')
    parser.add_argument('--stats', action='store_true', help='显示统计信息')
    parser.add_argument('--info', action='store_true', help='显示数据存储信息')
    parser.add_argument('--cleanup', action='store_true', help='清理过期文件')
    parser.add_argument('--days', '-d', type=int, default=7, help='回溯天数')
    parser.add_argument('--cve', help='查看特定CVE信息')
    parser.add_argument('--list-cves', help='列出CVE文件 (格式: 2025 或 2025/08)')
    
    args = parser.parse_args()
    
    try:
        # 初始化引擎
        engine = ThreatSyncEngine(args.config)
        
        if args.cleanup:
            # 清理过期文件
            engine.cleanup_old_files()
            
        elif args.info:
            # 显示数据存储信息
            info = engine.get_data_info()
            print("\n=== ThreatSync 数据存储信息 ===")
            print("\n结构化数据存储路径:")
            for source, path in info['storage_paths']['structured_data'].items():
                print(f"  {source.upper()}: {path}")
            print("\n非结构化数据存储路径:")
            for source, path in info['storage_paths']['unstructured_data'].items():
                print(f"  {source.upper()}: {path}")
            print(f"\n采集结果路径: {info['storage_paths']['collection_results']}")
            
            file_org = info.get('file_organization', {})
            print(f"\n文件组织方式: {file_org.get('group_by', 'daily')}")
            print(f"文件命名格式: {file_org.get('filename_format', '{source}_{date}_{timestamp}.json')}")
            
            retention = info.get('retention_policy', {})
            print(f"\n数据保留策略:")
            print(f"  保留天数: {retention.get('retention_days', 365)}")
            print(f"  清理间隔: {retention.get('cleanup_interval', 24)} 小时")
            
        elif args.stats:
            # 显示统计信息
            stats = engine.get_statistics()
            print("\n=== ThreatSync 统计信息 ===")
            print(f"总漏洞数: {stats.get('total_vulnerabilities', 0)}")
            print(f"总文件数: {stats.get('file_count', 0)}")
            print("\n按数据源统计:")
            for source, count in stats.get('by_source', {}).items():
                print(f"  {source}: {count}")
            print("\n按严重性统计:")
            for severity, count in stats.get('by_severity', {}).items():
                if count > 0:  # 只显示有数据的严重性等级
                    print(f"  {severity}: {count}")
            
            last_update = stats.get('last_update')
            if last_update:
                print(f"\n最后更新: {last_update}")
            
        elif args.export:
            # 导出数据
            source_filter = args.sources[0] if args.sources and len(args.sources) == 1 else None
            success = engine.export_data(args.export, source_filter)
            if success:
                print(f"数据导出成功: {args.export}")
            else:
                print(f"数据导出失败: {args.export}")
                
        elif args.mode == 'once':
            # 单次采集
            kwargs = {
                'sources': args.sources, 
                'days_back': args.days if not args.all else None,
                'github_method': args.github_method,
                'collect_all': args.all
            }
            engine.run_full_collection(**kwargs)
            
        elif args.mode == 'schedule':
            # 定时采集
            engine.run_scheduler()
            
    except KeyboardInterrupt:
        logger.info("用户中断程序执行")
        print("\n程序已停止")
    except Exception as e:
        # 使用增强的错误日志功能
        logger.error(
            "程序执行失败",
            exception=e,
            extra={
                'args': vars(args) if 'args' in locals() else {},
                'execution_context': 'main'
            }
        )
        print(f"错误: {e}")
        print("详细错误信息已记录到日志文件中")
        return 1
    
    return 0


if __name__ == "__main__":
    main()
