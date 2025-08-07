"""
主程序入口
"""
import schedule
import time
from pathlib import Path

try:
    # 相对导入（作为包的一部分时）
    from .utils import ConfigManager, logger
    from .utils.file_storage import FileStorage
    from .collectors import (
        NVDCollector, GitHubCollector, OSVCollector, CNVDCollector
    )
except ImportError:
    # 绝对导入（直接运行时）
    import sys
    from pathlib import Path
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    from src.utils import ConfigManager, logger
    from src.utils.file_storage import FileStorage
    from src.collectors import (
        NVDCollector, GitHubCollector, OSVCollector, CNVDCollector
    )


class ThreatSyncEngine:
    """威胁同步引擎主类"""
    
    def __init__(self, config_path: str = None):
        self.config_manager = ConfigManager(config_path)
        self.file_storage = FileStorage(self.config_manager)
        self.collectors = {}
        self._init_collectors()
        self._setup_logging()
    
    def _init_collectors(self):
        """初始化采集器"""
        try:
            self.collectors = {
                'nvd': NVDCollector(self.config_manager),
                'github': GitHubCollector(self.config_manager),
                'osv': OSVCollector(self.config_manager),
                'cnvd': CNVDCollector(self.config_manager)
            }
            logger.info("采集器初始化完成")
        except Exception as e:
            logger.error(f"采集器初始化失败: {str(e)}")
    
    def _setup_logging(self):
        """设置日志"""
        log_config = self.config_manager.get_logging_config()
        log_file = log_config.get('file', 'logs/threatsync.log')
        
        # 创建日志目录
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info("日志系统初始化完成")
    
    def collect_structured_data(self, sources: list = None, **kwargs):
        """采集结构化数据"""
        if sources is None:
            sources = ['nvd', 'github', 'osv']
        
        logger.info(f"开始采集结构化数据，数据源: {sources}")
        
        for source in sources:
            if source in self.collectors:
                try:
                    collector = self.collectors[source]
                    result = collector.run_collection(**kwargs)
                    
                    logger.info(f"{source.upper()} 数据采集完成，成功采集{result.successful}条")
                    
                except Exception as e:
                    logger.error(f"采集{source}数据失败: {str(e)}")
            else:
                logger.warning(f"未找到{source}采集器")
    
    def collect_unstructured_data(self, sources: list = None, **kwargs):
        """采集非结构化数据"""
        if sources is None:
            sources = ['cnvd']
        
        logger.info(f"开始采集非结构化数据，数据源: {sources}")
        
        for source in sources:
            if source in self.collectors:
                try:
                    collector = self.collectors[source]
                    result = collector.run_collection(**kwargs)
                    
                    logger.info(f"{source.upper()} 数据采集完成，成功采集{result.successful}条")
                    
                except Exception as e:
                    logger.error(f"采集{source}数据失败: {str(e)}")
            else:
                logger.warning(f"未找到{source}采集器")
    
    def run_full_collection(self, **kwargs):
        """运行完整采集"""
        logger.info("开始运行完整数据采集")
        
        # 获取指定的数据源列表
        sources = kwargs.pop('sources', None) 
        
        if sources:
            # 分离结构化和非结构化数据源
            structured_sources = [s for s in sources if s in ['nvd', 'github', 'osv']]
            unstructured_sources = [s for s in sources if s in ['cnvd']]
            
            if structured_sources:
                self.collect_structured_data(sources=structured_sources, **kwargs)
            if unstructured_sources:
                self.collect_unstructured_data(sources=unstructured_sources, **kwargs)
        else:
            # 采集所有数据源
            self.collect_structured_data(**kwargs)
            self.collect_unstructured_data(**kwargs)
        
        # 显示统计信息
        self.show_collection_summary()
    
    def show_collection_summary(self):
        """显示采集统计摘要"""
        try:
            storage_config = self.config_manager.get_storage_config()
            
            # 统计各数据源的文件数量
            structured_data = storage_config.get('structured_data', {})
            summary = {}
            
            for source, path in structured_data.items():
                source_path = Path(path)
                if source_path.exists():
                    json_files = list(source_path.glob('*.json'))
                    summary[source.upper()] = len(json_files)
                else:
                    summary[source.upper()] = 0
            
            # 统计非结构化数据
            unstructured_data = storage_config.get('unstructured_data', {})
            for source, path in unstructured_data.items():
                source_path = Path(path)
                if source_path.exists():
                    # 统计所有子目录中的文件
                    file_count = sum(1 for _ in source_path.rglob('*') if _.is_file())
                    summary[source.upper()] = file_count
                else:
                    summary[source.upper()] = 0
            
            # 显示统计信息
            logger.info("=== 数据采集统计 ===")
            for source, count in summary.items():
                logger.info(f"{source}: {count} 个文件")
            
            # 显示最新采集时间
            collection_results_path = Path(storage_config.get('collection_results', 'data/collection_results'))
            if collection_results_path.exists():
                latest_file = max(collection_results_path.glob('*.json'), 
                                key=lambda x: x.stat().st_mtime, default=None)
                if latest_file:
                    import json
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        timestamp = data.get('metadata', {}).get('timestamp', 'Unknown')
                        logger.info(f"最新采集时间: {timestamp}")
            
        except Exception as e:
            logger.error(f"生成统计摘要失败: {e}")
    
    def setup_scheduler(self):
        """设置定时任务"""
        schedule_config = self.config_manager.get_schedule_config()
        
        structured_interval = schedule_config.get('structured_interval', 6)
        unstructured_interval = schedule_config.get('unstructured_interval', 12)
        
        # 结构化数据定时采集
        schedule.every(structured_interval).hours.do(
            self.collect_structured_data
        )
        
        # 非结构化数据定时采集
        schedule.every(unstructured_interval).hours.do(
            self.collect_unstructured_data
        )
        
        logger.info(f"定时任务设置完成，结构化数据每{structured_interval}小时采集一次，"
                   f"非结构化数据每{unstructured_interval}小时采集一次")
    
    def run_scheduler(self):
        """运行定时任务"""
        logger.info("启动定时任务调度器")
        self.setup_scheduler()
        
        while True:
            schedule.run_pending()
            time.sleep(60)  # 每分钟检查一次
    
    def export_data(self, output_path: str, source: str = None):
        """导出数据"""
        logger.info(f"开始导出数据到: {output_path}")
        
        try:
            import json
            from datetime import datetime
            
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            storage_config = self.config_manager.get_storage_config()
            structured_data = storage_config.get('structured_data', {})
            
            export_data = {
                'metadata': {
                    'export_time': datetime.now().isoformat(),
                    'source_filter': source,
                    'version': '1.0'
                },
                'data': {}
            }
            
            # 导出指定数据源或所有数据源
            sources_to_export = [source.lower()] if source else structured_data.keys()
            
            for src in sources_to_export:
                if src in structured_data:
                    src_path = Path(structured_data[src])
                    src_data = []
                    
                    if src_path.exists():
                        for json_file in src_path.glob('*.json'):
                            try:
                                with open(json_file, 'r', encoding='utf-8') as f:
                                    file_data = json.load(f)
                                    if 'data' in file_data:
                                        src_data.extend(file_data['data'])
                            except Exception as e:
                                logger.warning(f"读取文件{json_file}失败: {e}")
                    
                    export_data['data'][src.upper()] = src_data
            
            # 保存导出文件
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2, default=str)
            
            total_records = sum(len(data) for data in export_data['data'].values())
            logger.info(f"数据导出成功: {output_path}, 共导出{total_records}条记录")
            return True
            
        except Exception as e:
            logger.error(f"数据导出失败: {e}")
            return False
    
    def get_statistics(self):
        """获取统计信息"""
        try:
            import json
            from datetime import datetime
            
            storage_config = self.config_manager.get_storage_config()
            structured_data = storage_config.get('structured_data', {})
            
            stats = {
                'total_vulnerabilities': 0,
                'by_source': {},
                'by_severity': {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0,
                    'UNKNOWN': 0
                },
                'last_update': None,
                'file_count': 0
            }
            
            # 统计结构化数据
            for source, path in structured_data.items():
                source_path = Path(path)
                source_count = 0
                
                if source_path.exists():
                    for json_file in source_path.glob('*.json'):
                        try:
                            with open(json_file, 'r', encoding='utf-8') as f:
                                file_data = json.load(f)
                                if 'data' in file_data:
                                    vulnerabilities = file_data['data']
                                    source_count += len(vulnerabilities)
                                    
                                    # 统计严重性
                                    for vuln in vulnerabilities:
                                        severity = vuln.get('severity', 'UNKNOWN')
                                        if severity in stats['by_severity']:
                                            stats['by_severity'][severity] += 1
                                        else:
                                            stats['by_severity']['UNKNOWN'] += 1
                                
                                # 更新最后更新时间
                                metadata = file_data.get('metadata', {})
                                collected_at = metadata.get('collected_at')
                                if collected_at:
                                    if not stats['last_update'] or collected_at > stats['last_update']:
                                        stats['last_update'] = collected_at
                                        
                        except Exception as e:
                            logger.warning(f"读取统计文件{json_file}失败: {e}")
                    
                    stats['file_count'] += len(list(source_path.glob('*.json')))
                
                stats['by_source'][source.upper()] = source_count
                stats['total_vulnerabilities'] += source_count
            
            return stats
            
        except Exception as e:
            logger.error(f"获取统计信息失败: {e}")
            return {
                'total_vulnerabilities': 0,
                'by_source': {},
                'by_severity': {},
                'last_update': None,
                'file_count': 0
            }
    
    def cleanup_old_files(self):
        """清理过期文件"""
        logger.info("开始清理过期文件...")
        try:
            self.file_storage.cleanup_old_files()
            logger.info("过期文件清理完成")
        except Exception as e:
            logger.error(f"清理过期文件失败: {e}")
    
    def get_data_info(self):
        """获取数据信息"""
        try:
            storage_config = self.config_manager.get_storage_config()
            info = {
                'storage_paths': {
                    'structured_data': storage_config.get('structured_data', {}),
                    'unstructured_data': storage_config.get('unstructured_data', {}),
                    'collection_results': storage_config.get('collection_results', '')
                },
                'file_organization': storage_config.get('file_organization', {}),
                'retention_policy': storage_config.get('retention', {})
            }
            return info
        except Exception as e:
            logger.error(f"获取数据信息失败: {e}")
            return {}


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ThreatSync - 威胁情报采集工具')
    parser.add_argument('--config', '-c', help='配置文件路径')
    parser.add_argument('--mode', '-m', choices=['once', 'schedule'], 
                       default='once', help='运行模式')
    parser.add_argument('--sources', '-s', nargs='+', 
                       choices=['nvd', 'github', 'osv', 'cnvd'],
                       help='指定数据源')
    parser.add_argument('--export', '-e', help='导出数据到指定路径')
    parser.add_argument('--stats', action='store_true', help='显示统计信息')
    parser.add_argument('--info', action='store_true', help='显示数据存储信息')
    parser.add_argument('--cleanup', action='store_true', help='清理过期文件')
    parser.add_argument('--days', '-d', type=int, default=7, help='回溯天数')
    
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
            engine.run_full_collection(sources=args.sources, days_back=args.days)
            
        elif args.mode == 'schedule':
            # 定时采集
            engine.run_scheduler()
            
    except KeyboardInterrupt:
        logger.info("用户中断程序执行")
        print("\n程序已停止")
    except Exception as e:
        logger.error(f"程序执行失败: {e}")
        print(f"错误: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    main()
