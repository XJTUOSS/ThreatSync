"""
数据存储管理器
"""
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from .models.vulnerability import VulnerabilityData, CollectionResult
from .utils import logger


class DatabaseManager:
    """文件存储管理器"""
    
    def __init__(self, base_path: str = "data"):
        self.base_path = Path(base_path)
        self.structured_path = self.base_path / "structured"
        self.unstructured_path = self.base_path / "unstructured"
        self.collection_results_path = self.base_path / "collection_results"
        self._init_storage()
    
    def _init_storage(self):
        """初始化存储目录"""
        # 创建目录结构
        self.structured_path.mkdir(parents=True, exist_ok=True)
        self.unstructured_path.mkdir(parents=True, exist_ok=True)
        self.collection_results_path.mkdir(parents=True, exist_ok=True)
        
        # 为每个数据源创建子目录
        for source in ['nvd', 'github', 'osv']:
            (self.structured_path / source).mkdir(exist_ok=True)
        
        for source in ['cnvd']:
            (self.unstructured_path / source).mkdir(exist_ok=True)
        
        logger.info(f"存储目录初始化完成: {self.base_path}")
    
    def _get_storage_path(self, vulnerability: VulnerabilityData) -> Path:
        """根据数据源获取存储路径"""
        source = vulnerability.source.value
        
        # 结构化数据源
        if source in ['nvd', 'github', 'osv']:
            base_dir = self.structured_path / source
        # 非结构化数据源
        elif source in ['cnvd']:
            base_dir = self.unstructured_path / source
        else:
            base_dir = self.structured_path / 'other'
            base_dir.mkdir(exist_ok=True)
        
        # 按日期分组存储
        date_str = datetime.now().strftime("%Y-%m-%d")
        date_dir = base_dir / date_str
        date_dir.mkdir(exist_ok=True)
        
        return date_dir
    
    def save_vulnerability(self, vulnerability: VulnerabilityData) -> bool:
        """保存单个漏洞数据"""
        try:
            storage_path = self._get_storage_path(vulnerability)
            
            # 使用漏洞ID作为文件名
            filename = f"{vulnerability.id}.json"
            file_path = storage_path / filename
            
            # 转换为字典并保存
            data = vulnerability.dict()
            data['saved_time'] = datetime.now().isoformat()
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            logger.debug(f"漏洞数据保存成功: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"保存漏洞数据失败: {str(e)}")
            return False
    
    def save_vulnerabilities(self, vulnerabilities: List[VulnerabilityData]) -> int:
        """批量保存漏洞数据"""
        saved_count = 0
        for vulnerability in vulnerabilities:
            if self.save_vulnerability(vulnerability):
                saved_count += 1
        
        logger.info(f"批量保存完成，成功保存 {saved_count}/{len(vulnerabilities)} 条漏洞数据")
        return saved_count
    
    def save_collection_result(self, result: CollectionResult) -> bool:
        """保存采集结果"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{result.source}_{timestamp}.json"
            file_path = self.collection_results_path / filename
            
            data = result.dict()
            data['saved_time'] = datetime.now().isoformat()
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"采集结果保存成功: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"保存采集结果失败: {str(e)}")
            return False
    
    def get_vulnerabilities(self, source: str = None, limit: int = None) -> List[Dict[str, Any]]:
        """获取漏洞数据"""
        vulnerabilities = []
        
        try:
            # 确定搜索路径
            if source:
                if source in ['nvd', 'github', 'osv']:
                    search_paths = [self.structured_path / source]
                elif source in ['cnvd']:
                    search_paths = [self.unstructured_path / source]
                else:
                    search_paths = []
            else:
                # 搜索所有路径
                search_paths = []
                for source_dir in self.structured_path.iterdir():
                    if source_dir.is_dir():
                        search_paths.append(source_dir)
                for source_dir in self.unstructured_path.iterdir():
                    if source_dir.is_dir():
                        search_paths.append(source_dir)
            
            # 遍历搜索路径
            for source_path in search_paths:
                for date_dir in source_path.iterdir():
                    if date_dir.is_dir():
                        for json_file in date_dir.glob("*.json"):
                            try:
                                with open(json_file, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    vulnerabilities.append(data)
                                    
                                    if limit and len(vulnerabilities) >= limit:
                                        return vulnerabilities
                                        
                            except Exception as e:
                                logger.warning(f"读取文件失败 {json_file}: {str(e)}")
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"获取漏洞数据失败: {str(e)}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            'total_vulnerabilities': 0,
            'by_source': {},
            'by_severity': {},
            'last_update': None,
            'structured_count': 0,
            'unstructured_count': 0
        }
        
        try:
            latest_time = None
            
            # 统计结构化数据
            for source_dir in self.structured_path.iterdir():
                if source_dir.is_dir():
                    source_name = source_dir.name
                    source_count = 0
                    
                    for date_dir in source_dir.iterdir():
                        if date_dir.is_dir():
                            json_files = list(date_dir.glob("*.json"))
                            source_count += len(json_files)
                            
                            # 更新最后修改时间
                            for json_file in json_files:
                                mtime = datetime.fromtimestamp(json_file.stat().st_mtime)
                                if latest_time is None or mtime > latest_time:
                                    latest_time = mtime
                    
                    stats['by_source'][source_name] = source_count
                    stats['structured_count'] += source_count
            
            # 统计非结构化数据
            for source_dir in self.unstructured_path.iterdir():
                if source_dir.is_dir():
                    source_name = source_dir.name
                    source_count = 0
                    
                    for date_dir in source_dir.iterdir():
                        if date_dir.is_dir():
                            json_files = list(date_dir.glob("*.json"))
                            source_count += len(json_files)
                            
                            # 更新最后修改时间
                            for json_file in json_files:
                                mtime = datetime.fromtimestamp(json_file.stat().st_mtime)
                                if latest_time is None or mtime > latest_time:
                                    latest_time = mtime
                    
                    stats['by_source'][source_name] = source_count
                    stats['unstructured_count'] += source_count
            
            # 总计
            stats['total_vulnerabilities'] = stats['structured_count'] + stats['unstructured_count']
            
            if latest_time:
                stats['last_update'] = latest_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # 简单的严重性统计（需要读取文件内容）
            severity_count = {'高': 0, '中': 0, '低': 0, '未知': 0}
            
            # 随机采样一些文件来统计严重性
            sample_vulnerabilities = self.get_vulnerabilities(limit=100)
            for vuln in sample_vulnerabilities:
                severity = vuln.get('severity', '未知')
                if severity in severity_count:
                    severity_count[severity] += 1
                else:
                    severity_count['未知'] += 1
            
            stats['by_severity'] = severity_count
            
        except Exception as e:
            logger.error(f"获取统计信息失败: {str(e)}")
        
        return stats
    
    def export_to_json(self, output_path: str, source: str = None) -> bool:
        """导出数据到JSON文件"""
        try:
            vulnerabilities = self.get_vulnerabilities(source)
            
            export_data = {
                'export_time': datetime.now().isoformat(),
                'source_filter': source,
                'total_count': len(vulnerabilities),
                'vulnerabilities': vulnerabilities
            }
            
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"数据导出成功: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"数据导出失败: {str(e)}")
            return False
