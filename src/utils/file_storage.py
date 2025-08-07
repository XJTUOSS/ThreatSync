"""
文件存储工具 - 替代数据库存储，直接保存JSON文件
"""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from ..utils import logger


class FileStorage:
    """文件存储管理器"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.storage_config = config_manager.get_storage_config()
        self.data_dir = Path(self.storage_config.get('data_dir', 'data'))
        
        # 创建存储目录
        self._ensure_directories()
    
    def _ensure_directories(self):
        """确保所有必要的目录存在"""
        # 结构化数据目录
        structured_data = self.storage_config.get('structured_data', {})
        for source, path in structured_data.items():
            Path(path).mkdir(parents=True, exist_ok=True)
        
        # 非结构化数据目录
        unstructured_data = self.storage_config.get('unstructured_data', {})
        for source, path in unstructured_data.items():
            Path(path).mkdir(parents=True, exist_ok=True)
        
        # 采集结果目录
        collection_results_path = self.storage_config.get('collection_results', 'data/collection_results')
        Path(collection_results_path).mkdir(parents=True, exist_ok=True)
    
    def save_structured_data(self, source: str, data: List[Dict[str, Any]], 
                           metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        保存结构化数据
        
        Args:
            source: 数据源名称 (nvd, github, osv)
            data: 数据列表
            metadata: 元数据信息
            
        Returns:
            保存的文件路径
        """
        source = source.lower()
        structured_data = self.storage_config.get('structured_data', {})
        base_path = structured_data.get(source, f'data/structured/{source}')
        
        # 生成文件名
        filename = self._generate_filename(source, 'structured')
        file_path = Path(base_path) / filename
        
        # 确保目录存在
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 准备保存的数据
        save_data = {
            'metadata': {
                'source': source,
                'data_type': 'structured',
                'collected_at': datetime.now().isoformat(),
                'count': len(data),
                'version': '1.0'
            },
            'data': data
        }
        
        # 合并额外的元数据
        if metadata:
            save_data['metadata'].update(metadata)
        
        # 保存文件
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, ensure_ascii=False, indent=2, default=str)
            
            logger.info(f"已保存{len(data)}条{source.upper()}数据到文件: {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"保存{source}数据失败: {e}")
            raise
    
    def save_unstructured_data(self, source: str, data: Any, 
                             filename: Optional[str] = None) -> str:
        """
        保存非结构化数据
        
        Args:
            source: 数据源名称 (cnvd)
            data: 原始数据
            filename: 指定文件名（可选）
            
        Returns:
            保存的文件路径
        """
        source = source.lower()
        unstructured_data = self.storage_config.get('unstructured_data', {})
        base_path = unstructured_data.get(source, f'data/unstructured/{source}')
        
        # 生成文件名
        if not filename:
            filename = self._generate_filename(source, 'unstructured')
        
        file_path = Path(base_path) / filename
        
        # 确保目录存在
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 保存文件
        try:
            if isinstance(data, (dict, list)):
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(str(data))
            
            logger.info(f"已保存{source.upper()}非结构化数据到文件: {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"保存{source}非结构化数据失败: {e}")
            raise
    
    def save_collection_result(self, source: str, result_data: Dict[str, Any]) -> str:
        """
        保存采集结果摘要
        
        Args:
            source: 数据源名称
            result_data: 采集结果数据
            
        Returns:
            保存的文件路径
        """
        collection_results_path = self.storage_config.get('collection_results', 'data/collection_results')
        
        # 生成文件名
        filename = self._generate_filename(source, 'result')
        file_path = Path(collection_results_path) / filename
        
        # 确保目录存在
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 添加元数据
        save_data = {
            'metadata': {
                'source': source,
                'type': 'collection_result',
                'timestamp': datetime.now().isoformat(),
                'version': '1.0'
            },
            'result': result_data
        }
        
        # 保存文件
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, ensure_ascii=False, indent=2, default=str)
            
            logger.info(f"已保存{source.upper()}采集结果到文件: {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"保存{source}采集结果失败: {e}")
            raise
    
    def _generate_filename(self, source: str, data_type: str) -> str:
        """生成文件名"""
        file_org = self.storage_config.get('file_organization', {})
        filename_format = file_org.get('filename_format', '{source}_{date}_{timestamp}.json')
        group_by = file_org.get('group_by', 'daily')
        
        now = datetime.now()
        
        # 根据分组方式生成日期部分
        if group_by == 'daily':
            date_part = now.strftime('%Y%m%d')
        elif group_by == 'monthly':
            date_part = now.strftime('%Y%m')
        elif group_by == 'yearly':
            date_part = now.strftime('%Y')
        else:
            date_part = now.strftime('%Y%m%d')
        
        timestamp_part = now.strftime('%H%M%S')
        
        filename = filename_format.format(
            source=source.upper(),
            date=date_part,
            timestamp=timestamp_part,
            type=data_type
        )
        
        return filename
    
    def load_structured_data(self, source: str, date_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        加载结构化数据
        
        Args:
            source: 数据源名称
            date_filter: 日期过滤器 (YYYYMMDD)
            
        Returns:
            数据列表
        """
        source = source.lower()
        structured_data = self.storage_config.get('structured_data', {})
        base_path = Path(structured_data.get(source, f'data/structured/{source}'))
        
        if not base_path.exists():
            return []
        
        data_list = []
        
        for file_path in base_path.glob('*.json'):
            # 应用日期过滤器
            if date_filter and date_filter not in file_path.name:
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_data = json.load(f)
                    
                if 'data' in file_data:
                    data_list.extend(file_data['data'])
                    
            except Exception as e:
                logger.error(f"读取文件{file_path}失败: {e}")
        
        return data_list
    
    def get_latest_collection_time(self, source: str) -> Optional[datetime]:
        """获取最新采集时间"""
        collection_results_path = Path(self.storage_config.get('collection_results', 'data/collection_results'))
        
        if not collection_results_path.exists():
            return None
        
        latest_time = None
        
        for file_path in collection_results_path.glob(f'{source.upper()}_*.json'):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_data = json.load(f)
                    
                timestamp_str = file_data.get('metadata', {}).get('timestamp')
                if timestamp_str:
                    file_time = datetime.fromisoformat(timestamp_str)
                    if latest_time is None or file_time > latest_time:
                        latest_time = file_time
                        
            except Exception as e:
                logger.error(f"读取采集结果文件{file_path}失败: {e}")
        
        return latest_time
    
    def cleanup_old_files(self):
        """清理过期文件"""
        retention_config = self.storage_config.get('retention', {})
        retention_days = retention_config.get('retention_days', 365)
        
        if retention_days <= 0:  # 0表示永久保留
            return
        
        from datetime import timedelta
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        # 清理所有数据目录
        all_paths = []
        
        # 添加结构化数据路径
        structured_data = self.storage_config.get('structured_data', {})
        all_paths.extend(structured_data.values())
        
        # 添加非结构化数据路径
        unstructured_data = self.storage_config.get('unstructured_data', {})
        all_paths.extend(unstructured_data.values())
        
        # 添加采集结果路径
        collection_results = self.storage_config.get('collection_results', 'data/collection_results')
        all_paths.append(collection_results)
        
        deleted_count = 0
        
        for path_str in all_paths:
            path = Path(path_str)
            if not path.exists():
                continue
            
            for file_path in path.glob('*.json'):
                try:
                    file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_mtime < cutoff_date:
                        file_path.unlink()
                        deleted_count += 1
                        logger.debug(f"删除过期文件: {file_path}")
                        
                except Exception as e:
                    logger.error(f"删除文件{file_path}失败: {e}")
        
        if deleted_count > 0:
            logger.info(f"清理完成，删除了{deleted_count}个过期文件")
