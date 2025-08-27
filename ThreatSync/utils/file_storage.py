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
            data: 数据列表（原始API数据）
            metadata: 元数据信息（包含采集信息）
            
        Returns:
            保存的目录路径
        """
        source = source.lower()
        
        # 对于NVD数据，使用增量更新的CVE单文件保存
        if source == 'nvd':
            return self._save_nvd_data_incremental(data, metadata)
        # 对于GitHub数据，使用增量更新的GHSA单文件保存
        elif source == 'github':
            return self._save_github_data_incremental(data, metadata)
        else:
            # 其他数据源保持原有的批量保存方式
            return self._save_bulk_data(source, data, metadata)
    
    def _save_nvd_data_incremental(self, data: List[Dict[str, Any]], 
                                  metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        增量保存NVD数据，按CVE ID分别保存，支持原始数据存储和增量更新
        
        Args:
            data: NVD数据列表（解析后的VulnerabilityData对象转换的dict）
            metadata: 元数据信息
            
        Returns:
            保存的目录路径
        """
        structured_data = self.storage_config.get('structured_data', {})
        base_path = Path(structured_data.get('nvd', 'data/structured/nvd'))
        
        saved_files = []
        updated_files = []
        skipped_files = []
        current_time = datetime.now()
        
        for item in data:
            try:
                # 提取CVE ID和原始数据
                cve_id = item.get('id') or item.get('cve_id')
                raw_data = item.get('raw_data')  # 原始API数据
                
                if not cve_id:
                    logger.warning("跳过没有CVE ID的数据项")
                    continue
                
                if not raw_data:
                    logger.warning(f"CVE {cve_id} 没有原始数据，使用处理后的数据")
                    raw_data = item
                
                # 获取发布日期，用于确定年月目录
                published_date = self._extract_published_date(item, current_time)
                
                # 构建目录路径: nvd/2025/08/
                year = published_date.strftime('%Y')
                month = published_date.strftime('%m')
                cve_dir = base_path / year / month
                cve_dir.mkdir(parents=True, exist_ok=True)
                
                # 构建文件路径: CVE-2025-12345.json
                safe_cve_id = cve_id.replace('/', '_').replace('\\', '_')
                cve_file_path = cve_dir / f"{safe_cve_id}.json"
                
                # 检查文件是否已存在（增量更新）
                file_exists = cve_file_path.exists()
                should_update = True
                
                if file_exists:
                    # 检查是否需要更新
                    try:
                        with open(cve_file_path, 'r', encoding='utf-8') as f:
                            existing_data = json.load(f)
                        
                        # 比较数据内容是否相同
                        if existing_data == raw_data:
                            should_update = False
                            skipped_files.append(cve_id)
                            
                            # 数据相同，跳过更新
                            skipped_files.append(cve_id)
                            continue
                    except Exception as e:
                        logger.warning(f"读取现有CVE文件失败 {cve_id}: {e}，将重新保存")
                
                # 直接保存原始数据，不再保存metadata
                cve_data = raw_data
                
                # 保存CVE文件
                with open(cve_file_path, 'w', encoding='utf-8') as f:
                    json.dump(cve_data, f, ensure_ascii=False, indent=2, default=str)
                
                if file_exists:
                    updated_files.append(cve_id)
                else:
                    saved_files.append(cve_id)
                
            except Exception as e:
                logger.error(f"保存CVE数据失败 {cve_id}: {e}")
                continue
        
        logger.info(f"NVD增量更新完成 - 新增:{len(saved_files)}, 更新:{len(updated_files)}, 跳过:{len(skipped_files)}")
        
        return str(base_path)
    
    def save_github_data_incremental(self, ghsa_id: str, data: Dict[str, Any], 
                                    published_date: datetime = None) -> bool:
        """
        增量保存单个GitHub GHSA数据
        
        Args:
            ghsa_id: GHSA ID
            data: 原始GitHub Advisory数据
            published_date: 发布日期
            
        Returns:
            是否保存成功
        """
        try:
            structured_data = self.storage_config.get('structured_data', {})
            base_path = Path(structured_data.get('github', 'data/structured/github'))
            
            # 使用发布日期或当前时间确定目录
            if published_date is None:
                published_date = datetime.now()
            
            # 构建目录路径: github/2025/08/
            year = published_date.strftime('%Y')
            month = published_date.strftime('%m')
            ghsa_dir = base_path / year / month
            ghsa_dir.mkdir(parents=True, exist_ok=True)
            
            # 构建文件路径: GHSA-xxxx-xxxx-xxxx.json
            safe_ghsa_id = ghsa_id.replace('/', '_').replace('\\', '_')
            ghsa_file_path = ghsa_dir / f"{safe_ghsa_id}.json"
            
            # 检查文件是否已存在（避免重复保存）
            if ghsa_file_path.exists():
                return False  # 文件已存在，跳过，返回False表示未新增保存
            
            # 保存原始数据
            with open(ghsa_file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            
            return True  # 新保存成功
            
            return True
            
        except Exception as e:
            logger.error(f"保存GitHub数据失败: {ghsa_id}", exception=e)
            return False
    
    def _save_github_data_incremental(self, data: List[Dict[str, Any]], 
                                     metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        增量保存GitHub数据，按GHSA ID分别保存，支持原始数据存储和增量更新
        
        Args:
            data: GitHub数据列表（解析后的VulnerabilityData对象转换的dict）
            metadata: 元数据信息
            
        Returns:
            保存的目录路径
        """
        structured_data = self.storage_config.get('structured_data', {})
        base_path = Path(structured_data.get('github', 'data/structured/github'))
        
        saved_files = []
        updated_files = []
        skipped_files = []
        current_time = datetime.now()
        
        for item in data:
            try:
                # 提取GHSA ID和原始数据
                ghsa_id = item.get('id') or item.get('ghsa_id')
                raw_data = item.get('raw_data')  # 原始API数据
                
                if not ghsa_id:
                    logger.warning("跳过没有GHSA ID的数据项")
                    continue
                
                if not raw_data:
                    logger.warning(f"GHSA {ghsa_id} 没有原始数据，使用处理后的数据")
                    raw_data = item
                
                # 获取发布日期，用于确定年月目录
                published_date = self._extract_published_date(item, current_time)
                
                # 构建目录路径: github/2025/08/
                year = published_date.strftime('%Y')
                month = published_date.strftime('%m')
                ghsa_dir = base_path / year / month
                ghsa_dir.mkdir(parents=True, exist_ok=True)
                
                # 构建文件路径: GHSA-xxxx-xxxx-xxxx.json
                safe_ghsa_id = ghsa_id.replace('/', '_').replace('\\', '_')
                ghsa_file_path = ghsa_dir / f"{safe_ghsa_id}.json"
                
                # 检查文件是否已存在（增量更新）
                file_exists = ghsa_file_path.exists()
                should_update = True
                
                if file_exists:
                    # 检查是否需要更新
                    try:
                        with open(ghsa_file_path, 'r', encoding='utf-8') as f:
                            existing_data = json.load(f)
                        
                        # 比较数据内容是否相同
                        if existing_data == raw_data:
                            should_update = False
                            skipped_files.append(ghsa_id)
                            continue
                    except Exception as e:
                        logger.warning(f"读取现有GHSA文件失败 {ghsa_id}: {e}，将重新保存")
                
                # 直接保存原始数据，不再保存metadata
                ghsa_data = raw_data
                
                # 保存GHSA文件
                with open(ghsa_file_path, 'w', encoding='utf-8') as f:
                    json.dump(ghsa_data, f, ensure_ascii=False, indent=2, default=str)
                
                if file_exists:
                    updated_files.append(ghsa_id)
                else:
                    saved_files.append(ghsa_id)
                
            except Exception as e:
                logger.error(f"保存GHSA数据失败 {ghsa_id}: {e}")
                continue
        
        logger.info(f"GitHub增量更新完成 - 新增:{len(saved_files)}, 更新:{len(updated_files)}, 跳过:{len(skipped_files)}")
        
        return str(base_path)
    
    def _extract_published_date(self, item: Dict[str, Any], default_time: datetime) -> datetime:
        """提取发布日期"""
        published_date = item.get('published_date')
        if not published_date:
            return default_time
            
        if isinstance(published_date, str):
            try:
                return datetime.fromisoformat(published_date.replace('Z', '+00:00'))
            except:
                return default_time
        elif isinstance(published_date, datetime):
            return published_date
        else:
            return default_time
    
    def get_existing_cve_ids(self, source: str = 'nvd') -> set:
        """
        获取已存在的CVE ID列表
        
        Args:
            source: 数据源名称
            
        Returns:
            CVE ID集合
        """
        if source.lower() not in ['nvd', 'github']:
            return set()
        
        structured_data = self.storage_config.get('structured_data', {})
        base_path = Path(structured_data.get(source.lower(), f'data/structured/{source.lower()}'))
        
        ids = set()
        file_pattern = 'CVE-*.json' if source.lower() == 'nvd' else 'GHSA-*.json'
        
        # 遍历年/月目录
        for year_dir in base_path.glob('[0-9][0-9][0-9][0-9]'):
            if year_dir.is_dir():
                for month_dir in year_dir.glob('[0-1][0-9]'):
                    if month_dir.is_dir():
                        for file in month_dir.glob(file_pattern):
                            file_id = file.stem
                            ids.add(file_id)
        
        return ids
    
    def get_cve_file_path(self, cve_id: str, source: str = 'nvd') -> Optional[Path]:
        """
        根据CVE ID或GHSA ID查找对应的文件路径
        
        Args:
            cve_id: CVE ID或GHSA ID
            source: 数据源名称
            
        Returns:
            文件路径或None
        """
        if source.lower() not in ['nvd', 'github']:
            return None
        
        structured_data = self.storage_config.get('structured_data', {})
        base_path = Path(structured_data.get(source.lower(), f'data/structured/{source.lower()}'))
        
        safe_id = cve_id.replace('/', '_').replace('\\', '_')
        
        # 遍历所有年/月目录查找文件
        for file in base_path.rglob(f'{safe_id}.json'):
            if file.is_file():
                return file
        
        return None
    
    def load_cve_data(self, cve_id: str, source: str = 'nvd') -> Optional[Dict[str, Any]]:
        """
        加载特定CVE或GHSA的数据
        
        Args:
            cve_id: CVE ID或GHSA ID
            source: 数据源名称
            
        Returns:
            CVE/GHSA数据或None
        """
        file_path = self.get_cve_file_path(cve_id, source)
        if not file_path:
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载{source.upper()}数据失败 {cve_id}: {e}")
            return None
    
    def get_collection_metadata(self, collection_id: str = None, source: str = 'nvd') -> Dict[str, Any]:
        """
        获取采集元数据
        
        Args:
            collection_id: 采集ID，如果为None则获取最新的
            source: 数据源名称
            
        Returns:
            采集元数据
        """
        if source.lower() != 'nvd':
            return {}
        
        structured_data = self.storage_config.get('structured_data', {})
        base_path = Path(structured_data.get('nvd', 'data/structured/nvd'))
        collections_path = base_path / 'collections'
        
        if not collections_path.exists():
            return {}
        
        if collection_id:
            metadata_file = collections_path / collection_id / 'metadata.json'
        else:
            # 获取最新的采集
            collection_dirs = [d for d in collections_path.iterdir() if d.is_dir()]
            if not collection_dirs:
                return {}
            
            latest_collection = max(collection_dirs, key=lambda x: x.name)
            metadata_file = latest_collection / 'metadata.json'
        
        if not metadata_file.exists():
            return {}
        
        try:
            with open(metadata_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载采集元数据失败: {e}")
            return {}
    
    def list_collections(self, source: str = 'nvd', limit: int = 10) -> List[Dict[str, Any]]:
        """
        列出采集历史
        
        Args:
            source: 数据源名称
            limit: 返回数量限制
            
        Returns:
            采集历史列表
        """
        if source.lower() != 'nvd':
            return []
        
        structured_data = self.storage_config.get('structured_data', {})
        base_path = Path(structured_data.get('nvd', 'data/structured/nvd'))
        collections_path = base_path / 'collections'
        
        if not collections_path.exists():
            return []
        
        collections = []
        collection_dirs = sorted([d for d in collections_path.iterdir() if d.is_dir()], 
                               key=lambda x: x.name, reverse=True)
        
        for collection_dir in collection_dirs[:limit]:
            metadata_file = collection_dir / 'metadata.json'
            if metadata_file.exists():
                try:
                    with open(metadata_file, 'r', encoding='utf-8') as f:
                        metadata = json.load(f)
                        collections.append(metadata)
                except Exception as e:
                    logger.error(f"读取采集元数据失败 {collection_dir.name}: {e}")
        
        return collections
    
    def _save_bulk_data(self, source: str, data: List[Dict[str, Any]], 
                       metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        批量保存数据（非NVD数据源使用）
        
        Args:
            source: 数据源名称
            data: 数据列表
            metadata: 元数据信息
            
        Returns:
            保存的文件路径
        """
        # 获取存储路径
        structured_data = self.storage_config.get('structured_data', {})
        source_path = Path(structured_data.get(source, f'data/structured/{source}'))
        source_path.mkdir(parents=True, exist_ok=True)
        
        # 生成文件名
        file_org = self.storage_config.get('file_organization', {})
        filename_format = file_org.get('filename_format', '{source}_{date}_{timestamp}.json')
        
        current_time = datetime.now()
        filename = filename_format.format(
            source=source.upper(),
            date=current_time.strftime('%Y%m%d'),
            timestamp=current_time.strftime('%H%M%S')
        )
        
        file_path = source_path / filename
        
        # 准备保存的数据
        save_data = {
            'metadata': {
                'source': source,
                'data_type': 'structured',
                'collected_at': current_time.isoformat(),
                'total_items': len(data),
                'version': '1.0'
            },
            'data': data
        }
        
        # 合并额外的元数据
        if metadata:
            save_data['metadata'].update(metadata)
        
        # 保存文件
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(save_data, f, ensure_ascii=False, indent=2, default=str)
        
        logger.info(f"已保存{len(data)}条{source.upper()}数据到文件: {file_path}")
        return str(file_path)
        """
        批量保存数据（非NVD数据源使用）
        
        Args:
            source: 数据源名称
            data: 数据列表
            metadata: 元数据信息
            
        Returns:
            保存的文件路径
        """
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
    
    def get_cve_file_path(self, cve_id: str, published_date: Optional[datetime] = None) -> Path:
        """
        获取CVE文件的路径
        
        Args:
            cve_id: CVE ID
            published_date: 发布日期（用于确定目录）
            
        Returns:
            CVE文件路径
        """
        structured_data = self.storage_config.get('structured_data', {})
        base_path = Path(structured_data.get('nvd', 'data/structured/nvd'))
        
        if published_date:
            year = published_date.strftime('%Y')
            month = published_date.strftime('%m')
        else:
            # 如果没有发布日期，使用当前日期
            now = datetime.now()
            year = now.strftime('%Y')
            month = now.strftime('%m')
        
        safe_cve_id = cve_id.replace('/', '_').replace('\\', '_')
        return base_path / year / month / f"{safe_cve_id}.json"
    
    def load_cve_data(self, cve_id: str, published_date: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
        """
        加载单个CVE数据
        
        Args:
            cve_id: CVE ID
            published_date: 发布日期
            
        Returns:
            CVE数据或None
        """
        file_path = self.get_cve_file_path(cve_id, published_date)
        
        if not file_path.exists():
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载CVE数据失败 {cve_id}: {e}")
            return None
    
    def cve_exists(self, cve_id: str, published_date: Optional[datetime] = None) -> bool:
        """
        检查CVE是否已存在
        
        Args:
            cve_id: CVE ID
            published_date: 发布日期
            
        Returns:
            是否存在
        """
        file_path = self.get_cve_file_path(cve_id, published_date)
        return file_path.exists()
    
    def list_cve_files(self, year: Optional[str] = None, month: Optional[str] = None) -> List[Path]:
        """
        列出CVE文件
        
        Args:
            year: 年份过滤 (例: "2025")
            month: 月份过滤 (例: "08")
            
        Returns:
            CVE文件路径列表
        """
        structured_data = self.storage_config.get('structured_data', {})
        base_path = Path(structured_data.get('nvd', 'data/structured/nvd'))
        
        cve_files = []
        
        if year and month:
            # 指定年月
            target_dir = base_path / year / month
            if target_dir.exists():
                cve_files.extend(target_dir.glob("CVE-*.json"))
        elif year:
            # 指定年份的所有月份
            year_dir = base_path / year
            if year_dir.exists():
                for month_dir in year_dir.iterdir():
                    if month_dir.is_dir():
                        cve_files.extend(month_dir.glob("CVE-*.json"))
        else:
            # 所有CVE文件
            cve_files.extend(base_path.glob("**/CVE-*.json"))
        
        return sorted(cve_files)
    
    def get_nvd_statistics(self) -> Dict[str, Any]:
        """
        获取NVD数据统计信息
        
        Returns:
            统计信息字典
        """
        structured_data = self.storage_config.get('structured_data', {})
        base_path = Path(structured_data.get('nvd', 'data/structured/nvd'))
        
        stats = {
            'total_cves': 0,
            'by_year': {},
            'by_month': {},
            'latest_cve': None,
            'oldest_cve': None
        }
        
        if not base_path.exists():
            return stats
        
        all_cve_files = self.list_cve_files()
        stats['total_cves'] = len(all_cve_files)
        
        # 统计按年月分布
        for cve_file in all_cve_files:
            try:
                # 从路径中提取年月信息
                parts = cve_file.parts
                if len(parts) >= 3:
                    year = parts[-3]
                    month = parts[-2]
                    
                    if year not in stats['by_year']:
                        stats['by_year'][year] = 0
                    stats['by_year'][year] += 1
                    
                    year_month = f"{year}-{month}"
                    if year_month not in stats['by_month']:
                        stats['by_month'][year_month] = 0
                    stats['by_month'][year_month] += 1
                    
                    # 更新最新和最旧的CVE
                    file_time = cve_file.stat().st_mtime
                    if stats['latest_cve'] is None or file_time > stats['latest_cve']['time']:
                        stats['latest_cve'] = {
                            'file': str(cve_file),
                            'time': file_time,
                            'cve_id': cve_file.stem
                        }
                    
                    if stats['oldest_cve'] is None or file_time < stats['oldest_cve']['time']:
                        stats['oldest_cve'] = {
                            'file': str(cve_file),
                            'time': file_time,
                            'cve_id': cve_file.stem
                        }
                        
            except Exception as e:
                logger.warning(f"处理CVE文件统计失败 {cve_file}: {e}")
                continue
        
        return stats
    
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
