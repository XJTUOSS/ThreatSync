"""
OSV 漏洞收集器
简单的下载解压方式：下载ZIP包，解压到相应文件夹，不进行JSON解析
"""

import logging
import os
import requests
import zipfile
from pathlib import Path
from typing import List

from .base_collector import BaseCollector
from ..models.vulnerability import VulnerabilityData, DataSource
from ..utils import logger


class OSVCollector(BaseCollector):
    """OSV数据采集器 - 简单的ZIP下载解压方式"""
    
    def _get_source(self) -> DataSource:
        return DataSource.OSV
    
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.config_manager = config_manager
        
        # 获取项目根目录
        self.project_root = self._get_project_root()
        
        # OSV数据存储路径
        self.osv_dir = self.project_root / "data" / "structured" / "osv" / "zip"
        self.temp_dir = self.project_root / "temp_osv_download"
        
        # 创建目录
        self.osv_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
    def _get_project_root(self) -> Path:
        """获取项目根目录"""
        current_file = Path(__file__).resolve()
        current_dir = current_file.parent
        while current_dir.parent != current_dir:
            if (current_dir / "README.md").exists():
                return current_dir
            current_dir = current_dir.parent
        return current_file.parent.parent.parent
    
    def collect(self, ecosystems: List[str] = None, **kwargs) -> List[VulnerabilityData]:
        """
        收集OSV数据 - 仅下载和解压，不解析JSON文件
        
        Args:
            ecosystems: 要下载的生态系统列表，如果为None则下载所有
            
        Returns:
            空列表（因为不进行解析，直接返回空列表）
        """
        logger.info("开始采集 OSV 数据")
        
        try:
            # 如果没有指定生态系统，先获取完整列表
            if ecosystems is None:
                ecosystems = self._get_available_ecosystems()
            
            logger.info(f"准备下载的生态系统: {ecosystems}")
            
            total_files = 0
            
            for ecosystem in ecosystems:
                logger.info(f"下载并解压 {ecosystem} 生态系统")
                file_count = self._download_and_extract_ecosystem(ecosystem)
                total_files += file_count
                logger.info(f"{ecosystem} 生态系统处理完成，包含 {file_count} 个JSON文件")
            
            logger.info(f"OSV数据下载完成，共获得{total_files}个JSON文件（未解析）")
            logger.info("OSV数据已保存到本地，可通过文件系统直接访问")
            return []  # 不解析，返回空列表
            
        except Exception as e:
            logger.error(f"OSV数据下载失败: {e}")
            return []
    
    def _get_available_ecosystems(self) -> List[str]:
        """获取可用的生态系统列表"""
        try:
            logger.info("获取OSV生态系统列表")
            url = "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            ecosystems = [line.strip() for line in response.text.splitlines() if line.strip()]
            logger.info(f"获取到 {len(ecosystems)} 个生态系统")
            return ecosystems
            
        except Exception as e:
            logger.error(f"获取生态系统列表失败: {e}")
            # 返回一些常见的生态系统作为备选
            return ["npm", "PyPI", "Maven", "Go", "crates.io", "NuGet"]
    
    def _download_and_extract_ecosystem(self, ecosystem: str) -> int:
        """
        下载并解压单个生态系统的数据，不进行解析
        
        Args:
            ecosystem: 生态系统名称
            
        Returns:
            解压后的JSON文件数量
        """
        try:
            # 构建下载URL
            zip_url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
            zip_file_path = self.temp_dir / f"{ecosystem}-all.zip"
            ecosystem_dir = self.osv_dir / ecosystem
            
            # 创建生态系统目录
            ecosystem_dir.mkdir(parents=True, exist_ok=True)
            
            # 下载ZIP文件
            logger.info(f"下载 {ecosystem} 数据包")
            response = requests.get(zip_url, stream=True, timeout=300)
            response.raise_for_status()
            
            # 保存ZIP文件
            with open(zip_file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            logger.info(f"{ecosystem} 数据包下载完成")
            
            # 解压ZIP文件
            logger.info(f"解压 {ecosystem} 数据包")
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(ecosystem_dir)
            
            # 清理ZIP文件
            zip_file_path.unlink()
            
            # 统计JSON文件数量
            json_files = list(ecosystem_dir.glob("*.json"))
            file_count = len(json_files)
            logger.info(f"在 {ecosystem} 中解压了 {file_count} 个JSON文件")
            
            return file_count
            
        except Exception as e:
            logger.error(f"处理生态系统 {ecosystem} 失败: {e}")
            return 0
