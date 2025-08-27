"""
OSV (Open Source Vulnerabilities) 数据采集器
"""
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from .base_collector import BaseCollector
from ..models.vulnerability import (
    VulnerabilityData, DataSource, VulnerabilityStatus,
    CVSSScore, Reference, Weakness, AffectedProduct
)
from ..utils import logger, RequestsUtil


class OSVCollector(BaseCollector):
    """OSV数据采集器"""
    
    def _get_source(self) -> DataSource:
        return DataSource.OSV
    
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.api_config = config_manager.get_api_config('osv')
        self.base_url = self.api_config.get('base_url', 'https://api.osv.dev/v1')
        self.http_client = RequestsUtil(config_manager.get_crawler_config())
    
    def collect(self, ecosystems: List[str] = None, page_size: int = 1000, 
                collect_all: bool = False, **kwargs) -> List[VulnerabilityData]:
        """
        采集OSV数据
        
        Args:
            ecosystems: 生态系统列表，如['PyPI', 'npm', 'Go', 'Maven']
            page_size: 页面大小
            collect_all: 是否采集所有生态系统（忽略ecosystems参数）
        """
        if collect_all:
            # 采集所有支持的生态系统
            ecosystems = ['PyPI', 'npm', 'Go', 'Maven', 'NuGet', 'RubyGems', 'crates.io', 
                         'Packagist', 'ConanCenter', 'Rocky Linux', 'AlmaLinux', 'Ubuntu',
                         'Debian', 'Alpine', 'SUSE', 'Red Hat', 'Android', 'GSD']
            logger.info("开始采集OSV所有生态系统数据")
        elif ecosystems is None:
            ecosystems = ['PyPI', 'npm', 'Go', 'Maven', 'NuGet', 'RubyGems', 'crates.io']
        
        logger.info(f"开始采集OSV数据，生态系统: {ecosystems}")
        
        vulnerabilities = []
        
        for ecosystem in ecosystems:
            try:
                logger.info(f"采集 {ecosystem} 生态系统的漏洞数据")
                ecosystem_vulns = self._collect_ecosystem_vulnerabilities(ecosystem, page_size)
                vulnerabilities.extend(ecosystem_vulns)
            except Exception as e:
                self._handle_error(e, f"采集 {ecosystem} 生态系统数据失败")
        
        logger.info(f"OSV数据采集完成，共收集到{len(vulnerabilities)}个漏洞")
        return vulnerabilities
    
    def _collect_ecosystem_vulnerabilities(self, ecosystem: str, page_size: int) -> List[VulnerabilityData]:
        """采集特定生态系统的漏洞数据"""
        vulnerabilities = []
        page_token = ""
        
        while True:
            url = f"{self.base_url}/query"
            
            query_data = {
                "query": {
                    "ecosystem": ecosystem
                },
                "page_size": page_size
            }
            
            if page_token:
                query_data["page_token"] = page_token
            
            try:
                response = self.http_client.post(url, json=query_data)
                data = response.json()
                
                vulns = data.get('vulns', [])
                if not vulns:
                    break
                
                for vuln_data in vulns:
                    try:
                        vuln = self._parse_osv_vulnerability(vuln_data)
                        if vuln:
                            vulnerabilities.append(vuln)
                    except Exception as e:
                        self._handle_error(e, f"解析OSV漏洞失败: {vuln_data.get('id', 'unknown')}")
                
                # 检查是否有下一页
                page_token = data.get('next_page_token', '')
                if not page_token:
                    break
                    
            except Exception as e:
                self._handle_error(e, f"请求OSV API失败，生态系统={ecosystem}")
                break
        
        return vulnerabilities
    
    def _parse_osv_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[VulnerabilityData]:
        """解析OSV漏洞数据"""
        vuln_id = vuln_data.get('id', '')
        if not vuln_id:
            return None
        
        # 基本信息
        summary = vuln_data.get('summary', '')
        details = vuln_data.get('details', '')
        
        # 时间信息
        published_date = None
        modified_date = None
        
        if vuln_data.get('published'):
            published_date = datetime.fromisoformat(
                vuln_data['published'].replace('Z', '+00:00')
            )
        
        if vuln_data.get('modified'):
            modified_date = datetime.fromisoformat(
                vuln_data['modified'].replace('Z', '+00:00')
            )
        
        # 严重性信息
        severity = "UNKNOWN"
        cvss_scores = []
        
        for sev in vuln_data.get('severity', []):
            if sev.get('type') == 'CVSS_V3':
                score_value = sev.get('score', 0.0)
                if isinstance(score_value, str):
                    # 解析CVSS向量字符串中的分数
                    try:
                        score_value = float(score_value.split('/')[0])
                    except:
                        score_value = 0.0
                
                cvss_score = CVSSScore(
                    version="3.x",
                    base_score=score_value,
                    vector_string=str(sev.get('score', '')),
                    severity=self._parse_severity(score_value)
                )
                cvss_scores.append(cvss_score)
                severity = cvss_score.severity
        
        # 别名（包括CVE ID）
        cve_id = None
        for alias in vuln_data.get('aliases', []):
            if alias.startswith('CVE-'):
                cve_id = alias
                break
        
        # 参考链接
        references = []
        for ref in vuln_data.get('references', []):
            url = ref.get('url', '')
            if url:
                references.append(Reference(
                    url=url,
                    title=ref.get('title', ''),
                    source='OSV',
                    tags=ref.get('type', '').split() if ref.get('type') else []
                ))
        
        # 受影响的产品
        affected_products = []
        for affected in vuln_data.get('affected', []):
            package = affected.get('package', {})
            ecosystem = package.get('ecosystem', '')
            name = package.get('name', '')
            
            # 处理版本范围
            for version_range in affected.get('ranges', []):
                events = version_range.get('events', [])
                version_info = "unknown"
                
                for event in events:
                    if 'introduced' in event:
                        version_info = f">= {event['introduced']}"
                    elif 'fixed' in event:
                        version_info += f", < {event['fixed']}"
                
                affected_products.append(AffectedProduct(
                    vendor=ecosystem,
                    product=name,
                    version_affected=version_info
                ))
        
        return VulnerabilityData(
            id=vuln_id,
            cve_id=cve_id,
            title=summary or vuln_id,
            description=details,
            status=VulnerabilityStatus.PUBLISHED,
            severity=severity,
            source=DataSource.OSV,
            published_date=published_date or datetime.now(),
            modified_date=modified_date,
            cvss_scores=cvss_scores,
            weaknesses=[],  # OSV通常不提供CWE信息
            affected_products=affected_products,
            references=references,
            raw_data=vuln_data
        )
