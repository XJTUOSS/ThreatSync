"""
GitHub Security Advisories 数据采集器
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


class GitHubCollector(BaseCollector):
    """GitHub Security Advisories数据采集器"""
    
    def _get_source(self) -> DataSource:
        return DataSource.GITHUB
    
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.api_config = config_manager.get_api_config('github')
        self.token = self.api_config.get('token', '')
        self.base_url = "https://api.github.com"
        self.http_client = RequestsUtil(config_manager.get_crawler_config())
    
    def collect(self, days_back: int = 7, per_page: int = 100, **kwargs) -> List[VulnerabilityData]:
        """
        采集GitHub Security Advisories数据
        
        Args:
            days_back: 回溯天数
            per_page: 每页数量
        """
        logger.info(f"开始采集GitHub Security Advisories数据，回溯{days_back}天")
        
        # 设置时间范围
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        vulnerabilities = []
        page = 1
        
        while True:
            url = f"{self.base_url}/advisories"
            params = {
                'published': f">={start_date.strftime('%Y-%m-%d')}",
                'per_page': per_page,
                'page': page,
                'sort': 'published',
                'direction': 'desc'
            }
            
            headers = {
                'Accept': 'application/vnd.github.v3+json',
                'Authorization': f'token {self.token}' if self.token else None
            }
            
            # 移除None值
            headers = {k: v for k, v in headers.items() if v is not None}
            
            try:
                logger.info(f"请求GitHub Advisories数据，页码={page}")
                response = self.http_client.get(url, params=params, headers=headers)
                advisories = response.json()
                
                if not advisories:
                    break
                
                for advisory in advisories:
                    try:
                        vuln = self._parse_github_advisory(advisory)
                        if vuln:
                            vulnerabilities.append(vuln)
                    except Exception as e:
                        self._handle_error(e, f"解析GitHub Advisory失败: {advisory.get('ghsa_id', 'unknown')}")
                
                # 检查是否还有更多页
                if len(advisories) < per_page:
                    break
                
                page += 1
                
            except Exception as e:
                self._handle_error(e, f"请求GitHub API失败，页码={page}")
                break
        
        logger.info(f"GitHub数据采集完成，共收集到{len(vulnerabilities)}个漏洞")
        return vulnerabilities
    
    def _parse_github_advisory(self, advisory: Dict[str, Any]) -> Optional[VulnerabilityData]:
        """解析GitHub Security Advisory数据"""
        ghsa_id = advisory.get('ghsa_id', '')
        if not ghsa_id:
            return None
        
        # 基本信息
        title = advisory.get('summary', '')
        description = advisory.get('description', '')
        
        # 时间信息
        published_date = datetime.fromisoformat(
            advisory.get('published_at', '').replace('Z', '+00:00')
        )
        
        updated_date = None
        if advisory.get('updated_at'):
            updated_date = datetime.fromisoformat(
                advisory.get('updated_at', '').replace('Z', '+00:00')
            )
        
        # CVSS评分
        cvss_scores = []
        cvss = advisory.get('cvss', {})
        if cvss:
            score = CVSSScore(
                version="3.1",
                base_score=cvss.get('score', 0.0),
                vector_string=cvss.get('vector_string', ''),
                severity=self._parse_github_severity(advisory.get('severity', 'unknown'))
            )
            cvss_scores.append(score)
        
        # 弱点信息
        weaknesses = []
        for cwe in advisory.get('cwe_ids', []):
            weaknesses.append(Weakness(
                cwe_id=cwe,
                name=cwe,
                description=""
            ))
        
        # 参考链接
        references = []
        for ref in advisory.get('references', []):
            url = ref.get('url', '')
            if url:
                references.append(Reference(
                    url=url,
                    title=ref.get('title', ''),
                    source='GitHub'
                ))
        
        # HTML URL
        if advisory.get('html_url'):
            references.append(Reference(
                url=advisory['html_url'],
                title=title,
                source='GitHub',
                tags=['official']
            ))
        
        # 受影响的产品
        affected_products = []
        for vuln in advisory.get('vulnerabilities', []):
            package = vuln.get('package', {})
            if package:
                ecosystem = package.get('ecosystem', '')
                name = package.get('name', '')
                
                for version_range in vuln.get('vulnerable_version_range', '').split(','):
                    version_range = version_range.strip()
                    if version_range:
                        affected_products.append(AffectedProduct(
                            vendor=ecosystem,
                            product=name,
                            version_affected=version_range
                        ))
        
        # 严重性等级
        severity = self._parse_github_severity(advisory.get('severity', 'unknown'))
        
        return VulnerabilityData(
            id=ghsa_id,
            cve_id=None,  # GitHub可能有关联的CVE ID
            title=title,
            description=description,
            status=VulnerabilityStatus.PUBLISHED,
            severity=severity,
            source=DataSource.GITHUB,
            published_date=published_date,
            modified_date=updated_date,
            cvss_scores=cvss_scores,
            weaknesses=weaknesses,
            affected_products=affected_products,
            references=references,
            raw_data=advisory
        )
    
    def _parse_github_severity(self, severity: str) -> str:
        """解析GitHub严重性等级"""
        severity_map = {
            'critical': 'CRITICAL',
            'high': 'HIGH',
            'moderate': 'MEDIUM',
            'low': 'LOW'
        }
        return severity_map.get(severity.lower(), 'UNKNOWN')
