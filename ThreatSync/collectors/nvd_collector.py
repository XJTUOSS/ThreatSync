"""
NVD (National Vulnerability Database) 数据采集器
"""
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

from .base_collector import BaseCollector
from ..models.vulnerability import (
    VulnerabilityData, DataSource, VulnerabilityStatus, 
    CVSSScore, Reference, Weakness, AffectedProduct
)
from ..utils import logger, RequestsUtil


class NVDCollector(BaseCollector):
    """NVD数据采集器"""
    
    def _get_source(self) -> DataSource:
        return DataSource.NVD
    
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.api_config = config_manager.get_api_config('nvd')
        self.base_url = self.api_config.get('base_url')
        self.api_key = self.api_config.get('api_key')
        
        # 获取速率限制配置
        rate_limit_config = self.api_config.get('rate_limit', {})
        self.requests_per_30s = rate_limit_config.get('requests_per_30s', 5)
        self.sleep_between_requests = rate_limit_config.get('sleep_between_requests', 6)
        
        # 获取分页配置
        pagination_config = self.api_config.get('pagination', {})
        self.results_per_page = pagination_config.get('results_per_page', 2000)
        self.max_total_results = pagination_config.get('max_total_results', 50000)
        
        # 使用新的HTTP配置
        self.http_client = RequestsUtil(config_manager.get_http_config())
    
    def collect(self, days_back: int = 7, start_date: str = None, 
                end_date: str = None, collect_all: bool = False, **kwargs) -> List[VulnerabilityData]:
        """
        采集NVD数据
        
        Args:
            days_back: 回溯天数（默认7天）
            start_date: 开始日期 (YYYY-MM-DD格式)
            end_date: 结束日期 (YYYY-MM-DD格式)
            collect_all: 是否采集所有数据（不限时间）
        """
        if collect_all:
            logger.info("开始采集NVD所有数据")
        else:
            logger.info(f"开始采集NVD数据，回溯{days_back}天")
        
        # 设置时间范围
        if collect_all:
            # 不限时间：从1999年CVE开始到现在
            pub_start_date = "1999-01-01"
            pub_end_date = datetime.now().strftime('%Y-%m-%d')
        elif start_date and end_date:
            pub_start_date = start_date
            pub_end_date = end_date
        else:
            end_dt = datetime.now()
            start_dt = end_dt - timedelta(days=days_back)
            pub_start_date = start_dt.strftime('%Y-%m-%d')
            pub_end_date = end_dt.strftime('%Y-%m-%d')
        
        vulnerabilities = []
        start_index = 0
        total_collected = 0
        
        while total_collected < self.max_total_results:
            params = {
                'pubStartDate': f"{pub_start_date}T00:00:00.000",
                'pubEndDate': f"{pub_end_date}T23:59:59.999",
                'startIndex': start_index,
                'resultsPerPage': self.results_per_page
            }
            
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            try:
                logger.info(f"请求NVD数据，startIndex={start_index}")
                
                # 遵循NVD官方建议的6秒间隔
                if start_index > 0:
                    import time
                    time.sleep(self.sleep_between_requests)
                
                # 记录API请求开始时间
                request_start_time = datetime.now()
                
                response = self.http_client.get(self.base_url, params=params, headers=headers)
                
                # 计算响应时间
                response_time = (datetime.now() - request_start_time).total_seconds()
                
                # 记录API请求日志
                logger.log_api_request(
                    method="GET",
                    url=self.base_url,
                    status_code=response.status_code,
                    response_time=response_time,
                    request_data={'params': params, 'headers': {k: v for k, v in headers.items() if k != 'apiKey'}},
                    error=None if response.status_code == 200 else f"HTTP {response.status_code}"
                )
                
                # 调试信息
                logger.debug(f"响应状态码: {response.status_code}")
                logger.debug(f"响应头: {dict(response.headers)}")
                logger.debug(f"响应内容长度: {len(response.content)}")
                
                # 检查响应状态
                if response.status_code != 200:
                    error_msg = f"HTTP错误 {response.status_code}: {response.text[:200]}"
                    self._handle_error(Exception(error_msg), f"请求NVD API失败，startIndex={start_index}")
                    break
                
                # 检查响应内容
                if not response.content:
                    error_msg = "响应内容为空"
                    self._handle_error(Exception(error_msg), f"请求NVD API失败，startIndex={start_index}")
                    break
                
                data = response.json()
                logger.debug(f"JSON数据键: {list(data.keys()) if isinstance(data, dict) else type(data)}")
                
                cve_items = data.get('vulnerabilities', [])
                if not cve_items:
                    logger.info(f"没有更多数据，totalResults: {data.get('totalResults', 0)}")
                    break
                
                for item in cve_items:
                    try:
                        vuln = self._parse_nvd_vulnerability(item)
                        if vuln:
                            vulnerabilities.append(vuln)
                    except Exception as e:
                        self._handle_error(e, f"解析漏洞数据失败: {item.get('cve', {}).get('id', 'unknown')}")
                
                total_collected += len(cve_items)
                start_index += self.results_per_page
                
                logger.info(f"已采集 {len(cve_items)} 条数据，累计 {total_collected} 条")
                
                # 检查是否已获取所有数据
                total_results = data.get('totalResults', 0)
                if start_index >= total_results:
                    logger.info(f"已获取全部数据，totalResults: {total_results}")
                    break
                    
            except Exception as e:
                self._handle_error(e, f"请求NVD API失败，startIndex={start_index}")
                break
        
        logger.info(f"NVD数据采集完成，共收集到{len(vulnerabilities)}个漏洞")
        return vulnerabilities
    
    def _parse_nvd_vulnerability(self, item: Dict[str, Any]) -> Optional[VulnerabilityData]:
        """解析NVD漏洞数据"""
        cve_data = item.get('cve', {})
        cve_id = cve_data.get('id', '')
        
        if not cve_id:
            return None
        
        # 基本信息
        descriptions = cve_data.get('descriptions', [])
        if descriptions is None:
            descriptions = []
        description = ""
        for desc in descriptions:
            if desc and desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        # 发布和修改时间
        published_date = datetime.fromisoformat(
            cve_data.get('published', '').replace('Z', '+00:00')
        )
        
        modified_date = None
        if cve_data.get('lastModified'):
            modified_date = datetime.fromisoformat(
                cve_data.get('lastModified', '').replace('Z', '+00:00')
            )
        
        # CVSS评分
        cvss_scores = []
        metrics = cve_data.get('metrics', {})
        if metrics is None:
            metrics = {}
        
        # CVSS v3.1
        cvss_v31_list = metrics.get('cvssMetricV31', [])
        if cvss_v31_list is None:
            cvss_v31_list = []
        for cvss_v31 in cvss_v31_list:
            cvss_data = cvss_v31.get('cvssData', {}) if cvss_v31 else {}
            score = CVSSScore(
                version="3.1",
                base_score=cvss_data.get('baseScore', 0.0),
                vector_string=cvss_data.get('vectorString', ''),
                severity=self._parse_severity(cvss_data.get('baseScore', 0.0))
            )
            cvss_scores.append(score)
        
        # CVSS v3.0
        cvss_v30_list = metrics.get('cvssMetricV30', [])
        if cvss_v30_list is None:
            cvss_v30_list = []
        for cvss_v30 in cvss_v30_list:
            cvss_data = cvss_v30.get('cvssData', {}) if cvss_v30 else {}
            score = CVSSScore(
                version="3.0",
                base_score=cvss_data.get('baseScore', 0.0),
                vector_string=cvss_data.get('vectorString', ''),
                severity=self._parse_severity(cvss_data.get('baseScore', 0.0))
            )
            cvss_scores.append(score)
        
        # CVSS v2
        cvss_v2_list = metrics.get('cvssMetricV2', [])
        if cvss_v2_list is None:
            cvss_v2_list = []
        for cvss_v2 in cvss_v2_list:
            cvss_data = cvss_v2.get('cvssData', {}) if cvss_v2 else {}
            score = CVSSScore(
                version="2.0",
                base_score=cvss_data.get('baseScore', 0.0),
                vector_string=cvss_data.get('vectorString', ''),
                severity=self._parse_severity(cvss_data.get('baseScore', 0.0))
            )
            cvss_scores.append(score)
        
        # 弱点信息（CWE）
        weaknesses = []
        weaknesses_list = cve_data.get('weaknesses', [])
        if weaknesses_list is None:
            weaknesses_list = []
        for weakness in weaknesses_list:
            if weakness is None:
                continue
            descriptions = weakness.get('description', [])
            if descriptions is None:
                continue
            for desc in descriptions:
                if desc and desc.get('lang') == 'en':
                    cwe_id = desc.get('value', '')
                    if cwe_id.startswith('CWE-'):
                        weaknesses.append(Weakness(
                            cwe_id=cwe_id,
                            name=cwe_id,
                            description=""
                        ))
        
        # 参考链接
        references = []
        references_list = cve_data.get('references', [])
        if references_list is None:
            references_list = []
        for ref in references_list:
            if ref is None:
                continue
            url = ref.get('url', '')
            if url:
                references.append(Reference(
                    url=url,
                    source=ref.get('source', ''),
                    tags=ref.get('tags', []) or []
                ))
        
        # 受影响的产品
        affected_products = []
        configurations = cve_data.get('configurations', [])
        if configurations is None:
            configurations = []
        for config in configurations:
            if config is None:
                continue
            nodes = config.get('nodes', [])
            if nodes is None:
                continue
            for node in nodes:
                if node is None:
                    continue
                cpe_matches = node.get('cpeMatch', [])
                if cpe_matches is None:
                    continue
                for cpe_match in cpe_matches:
                    if cpe_match is None:
                        continue
                    criteria = cpe_match.get('criteria', '')
                    if criteria.startswith('cpe:2.3:'):
                        # 解析CPE格式
                        cpe_parts = criteria.split(':')
                        if len(cpe_parts) >= 6:
                            vendor = cpe_parts[3]
                            product = cpe_parts[4]
                            version = cpe_parts[5]
                            
                            affected_products.append(AffectedProduct(
                                vendor=vendor,
                                product=product,
                                version_affected=version,
                                version_start=cpe_match.get('versionStartIncluding'),
                                version_end=cpe_match.get('versionEndExcluding')
                            ))
        
        # 确定严重性等级
        severity = "UNKNOWN"
        if cvss_scores:
            severity = cvss_scores[0].severity
        
        return VulnerabilityData(
            id=cve_id,
            cve_id=cve_id,
            title=f"CVE-{cve_id.split('-')[1]}-{cve_id.split('-')[2]}",
            description=description,
            status=VulnerabilityStatus.PUBLISHED,
            severity=severity,
            source=DataSource.NVD,
            published_date=published_date,
            modified_date=modified_date,
            cvss_scores=cvss_scores,
            weaknesses=weaknesses,
            affected_products=affected_products,
            references=references,
            raw_data=item
        )
