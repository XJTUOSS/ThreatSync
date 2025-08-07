"""
CNVD (中国国家信息安全漏洞库) 数据采集器
"""
import re
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from .base_collector import BaseCollector
from ..models.vulnerability import (
    VulnerabilityData, DataSource, VulnerabilityStatus,
    CVSSScore, Reference, Weakness, AffectedProduct
)
from ..utils import logger, RequestsUtil


class CNVDCollector(BaseCollector):
    """CNVD数据采集器（非结构化数据）"""
    
    def _get_source(self) -> DataSource:
        return DataSource.CNVD
    
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.base_url = "https://www.cnvd.org.cn"
        self.http_client = RequestsUtil(config_manager.get_crawler_config())
        
        # 设置数据保存路径
        self.data_dir = Path("data/unstructured/cnvd")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # 创建年份子目录
        current_year = datetime.now().year
        for year in range(2014, current_year + 1):  # CNVD从2014年开始
            year_dir = self.data_dir / str(year)
            year_dir.mkdir(parents=True, exist_ok=True)
    
    def collect(self, days_back: int = 7, max_pages: int = 10, save_raw_json: bool = True, **kwargs) -> List[VulnerabilityData]:
        """
        采集CNVD漏洞数据
        
        Args:
            days_back: 回溯天数
            max_pages: 最大页数
            save_raw_json: 是否保存原生JSON文件
        """
        logger.info(f"开始采集CNVD数据，回溯{days_back}天，最大{max_pages}页")
        
        vulnerabilities = []
        
        # 获取漏洞列表
        vuln_urls = self._get_vulnerability_urls(max_pages)
        
        logger.info(f"找到{len(vuln_urls)}个漏洞链接")
        
        for i, url in enumerate(vuln_urls):
            try:
                logger.info(f"处理漏洞 {i+1}/{len(vuln_urls)}: {url}")
                
                # 解析漏洞详情
                vuln_data = self._parse_vulnerability_detail(url)
                if vuln_data:
                    vulnerabilities.append(vuln_data)
                    
                    # 如果需要保存原生JSON文件
                    if save_raw_json:
                        self._save_raw_json(vuln_data, url)
                
                # 添加延时避免被封
                time.sleep(1)
                
            except Exception as e:
                self._handle_error(e, f"解析CNVD漏洞详情失败: {url}")
        
        logger.info(f"CNVD数据采集完成，共收集到{len(vulnerabilities)}个漏洞")
        return vulnerabilities
    
    def _get_vulnerability_urls(self, max_pages: int) -> List[str]:
        """获取漏洞详情页URL列表"""
        urls = []
        
        for page in range(1, max_pages + 1):
            try:
                list_url = f"{self.base_url}/flaw/list.htm"
                params = {'page': page}
                
                response = self.http_client.get(list_url, params=params)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # 查找漏洞链接
                links = soup.find_all('a', href=re.compile(r'/flaw/show/'))
                
                if not links:
                    break
                
                for link in links:
                    href = link.get('href')
                    if href:
                        full_url = urljoin(self.base_url, href)
                        if full_url not in urls:
                            urls.append(full_url)
                
                logger.info(f"第{page}页找到{len(links)}个漏洞链接")
                
            except Exception as e:
                self._handle_error(e, f"获取CNVD列表页失败，页码={page}")
                break
        
        return urls
    
    def _parse_vulnerability_detail(self, url: str) -> Optional[VulnerabilityData]:
        """解析漏洞详情页"""
        try:
            response = self.http_client.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 提取漏洞ID
            cnvd_id = self._extract_cnvd_id(soup, url)
            if not cnvd_id:
                return None
            
            # 提取基本信息
            title = self._extract_title(soup)
            description = self._extract_description(soup)
            
            # 提取时间信息
            published_date = self._extract_published_date(soup)
            
            # 提取严重性等级
            severity = self._extract_severity(soup)
            
            # 提取CVE ID
            cve_id = self._extract_cve_id(soup)
            
            # 提取受影响产品
            affected_products = self._extract_affected_products(soup)
            
            # 提取参考链接
            references = [Reference(url=url, title=title, source='CNVD')]
            
            # 提取技术细节
            technical_details = self._extract_technical_details(soup)
            
            return VulnerabilityData(
                id=cnvd_id,
                cve_id=cve_id,
                title=title,
                description=description,
                status=VulnerabilityStatus.PUBLISHED,
                severity=severity,
                source=DataSource.CNVD,
                published_date=published_date or datetime.now(),
                modified_date=None,
                cvss_scores=[],
                weaknesses=[],
                affected_products=affected_products,
                references=references,
                technical_details=technical_details,
                raw_data={'url': url, 'html': response.text[:1000]}  # 保存部分HTML
            )
            
        except Exception as e:
            logger.error(f"解析CNVD漏洞详情失败: {url}, 错误: {str(e)}")
            return None
    
    def _save_raw_json(self, vuln_data: VulnerabilityData, source_url: str) -> None:
        """保存原生JSON数据到文件"""
        try:
            # 构建JSON数据结构（类似NVD格式）
            json_data = {
                "id": vuln_data.id,
                "sourceIdentifier": "cnvd.org.cn",
                "lastModified": vuln_data.modified_date.isoformat() if vuln_data.modified_date else datetime.now().isoformat(),
                "published": vuln_data.published_date.isoformat(),
                "vulnStatus": vuln_data.status.value if hasattr(vuln_data.status, 'value') else str(vuln_data.status),
                "descriptions": [
                    {
                        "lang": "zh",
                        "value": vuln_data.description
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [] if not vuln_data.cvss_scores else [
                        {
                            "source": "cnvd.org.cn",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": score.vector,
                                "baseScore": score.base_score,
                                "baseSeverity": score.severity
                            }
                        } for score in vuln_data.cvss_scores
                    ]
                },
                "weaknesses": [
                    {
                        "source": "cnvd.org.cn",
                        "type": "Primary",
                        "description": [
                            {
                                "lang": "zh",
                                "value": weakness.description
                            }
                        ]
                    } for weakness in vuln_data.weaknesses
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": f"cpe:2.3:a:{product.vendor}:{product.product}:{product.version_affected}:*:*:*:*:*:*:*",
                                        "matchCriteriaId": f"cnvd-{vuln_data.id}-{i}"
                                    } for i, product in enumerate(vuln_data.affected_products)
                                ]
                            }
                        ]
                    }
                ] if vuln_data.affected_products else [],
                "references": [
                    {
                        "url": ref.url,
                        "source": ref.source or "cnvd.org.cn",
                        "tags": ["Technical Description"] if ref.title else []
                    } for ref in vuln_data.references
                ],
                "cnvd": {
                    "title": vuln_data.title,
                    "severity": vuln_data.severity,
                    "technicalDetails": vuln_data.technical_details,
                    "sourceUrl": source_url,
                    "collectedAt": datetime.now().isoformat()
                }
            }
            
            # 如果有CVE ID，添加到数据中
            if vuln_data.cve_id:
                json_data["cveId"] = vuln_data.cve_id
            
            # 确定保存路径（按年份分类）
            if vuln_data.published_date:
                year = vuln_data.published_date.year
            else:
                year = datetime.now().year
            
            year_dir = self.data_dir / str(year)
            file_path = year_dir / f"{vuln_data.id}.json"
            
            # 保存JSON文件
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, ensure_ascii=False, indent=2)
            
            logger.debug(f"保存原生JSON文件: {file_path}")
            
        except Exception as e:
            logger.error(f"保存原生JSON文件失败 {vuln_data.id}: {str(e)}")
    
    def get_last_modified_date(self) -> Optional[datetime]:
        """
        获取本地数据集中最新的修改时间
        用于增量同步
        """
        try:
            last_modified = None
            for json_file in self.data_dir.rglob("*.json"):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    modified_str = data.get('lastModified')
                    if modified_str:
                        modified_dt = datetime.fromisoformat(modified_str.replace('Z', '+00:00'))
                        if last_modified is None or modified_dt > last_modified:
                            last_modified = modified_dt
                            
                except Exception as e:
                    logger.debug(f"读取文件 {json_file} 时出错: {str(e)}")
                    continue
            
            return last_modified
            
        except Exception as e:
            logger.error(f"获取最后修改时间失败: {str(e)}")
            return None
    
    def _extract_cnvd_id(self, soup: BeautifulSoup, url: str) -> Optional[str]:
        """提取CNVD ID"""
        # 从URL中提取
        match = re.search(r'CNVD-\d{4}-\d+', url)
        if match:
            return match.group()
        
        # 从页面内容中提取
        text = soup.get_text()
        match = re.search(r'CNVD-\d{4}-\d+', text)
        if match:
            return match.group()
        
        return None
    
    def _extract_title(self, soup: BeautifulSoup) -> str:
        """提取标题"""
        # 尝试多种标题选择器
        selectors = [
            'h1',
            '.vulTitle',
            '.flaw_title',
            'title'
        ]
        
        for selector in selectors:
            element = soup.select_one(selector)
            if element:
                title = element.get_text().strip()
                if title and len(title) > 5:
                    return title
        
        return "未知漏洞"
    
    def _extract_description(self, soup: BeautifulSoup) -> str:
        """提取描述"""
        # 查找描述内容
        desc_elements = soup.find_all(['p', 'div'], class_=re.compile(r'desc|content|detail'))
        
        description = ""
        for element in desc_elements:
            text = element.get_text().strip()
            if text and len(text) > 20:
                description += text + "\\n"
        
        if not description:
            # 获取主要内容
            main_content = soup.find('div', class_=re.compile(r'main|content'))
            if main_content:
                description = main_content.get_text().strip()[:500]
        
        return description or "暂无描述信息"
    
    def _extract_published_date(self, soup: BeautifulSoup) -> Optional[datetime]:
        """提取发布时间"""
        text = soup.get_text()
        
        # 匹配日期格式
        date_patterns = [
            r'(\d{4}-\d{2}-\d{2})',
            r'(\d{4}/\d{2}/\d{2})',
            r'(\d{4}年\d{1,2}月\d{1,2}日)'
        ]
        
        for pattern in date_patterns:
            matches = re.findall(pattern, text)
            if matches:
                date_str = matches[0]
                try:
                    # 处理中文日期格式
                    if '年' in date_str:
                        date_str = re.sub(r'年|月', '-', date_str).replace('日', '')
                    
                    return datetime.strptime(date_str, '%Y-%m-%d')
                except:
                    continue
        
        return None
    
    def _extract_severity(self, soup: BeautifulSoup) -> str:
        """提取严重性等级"""
        text = soup.get_text().lower()
        
        if any(word in text for word in ['critical', '严重', '高危']):
            return "CRITICAL"
        elif any(word in text for word in ['high', '高']):
            return "HIGH"
        elif any(word in text for word in ['medium', '中', '中等']):
            return "MEDIUM"
        elif any(word in text for word in ['low', '低']):
            return "LOW"
        
        return "UNKNOWN"
    
    def _extract_cve_id(self, soup: BeautifulSoup) -> Optional[str]:
        """提取CVE ID"""
        text = soup.get_text()
        match = re.search(r'CVE-\d{4}-\d+', text)
        return match.group() if match else None
    
    def _extract_affected_products(self, soup: BeautifulSoup) -> List[AffectedProduct]:
        """提取受影响的产品"""
        products = []
        text = soup.get_text()
        
        # 简单的产品提取逻辑
        product_keywords = ['产品', '软件', '系统', '版本']
        for keyword in product_keywords:
            if keyword in text:
                # 这里可以添加更复杂的产品解析逻辑
                products.append(AffectedProduct(
                    vendor="未知厂商",
                    product="未知产品",
                    version_affected="未知版本"
                ))
                break
        
        return products
    
    def _extract_technical_details(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """提取技术细节"""
        details = {}
        
        # 提取表格信息
        tables = soup.find_all('table')
        for table in tables:
            rows = table.find_all('tr')
            for row in rows:
                cols = row.find_all(['td', 'th'])
                if len(cols) >= 2:
                    key = cols[0].get_text().strip()
                    value = cols[1].get_text().strip()
                    if key and value:
                        details[key] = value
        
        return details
