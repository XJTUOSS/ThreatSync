"""
GitHub Security Advisories 数据采集器
支持两种采集方式：
1. GitHub REST API - 采集GitHub Security Advisories
2. GitHub GraphQL API - 采集详细的安全公告信息
"""
import json
import time
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from pathlib import Path

from .base_collector import BaseCollector
from ..models.vulnerability import (
    VulnerabilityData, DataSource, VulnerabilityStatus, SeverityLevel,
    CVSSScore, Reference, Weakness, AffectedProduct
)
from ..utils import logger, RequestsUtil


class GitHubCollector(BaseCollector):
    """GitHub Security Advisories数据采集器
    
    支持两种采集方式：
    1. REST API - 通过GitHub API采集Security Advisories
    2. GraphQL API - 通过GraphQL获取详细信息
    3. Advisory Database - 克隆GitHub Advisory Database仓库
    """
    
    def _get_source(self) -> DataSource:
        return DataSource.GITHUB
    
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.api_config = config_manager.get_api_config('github')
        self.token = self.api_config.get('token', '')
        self.base_url = self.api_config.get('base_url', 'https://api.github.com')
        self.rate_limit = self.api_config.get('rate_limit', 5000)
        
        # 使用新的HTTP配置
        self.http_client = RequestsUtil(config_manager.get_http_config())
        
        # GraphQL端点 - 从配置中获取或使用默认值
        self.graphql_url = f"{self.base_url}/graphql"
        
        # Advisory Database配置 - 从配置中获取
        collection_config = self.api_config.get('collection', {})
        methods_config = collection_config.get('methods', {})
        database_config = methods_config.get('database', {})
        self.advisory_repo_url = database_config.get('repo_url', 'https://github.com/github/advisory-database.git')
        
    def collect(self, days_back: int = 7, method: str = 'rest', 
                start_date: str = None, end_date: str = None, collect_all: bool = False, **kwargs) -> List[VulnerabilityData]:
        """
        采集GitHub Security Advisories数据
        
        Args:
            days_back: 回溯天数（默认7天）
            method: 采集方式 ('rest', 'graphql', 'database')
            start_date: 开始日期 (YYYY-MM-DD格式)
            end_date: 结束日期 (YYYY-MM-DD格式)
            collect_all: 是否采集所有数据（不限时间）
        """
        if collect_all:
            logger.info(f"开始采集GitHub所有数据，方式={method}")
        else:
            logger.info(f"开始采集GitHub数据，方式={method}，回溯{days_back}天")
        
        # 设置时间范围（确保所有datetime对象都带有时区信息）
        if collect_all:
            # 不限时间：从2008年GitHub成立开始到现在
            start_dt = datetime(2008, 1, 1, tzinfo=timezone.utc)
            end_dt = datetime.now(timezone.utc)
        elif start_date and end_date:
            start_dt = datetime.strptime(start_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            end_dt = datetime.strptime(end_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
        else:
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(days=days_back)
        
        vulnerabilities = []
        
        try:
            if method == 'rest':
                vulnerabilities = self._collect_rest_api(start_dt, end_dt, **kwargs)
            elif method == 'graphql':
                vulnerabilities = self._collect_graphql_api(start_dt, end_dt, **kwargs)
            elif method == 'database':
                vulnerabilities = self._collect_advisory_database(start_dt, end_dt, **kwargs)
            else:
                raise ValueError(f"不支持的采集方式: {method}")
        except Exception as e:
            self._handle_error(e, f"GitHub数据采集失败，方式={method}")
        
        logger.info(f"GitHub数据采集完成，共收集到{len(vulnerabilities)}个漏洞")
        return vulnerabilities
    
    def _collect_rest_api(self, start_dt: datetime, end_dt: datetime, 
                         per_page: int = 100, **kwargs) -> List[VulnerabilityData]:
        """
        通过REST API采集GitHub Security Advisories数据
        
        Args:
            start_dt: 开始时间
            end_dt: 结束时间
            per_page: 每页数量
        """
        logger.info("使用REST API采集GitHub数据")
        
        # 如果是全量采集（从2008年开始），使用分批采集策略
        if start_dt.year <= 2008:
            return self._collect_all_data_in_batches(per_page, **kwargs)
        else:
            return self._collect_data_with_time_filter(start_dt, end_dt, per_page, **kwargs)
    
    def _collect_data_with_time_filter(self, start_dt: datetime, end_dt: datetime, 
                                     per_page: int = 100, **kwargs) -> List[VulnerabilityData]:
        """采集指定时间范围的数据"""
        vulnerabilities = []
        after_cursor = None
        total_collected = 0
        page_num = 1
        
        while True:
            url = f"{self.base_url}/advisories"
            
            params = {
                'published': f">={start_dt.strftime('%Y-%m-%d')}",
                'per_page': min(per_page, 100),
                'sort': 'published',
                'direction': 'desc',
                'type': 'reviewed'
            }
            
            # 使用cursor-based pagination而不是page-based
            if after_cursor:
                params['after'] = after_cursor
            
            success, advisories, should_break, next_cursor = self._make_api_request_with_cursor(url, params, page_num)
            if not success or should_break:
                break
                
            # 处理当前页数据
            current_page_count = len(advisories)
            total_collected += current_page_count
            logger.info(f"已采集 {current_page_count} 条数据，累计 {total_collected} 条")
            
            # 记录保存统计
            new_saved_count = 0
            skipped_existing_count = 0
            
            # 解析并保存当前页的数据
            for advisory in advisories:
                try:
                    # 检查发布时间是否在范围内
                    published_at = datetime.fromisoformat(advisory['published_at'].replace('Z', '+00:00'))
                    
                    if published_at < start_dt:
                        continue
                    if end_dt and published_at > end_dt:
                        continue
                        
                    # 解析漏洞数据
                    vuln_data = self._parse_advisory(advisory)
                    if vuln_data:
                        vulnerabilities.append(vuln_data)
                        
                        # 立即保存到文件
                        if hasattr(self, 'file_storage') and self.file_storage:
                            ghsa_id = advisory.get('ghsa_id')
                            saved = self.file_storage.save_github_data_incremental(
                                ghsa_id=ghsa_id,
                                data=advisory,
                                published_date=published_at
                            )
                            if saved:
                                new_saved_count += 1
                            else:
                                skipped_existing_count += 1
                        
                except Exception as e:
                    logger.error(f"解析advisory失败: {e}, 数据: {advisory.get('ghsa_id', 'unknown')}")
                    continue
            
            # 显示保存统计信息
            if hasattr(self, 'file_storage') and self.file_storage:
                if new_saved_count > 0:
                    logger.info(f"新保存 {new_saved_count} 条数据到文件")
                if skipped_existing_count > 0:
                    logger.info(f"跳过 {skipped_existing_count} 条已存在的数据")
            
            # 检查是否还有更多页
            if not next_cursor:
                logger.info("已到达最后一页")
                break
                
            after_cursor = next_cursor
            page_num += 1
            time.sleep(0.1)  # 遵循GitHub API速率限制
            
        return vulnerabilities
    
    def _collect_all_data_in_batches(self, per_page: int = 100, **kwargs) -> List[VulnerabilityData]:
        """分批采集所有历史数据"""
        logger.info("开始分批采集所有历史数据")
        vulnerabilities = []
        
        # 按年份分批采集，从当前年份往回采集至2017年（GitHub Security Advisories开始时间）
        current_year = datetime.now().year
        start_year = 2017  # GitHub Security Advisories开始的年份
        
        for year in range(current_year, start_year - 1, -1):
            logger.info(f"采集 {year} 年的数据")
            
            # 设置该年份的时间范围
            year_start = f"{year}-01-01"
            year_end = f"{year}-12-31"
            
            year_vulnerabilities = self._collect_year_data(year_start, year_end, per_page)
            vulnerabilities.extend(year_vulnerabilities)
            
            logger.info(f"{year} 年数据采集完成，共 {len(year_vulnerabilities)} 条")
            
        return vulnerabilities
    
    def _collect_year_data(self, start_date: str, end_date: str, per_page: int = 100) -> List[VulnerabilityData]:
        """采集指定年份的数据"""
        vulnerabilities = []
        after_cursor = None
        total_collected = 0
        page_num = 1
        
        while True:
            url = f"{self.base_url}/advisories"
            
            params = {
                'published': f"{start_date}..{end_date}",  # 使用日期范围
                'per_page': min(per_page, 100),
                'sort': 'published',
                'direction': 'desc',
                'type': 'reviewed'
            }
            
            # 使用cursor-based pagination而不是page-based
            if after_cursor:
                params['after'] = after_cursor
            
            success, advisories, should_break, next_cursor = self._make_api_request_with_cursor(url, params, page_num)
            if not success or should_break:
                break
                
            # 处理当前页数据
            current_page_count = len(advisories)
            total_collected += current_page_count
            logger.info(f"{start_date} - {end_date}: 已采集 {current_page_count} 条数据，累计 {total_collected} 条")
            
            # 记录保存统计
            new_saved_count = 0
            skipped_existing_count = 0
            
            # 解析并保存当前页的数据
            for advisory in advisories:
                try:
                    # 解析漏洞数据
                    vuln_data = self._parse_advisory(advisory)
                    if vuln_data:
                        vulnerabilities.append(vuln_data)
                        
                        # 立即保存到文件
                        if hasattr(self, 'file_storage') and self.file_storage:
                            ghsa_id = advisory.get('ghsa_id')
                            published_at = advisory.get('published_at', '')
                            published_date = None
                            if published_at:
                                published_date = datetime.fromisoformat(published_at.replace('Z', '+00:00'))
                            
                            saved = self.file_storage.save_github_data_incremental(
                                ghsa_id=ghsa_id,
                                data=advisory,
                                published_date=published_date
                            )
                            if saved:
                                new_saved_count += 1
                            else:
                                skipped_existing_count += 1
                        
                except Exception as e:
                    logger.error(f"解析advisory失败: {e}, 数据: {advisory.get('ghsa_id', 'unknown')}")
                    continue
            
            # 显示保存统计信息
            if hasattr(self, 'file_storage') and self.file_storage:
                if new_saved_count > 0:
                    logger.info(f"新保存 {new_saved_count} 条数据到文件")
                if skipped_existing_count > 0:
                    logger.info(f"跳过 {skipped_existing_count} 条已存在的数据")
            
            # 检查是否还有更多页
            if not next_cursor:
                logger.info(f"{start_date} - {end_date}: 已到达最后一页")
                break
                
            after_cursor = next_cursor
            page_num += 1
            time.sleep(0.1)  # 遵循GitHub API速率限制
            
        return vulnerabilities
    
    def _make_api_request(self, url: str, params: dict, page: int) -> tuple:
        """统一的API请求处理方法
        
        Returns:
            tuple: (success: bool, advisories: list, should_break: bool)
        """
        headers = self._get_auth_headers()
        headers.update({
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        })
        
        try:
            logger.info(f"请求GitHub Advisories数据，页码={page}")
            
            # 记录API请求开始时间
            request_start_time = datetime.now()
            
            response = self.http_client.get(url, params=params, headers=headers)
            
            # 计算响应时间
            response_time = (datetime.now() - request_start_time).total_seconds()
            
            # 记录API请求日志
            logger.log_api_request(
                method="GET",
                url=url,
                status_code=response.status_code,
                response_time=response_time,
                request_data={'params': params},
                error=None if response.status_code == 200 else f"HTTP {response.status_code}"
            )
            
            if response.status_code != 200:
                if response.status_code == 403:
                    logger.warning("GitHub API速率限制或权限不足，停止采集")
                    return False, [], True
                elif response.status_code == 422:
                    logger.warning("请求参数验证失败，停止采集")
                    return False, [], True
                else:
                    error_msg = f"HTTP错误 {response.status_code}: {response.text[:200]}"
                    self._handle_error(Exception(error_msg), f"请求GitHub API失败，页码={page}")
                    return False, [], True
            
            advisories = response.json()
            
            if not advisories:
                logger.info("没有更多数据")
                return True, [], True
            
            return True, advisories, False
            
        except Exception as e:
            self._handle_error(e, f"采集GitHub数据失败，页码={page}")
            return False, [], True
    
    def _make_api_request_with_cursor(self, url: str, params: dict, page_num: int):
        """
        使用cursor-based pagination的API请求
        返回: (success, data, should_break, next_cursor)
        """
        headers = self._get_auth_headers()
        headers.update({
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        })
        
        try:
            logger.info(f"请求GitHub Advisories数据（cursor-based），页码={page_num}")
            
            # 记录API请求开始时间
            request_start_time = datetime.now()
            
            response = self.http_client.get(url, params=params, headers=headers)
            
            # 计算响应时间
            response_time = (datetime.now() - request_start_time).total_seconds()
            
            # 记录API请求日志
            logger.log_api_request(
                method="GET",
                url=url,
                status_code=response.status_code,
                response_time=response_time,
                request_data={'params': params},
                error=None if response.status_code == 200 else f"HTTP {response.status_code}"
            )
            
            if response.status_code != 200:
                if response.status_code == 403:
                    logger.warning("GitHub API速率限制或权限不足，停止采集")
                    return False, [], True, None
                elif response.status_code == 422:
                    logger.warning("请求参数验证失败，停止采集")
                    return False, [], True, None
                else:
                    error_msg = f"HTTP错误 {response.status_code}: {response.text[:200]}"
                    self._handle_error(Exception(error_msg), f"请求GitHub API失败，页码={page_num}")
                    return False, [], True, None
            
            advisories = response.json()
            
            if not advisories:
                logger.info("没有更多数据")
                return True, [], True, None
            
            # 解析Link header中的next cursor
            next_cursor = None
            link_header = response.headers.get('Link', '')
            if link_header:
                # 解析Link header: <url?after=cursor>; rel="next"
                import re
                next_match = re.search(r'<[^>]*[?&]after=([^&>]+)[^>]*>;\s*rel="next"', link_header)
                if next_match:
                    next_cursor = next_match.group(1)
                    logger.debug(f"找到下一页cursor: {next_cursor}")
                else:
                    logger.info("没有下一页cursor，已到达最后一页")
            
            logger.info(f"成功获取 {len(advisories)} 条数据，next_cursor: {'有' if next_cursor else '无'}")
            
            return True, advisories, False, next_cursor
            
        except Exception as e:
            self._handle_error(e, f"采集GitHub数据失败，页码={page_num}")
            return False, [], True, None
    
    def _parse_advisory(self, advisory: Dict[str, Any]) -> Optional[VulnerabilityData]:
        """解析GitHub Security Advisory数据的通用方法"""
        return self._parse_github_advisory(advisory)
    
    def _collect_graphql_api(self, start_dt: datetime, end_dt: datetime, 
                           per_page: int = 100, **kwargs) -> List[VulnerabilityData]:
        """
        通过GraphQL API采集GitHub Security Advisories数据
        
        Args:
            start_dt: 开始时间
            end_dt: 结束时间
            per_page: 每页数量
        """
        logger.info("使用GraphQL API采集GitHub数据")
        
        if not self.token:
            logger.warning("GraphQL API需要认证token，跳过采集")
            return []
        
        vulnerabilities = []
        after_cursor = None
        total_collected = 0
        
        while True:
            query = self._build_graphql_query(
                start_date=start_dt.strftime('%Y-%m-%d'),
                end_date=end_dt.strftime('%Y-%m-%d'),
                first=per_page,
                after=after_cursor
            )
            
            headers = self._get_auth_headers()
            headers['Content-Type'] = 'application/json'
            
            payload = {'query': query}
            
            try:
                logger.info(f"请求GitHub GraphQL API，after_cursor={after_cursor}")
                
                # 记录API请求开始时间
                request_start_time = datetime.now()
                
                response = self.http_client.post(
                    self.graphql_url, 
                    json=payload, 
                    headers=headers
                )
                
                # 计算响应时间
                response_time = (datetime.now() - request_start_time).total_seconds()
                
                # 记录API请求日志
                logger.log_api_request(
                    method="POST",
                    url=self.graphql_url,
                    status_code=response.status_code,
                    response_time=response_time,
                    request_data={'query_length': len(query)},
                    error=None if response.status_code == 200 else f"HTTP {response.status_code}"
                )
                
                if response.status_code != 200:
                    error_msg = f"HTTP错误 {response.status_code}: {response.text[:200]}"
                    self._handle_error(Exception(error_msg), "请求GitHub GraphQL API失败")
                    break
                
                data = response.json()
                
                if 'errors' in data:
                    error_msg = f"GraphQL错误: {data['errors']}"
                    self._handle_error(Exception(error_msg), "GraphQL查询失败")
                    break
                
                security_advisories = data.get('data', {}).get('securityAdvisories', {})
                edges = security_advisories.get('edges', [])
                
                if not edges:
                    logger.info("没有更多数据")
                    break
                
                for edge in edges:
                    try:
                        advisory = edge.get('node', {})
                        vuln = self._parse_graphql_advisory(advisory)
                        if vuln:
                            vulnerabilities.append(vuln)
                            total_collected += 1
                    except Exception as e:
                        self._handle_error(e, f"解析GraphQL Advisory失败: {advisory.get('ghsaId', 'unknown')}")
                
                logger.info(f"已采集 {len(edges)} 条数据，累计 {total_collected} 条")
                
                # 检查是否还有更多页
                page_info = security_advisories.get('pageInfo', {})
                if not page_info.get('hasNextPage', False):
                    break
                
                after_cursor = page_info.get('endCursor')
                
                # 遵循GitHub API速率限制
                time.sleep(0.1)
                
            except Exception as e:
                self._handle_error(e, "请求GitHub GraphQL API失败")
                break
        
        return vulnerabilities
    
    def _collect_advisory_database(self, start_dt: datetime, end_dt: datetime, **kwargs) -> List[VulnerabilityData]:
        """
        通过克隆GitHub Advisory Database仓库采集数据
        
        Args:
            start_dt: 开始时间
            end_dt: 结束时间
        """
        logger.info("使用Advisory Database采集GitHub数据")
        vulnerabilities = []
        
        try:
            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                repo_path = Path(temp_dir) / "advisory-database"
                
                # 克隆仓库（shallow clone以提高性能）
                logger.info(f"正在克隆Advisory Database到 {repo_path}")
                clone_cmd = [
                    "git", "clone", "--depth", "1", 
                    self.advisory_repo_url, str(repo_path)
                ]
                
                result = subprocess.run(
                    clone_cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=300  # 5分钟超时
                )
                
                if result.returncode != 0:
                    raise Exception(f"克隆仓库失败: {result.stderr}")
                
                logger.info("仓库克隆完成，开始解析数据")
                
                # 解析advisory文件
                advisories_path = repo_path / "advisories" / "github_reviewed"
                
                if not advisories_path.exists():
                    logger.warning(f"Advisory目录不存在: {advisories_path}")
                    return []
                
                total_files = 0
                processed_files = 0
                
                # 遍历所有.json文件
                for json_file in advisories_path.rglob("*.json"):
                    total_files += 1
                    
                    try:
                        with open(json_file, 'r', encoding='utf-8') as f:
                            advisory_data = json.load(f)
                        
                        # 检查发布时间是否在范围内
                        published_at = advisory_data.get('published', '')
                        if published_at:
                            published_date = datetime.fromisoformat(published_at.replace('Z', '+00:00'))
                            if not (start_dt <= published_date <= end_dt):
                                continue
                        
                        vuln = self._parse_database_advisory(advisory_data, json_file)
                        if vuln:
                            vulnerabilities.append(vuln)
                            processed_files += 1
                            
                    except Exception as e:
                        self._handle_error(e, f"解析Advisory文件失败: {json_file}")
                
                logger.info(f"数据库采集完成，处理文件 {processed_files}/{total_files}")
                
        except subprocess.TimeoutExpired:
            logger.error("克隆仓库超时")
        except Exception as e:
            self._handle_error(e, "Advisory Database采集失败")
        
        return vulnerabilities
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """获取认证头"""
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'ThreatSync/1.0'
        }
        
        if self.token:
            headers['Authorization'] = f'token {self.token}'
        
        return headers
    
    def _build_graphql_query(self, start_date: str, end_date: str, 
                           first: int = 100, after: str = None) -> str:
        """构建GraphQL查询"""
        after_clause = f', after: "{after}"' if after else ''
        
        query = f'''
        query {{
          securityAdvisories(
            first: {first}
            {after_clause}
            publishedSince: "{start_date}T00:00:00Z"
            updatedSince: "{start_date}T00:00:00Z"
            orderBy: {{field: PUBLISHED_AT, direction: DESC}}
          ) {{
            pageInfo {{
              hasNextPage
              endCursor
            }}
            edges {{
              node {{
                ghsaId
                summary
                description
                severity
                publishedAt
                updatedAt
                withdrawnAt
                permalink
                references {{
                  url
                }}
                identifiers {{
                  type
                  value
                }}
                cwes(first: 10) {{
                  nodes {{
                    cweId
                    name
                    description
                  }}
                }}
                vulnerabilities(first: 50) {{
                  nodes {{
                    package {{
                      ecosystem
                      name
                    }}
                    vulnerableVersionRange
                    firstPatchedVersion {{
                      identifier
                    }}
                  }}
                }}
              }}
            }}
          }}
        }}
        '''
        
        return query
    
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
        if cvss and isinstance(cvss, dict):
            base_score = cvss.get('score')
            if base_score is not None and isinstance(base_score, (int, float)) and base_score > 0:
                score = CVSSScore(
                    version="3.1",
                    base_score=float(base_score),
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
            if isinstance(ref, dict):
                url = ref.get('url', '')
                if url:
                    references.append(Reference(
                        url=url,
                        title=ref.get('title', ''),
                        source='GitHub'
                    ))
            elif isinstance(ref, str):
                # 有时references可能是字符串列表
                if ref:
                    references.append(Reference(
                        url=ref,
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
    
    def _parse_github_severity(self, severity: str) -> SeverityLevel:
        """解析GitHub严重性等级"""
        severity_map = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'moderate': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW
        }
        return severity_map.get(severity.lower(), SeverityLevel.UNKNOWN)
    
    def _parse_graphql_advisory(self, advisory: Dict[str, Any]) -> Optional[VulnerabilityData]:
        """解析GraphQL API返回的GitHub Security Advisory数据"""
        ghsa_id = advisory.get('ghsaId', '')
        if not ghsa_id:
            return None
        
        # 基本信息
        title = advisory.get('summary', '')
        description = advisory.get('description', '')
        
        # 时间信息
        published_date = datetime.fromisoformat(
            advisory.get('publishedAt', '').replace('Z', '+00:00')
        )
        
        updated_date = None
        if advisory.get('updatedAt'):
            updated_date = datetime.fromisoformat(
                advisory.get('updatedAt', '').replace('Z', '+00:00')
            )
        
        # CVSS评分（GraphQL API可能不直接提供CVSS详情）
        cvss_scores = []
        severity = self._parse_github_severity(advisory.get('severity', 'unknown'))
        
        # 弱点信息
        weaknesses = []
        cwes = advisory.get('cwes', {}).get('nodes', [])
        for cwe in cwes:
            if cwe:
                weaknesses.append(Weakness(
                    cwe_id=cwe.get('cweId', ''),
                    name=cwe.get('name', ''),
                    description=cwe.get('description', '')
                ))
        
        # 参考链接
        references = []
        for ref in advisory.get('references', []):
            url = ref.get('url', '')
            if url:
                references.append(Reference(
                    url=url,
                    source='GitHub',
                    tags=['official']
                ))
        
        # 添加permalink
        permalink = advisory.get('permalink', '')
        if permalink:
            references.append(Reference(
                url=permalink,
                title=title,
                source='GitHub',
                tags=['official', 'permalink']
            ))
        
        # 受影响的产品
        affected_products = []
        vulnerabilities = advisory.get('vulnerabilities', {}).get('nodes', [])
        for vuln in vulnerabilities:
            package = vuln.get('package', {})
            if package:
                ecosystem = package.get('ecosystem', '')
                name = package.get('name', '')
                version_range = vuln.get('vulnerableVersionRange', '')
                
                if version_range:
                    affected_products.append(AffectedProduct(
                        vendor=ecosystem,
                        product=name,
                        version_affected=version_range
                    ))
        
        # 提取CVE ID（如果有）
        cve_id = None
        identifiers = advisory.get('identifiers', [])
        for identifier in identifiers:
            if identifier.get('type') == 'CVE':
                cve_id = identifier.get('value')
                break
        
        return VulnerabilityData(
            id=ghsa_id,
            cve_id=cve_id,
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
    
    def _parse_database_advisory(self, advisory: Dict[str, Any], file_path: Path) -> Optional[VulnerabilityData]:
        """解析Advisory Database中的JSON文件数据"""
        # 从文件路径或内容中获取ID
        ghsa_id = advisory.get('id', '') or advisory.get('aliases', [{}])[0] if advisory.get('aliases') else ''
        
        if not ghsa_id:
            # 尝试从文件名获取ID
            ghsa_id = file_path.stem
        
        # 基本信息
        title = advisory.get('summary', '')
        description = advisory.get('details', '')
        
        # 时间信息
        published_date = None
        if advisory.get('published'):
            published_date = datetime.fromisoformat(
                advisory.get('published', '').replace('Z', '+00:00')
            )
        
        modified_date = None
        if advisory.get('modified'):
            modified_date = datetime.fromisoformat(
                advisory.get('modified', '').replace('Z', '+00:00')
            )
        
        # 如果没有发布时间，跳过
        if not published_date:
            return None
        
        # 严重性等级
        severity = SeverityLevel.UNKNOWN
        database_severity = advisory.get('database_specific', {}).get('severity', '')
        if database_severity:
            severity = self._parse_github_severity(database_severity)
        
        # CVSS评分
        cvss_scores = []
        # Database format可能包含CVSS信息
        
        # 弱点信息
        weaknesses = []
        # Database format可能不直接包含CWE信息
        
        # 参考链接
        references = []
        for ref in advisory.get('references', []):
            if isinstance(ref, dict):
                url = ref.get('url', '')
                ref_type = ref.get('type', '')
            else:
                url = ref
                ref_type = ''
            
            if url:
                references.append(Reference(
                    url=url,
                    source='GitHub Advisory Database',
                    tags=[ref_type] if ref_type else []
                ))
        
        # 受影响的产品
        affected_products = []
        for affected in advisory.get('affected', []):
            package = affected.get('package', {})
            if package:
                ecosystem = package.get('ecosystem', '')
                name = package.get('name', '')
                
                # 处理版本范围
                ranges = affected.get('ranges', [])
                for range_info in ranges:
                    events = range_info.get('events', [])
                    version_affected = "unknown"
                    
                    # 简化版本范围处理
                    for event in events:
                        if 'introduced' in event:
                            version_affected = f">= {event['introduced']}"
                        elif 'fixed' in event:
                            version_affected += f", < {event['fixed']}"
                    
                    affected_products.append(AffectedProduct(
                        vendor=ecosystem,
                        product=name,
                        version_affected=version_affected
                    ))
        
        # 提取CVE ID
        cve_id = None
        aliases = advisory.get('aliases', [])
        for alias in aliases:
            if alias.startswith('CVE-'):
                cve_id = alias
                break
        
        return VulnerabilityData(
            id=ghsa_id,
            cve_id=cve_id,
            title=title,
            description=description,
            status=VulnerabilityStatus.PUBLISHED,
            severity=severity,
            source=DataSource.GITHUB,
            published_date=published_date,
            modified_date=modified_date,
            cvss_scores=cvss_scores,
            weaknesses=weaknesses,
            affected_products=affected_products,
            references=references,
            raw_data=advisory
        )
