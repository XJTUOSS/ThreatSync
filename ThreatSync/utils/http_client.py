"""
HTTP客户端工具
"""
import requests
import random
import time
from typing import Dict, Any, Optional
from urllib.parse import urljoin
from ..utils import logger


class RequestsUtil:
    """HTTP请求工具类"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get('timeout', 30)
        self.max_retries = config.get('max_retries', 3)
        self.use_random_user_agent = config.get('use_random_user_agent', True)
        
        # 代理配置
        proxy_config = config.get('proxy', {})
        self.proxies = None
        if proxy_config.get('enabled', False):
            self.proxies = {
                'http': proxy_config.get('http', ''),
                'https': proxy_config.get('https', '')
            }
        
        # User-Agent列表
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
    
    def _get_headers(self, additional_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """获取请求头"""
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # 随机User-Agent
        if self.use_random_user_agent:
            headers['User-Agent'] = random.choice(self.user_agents)
        
        # 添加额外的头信息
        if additional_headers:
            headers.update(additional_headers)
        
        return headers
    
    def get(self, url: str, params: Optional[Dict[str, Any]] = None, 
            headers: Optional[Dict[str, str]] = None, **kwargs) -> requests.Response:
        """发送GET请求"""
        return self._request('GET', url, params=params, headers=headers, **kwargs)
    
    def post(self, url: str, data: Optional[Dict[str, Any]] = None, 
             json: Optional[Dict[str, Any]] = None,
             headers: Optional[Dict[str, str]] = None, **kwargs) -> requests.Response:
        """发送POST请求"""
        return self._request('POST', url, data=data, json=json, headers=headers, **kwargs)
    
    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """发送HTTP请求（带重试机制）"""
        headers = kwargs.pop('headers', None)
        request_headers = self._get_headers(headers)
        
        for attempt in range(self.max_retries + 1):
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    timeout=self.timeout,
                    proxies=self.proxies,
                    **kwargs
                )
                
                # 检查响应状态
                if response.status_code == 429:  # Rate limited
                    if attempt < self.max_retries:
                        wait_time = 2 ** attempt + random.uniform(0, 1)
                        logger.warning(f"速率限制，等待 {wait_time:.2f} 秒后重试")
                        time.sleep(wait_time)
                        continue
                
                return response
                
            except requests.exceptions.RequestException as e:
                if attempt < self.max_retries:
                    wait_time = 2 ** attempt + random.uniform(0, 1)
                    logger.warning(f"请求失败 (尝试 {attempt + 1}/{self.max_retries + 1}): {e}")
                    logger.warning(f"等待 {wait_time:.2f} 秒后重试")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"请求最终失败: {url} - {e}")
                    raise
        
        # 不应该到达这里
        raise Exception("请求重试耗尽")
