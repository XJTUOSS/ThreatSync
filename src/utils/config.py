"""
配置管理工具
"""
import yaml
import os
from typing import Dict, Any
from pathlib import Path


class ConfigManager:
    """配置管理器 - 支持环境变量和本地配置文件"""
    
    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
        
        self.config_path = Path(config_path)
        self.local_config_path = self.config_path.parent / "config.local.yaml"
        self._config = None
        self.load_config()
    
    def load_config(self):
        """加载配置文件（支持本地覆盖和环境变量）"""
        try:
            # 加载主配置文件
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self._config = yaml.safe_load(f)
            
            # 如果存在本地配置文件，合并配置
            if self.local_config_path.exists():
                with open(self.local_config_path, 'r', encoding='utf-8') as f:
                    local_config = yaml.safe_load(f)
                    self._merge_configs(self._config, local_config)
            
            # 应用环境变量覆盖
            self._apply_env_overrides()
            
        except FileNotFoundError:
            print(f"配置文件未找到: {self.config_path}")
            self._config = self._get_default_config()
        except yaml.YAMLError as e:
            print(f"配置文件解析错误: {e}")
            self._config = self._get_default_config()
    
    def _merge_configs(self, base_config: dict, override_config: dict):
        """递归合并配置"""
        for key, value in override_config.items():
            if key in base_config and isinstance(base_config[key], dict) and isinstance(value, dict):
                self._merge_configs(base_config[key], value)
            else:
                base_config[key] = value
    
    def _apply_env_overrides(self):
        """应用环境变量覆盖"""
        # GitHub Token
        github_token = os.getenv('GITHUB_TOKEN')
        if github_token:
            self._config['apis']['github']['token'] = github_token
        
        # NVD API Key
        nvd_api_key = os.getenv('NVD_API_KEY')
        if nvd_api_key:
            self._config['apis']['nvd']['api_key'] = nvd_api_key
    
    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            'apis': {
                'github': {
                    'token': '',
                    'rate_limit': 5000,
                    'base_url': 'https://api.github.com'
                },
                'nvd': {
                    'api_key': '',
                    'base_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
                    'rate_limit': {
                        'requests_per_30s': 5,  # 无API Key的限制
                        'sleep_between_requests': 6
                    },
                    'pagination': {
                        'results_per_page': 2000,
                        'max_total_results': 50000
                    }
                },
                'osv': {
                    'base_url': 'https://api.osv.dev/v1'
                }
            },
            'http': {
                'timeout': 30,
                'max_retries': 3,
                'use_random_user_agent': True,
                'proxy': {
                    'enabled': False,
                    'http': '',
                    'https': ''
                }
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/threatsync.log',
                'max_size': '10MB',
                'backup_count': 5
            },
            'schedule': {
                'structured_interval': 2,
                'unstructured_interval': 12,
                'initial_collection': {
                    'days_back': 30,
                    'batch_size': 2000
                }
            },
            'storage': {
                'data_dir': 'data',
                'structured_data': {
                    'nvd': 'data/structured/nvd',
                    'github': 'data/structured/github',
                    'osv': 'data/structured/osv'
                },
                'unstructured_data': {
                    'cnvd': 'data/unstructured/cnvd'
                },
                'collection_results': 'data/collection_results',
                'file_organization': {
                    'group_by': 'daily',
                    'filename_format': '{source}_{date}_{timestamp}.json',
                    'compress_after_days': 30
                },
                'retention': {
                    'retention_days': 365,
                    'cleanup_interval': 24
                }
            }
        }
    
    def get(self, key: str, default=None):
        """获取配置值"""
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_database_config(self) -> Dict[str, Any]:
        """获取数据库配置（已废弃，保留兼容性）"""
        return {}
    
    def get_api_config(self, api_name: str) -> Dict[str, Any]:
        """获取API配置"""
        return self.get(f'apis.{api_name}', {})
    
    def get_http_config(self) -> Dict[str, Any]:
        """获取HTTP客户端配置"""
        return self.get('http', {})
    
    def get_crawler_config(self) -> Dict[str, Any]:
        """获取爬虫配置（兼容性方法，映射到http配置）"""
        return self.get_http_config()
    
    def get_logging_config(self) -> Dict[str, Any]:
        """获取日志配置"""
        return self.get('logging', {})
    
    def get_schedule_config(self) -> Dict[str, Any]:
        """获取调度配置"""
        return self.get('schedule', {})
    
    def get_storage_config(self) -> Dict[str, Any]:
        """获取存储配置"""
        return self.get('storage', {})
