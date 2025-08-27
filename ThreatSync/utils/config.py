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
            # 优先使用本地配置文件
            config_dir = Path(__file__).parent.parent.parent / "config"
            self.local_config_path = config_dir / "config.local.yaml"
            self.example_config_path = config_dir / "config.example.yaml"
            # 向后兼容，如果指定了config_path则使用指定路径
            self.config_path = config_dir / "config.yaml" if config_path is None else Path(config_path)
        else:
            self.config_path = Path(config_path)
            self.local_config_path = self.config_path.parent / "config.local.yaml"
            self.example_config_path = self.config_path.parent / "config.example.yaml"
        
        self._config = None
        self.load_config()
    
    def load_config(self):
        """加载配置文件（优先使用本地配置）"""
        try:
            # 优先使用本地配置文件
            if self.local_config_path.exists():
                with open(self.local_config_path, 'r', encoding='utf-8') as f:
                    self._config = yaml.safe_load(f)
                    if self._config is None:
                        self._config = {}
                print(f"已加载本地配置: {self.local_config_path}")
            
            # 如果本地配置不存在，使用示例配置作为基础
            elif self.example_config_path.exists():
                with open(self.example_config_path, 'r', encoding='utf-8') as f:
                    self._config = yaml.safe_load(f)
                    if self._config is None:
                        self._config = {}
                print(f"已加载示例配置: {self.example_config_path}")
            
            # 如果都不存在，尝试加载旧的config.yaml（向后兼容）
            elif self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self._config = yaml.safe_load(f)
                    if self._config is None:
                        self._config = {}
                print(f"已加载配置文件: {self.config_path}")
            
            # 如果所有配置文件都不存在，使用默认配置
            else:
                print("未找到配置文件，使用默认配置")
                self._config = self._get_default_config()
            
            # 应用环境变量覆盖
            self._apply_env_overrides()
            
        except yaml.YAMLError as e:
            print(f"配置文件解析错误: {e}")
            self._config = self._get_default_config()
        except Exception as e:
            print(f"加载配置文件时发生错误: {e}")
            self._config = self._get_default_config()
    
    def _merge_configs(self, base_config: dict, override_config: dict):
        """递归合并配置"""
        if base_config is None:
            return override_config
        if override_config is None:
            return base_config
            
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
                    'base_url': 'https://api.github.com',
                    'collection': {
                        'default_method': 'rest',
                        'supported_methods': ['rest', 'graphql', 'database'],
                        'methods': {
                            'rest': {
                                'per_page': 100,
                                'max_pages': 100
                            },
                            'graphql': {
                                'per_page': 100,
                                'max_pages': 50
                            },
                            'database': {
                                'repo_url': 'https://github.com/github/advisory-database.git',
                                'clone_timeout': 300,
                                'shallow_clone': True
                            }
                        }
                    }
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
