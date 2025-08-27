"""
基础采集器抽象类
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from datetime import datetime
import traceback

from ..models.vulnerability import VulnerabilityData, CollectionResult, DataSource
from ..utils import ConfigManager, logger
from ..utils.file_storage import FileStorage


class BaseCollector(ABC):
    """基础采集器抽象类"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.source = self._get_source()
        self.collected_data: List[VulnerabilityData] = []
        self.errors: List[str] = []
        self.file_storage = FileStorage(config_manager)
    
    @abstractmethod
    def _get_source(self) -> DataSource:
        """获取数据源类型"""
        pass
    
    @abstractmethod
    def collect(self, **kwargs) -> List[VulnerabilityData]:
        """采集数据的具体实现"""
        pass
    
    def run_collection(self, **kwargs) -> CollectionResult:
        """运行采集任务"""
        start_time = datetime.now()
        logger.info(f"开始采集 {self.source.value} 数据")
        
        try:
            # 记录采集参数
            logger.debug(f"采集参数: {kwargs}", extra={'source': self.source.value, 'params': kwargs})
            
            self.collected_data = self.collect(**kwargs)
            successful = len(self.collected_data)
            failed = len(self.errors)
            total = successful + failed
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # 使用新的数据采集日志方法
            logger.log_data_collection(
                source=self.source.value,
                collected_count=successful,
                failed_count=failed,
                duration=duration,
                extra_info={'errors': self.errors if self.errors else None}
            )
            
            result = CollectionResult(
                source=self.source,
                total_collected=total,
                successful=successful,
                failed=failed,
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                errors=self.errors
            )
            
            # 保存采集的数据到文件
            if self.collected_data:
                try:
                    # 转换为可序列化的格式
                    serializable_data = [vuln.to_dict() for vuln in self.collected_data]
                    
                    # 保存结构化数据
                    file_path = self.file_storage.save_structured_data(
                        source=self.source.value.lower(),
                        data=serializable_data,
                        metadata={
                            'collection_params': kwargs,
                            'collection_result': result.to_dict()
                        }
                    )
                    
                    # 保存采集结果摘要
                    self.file_storage.save_collection_result(
                        source=self.source.value.lower(),
                        result_data=result.to_dict()
                    )
                    
                    logger.info(f"数据已保存到文件: {file_path}")
                    
                except Exception as e:
                    logger.error(f"保存数据失败", exception=e, extra={
                        'source': self.source.value,
                        'data_count': len(self.collected_data),
                        'file_path': str(file_path) if 'file_path' in locals() else 'unknown'
                    })
            
            return result
            
        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # 使用增强的错误日志
            logger.error(
                f"采集失败: {self.source.value}",
                exception=e,
                extra={
                    'source': self.source.value,
                    'duration': duration,
                    'params': kwargs,
                    'collected_before_error': len(self.collected_data)
                }
            )
            
            return CollectionResult(
                source=self.source,
                total_collected=0,
                successful=0,
                failed=1,
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                errors=[f"采集失败: {str(e)}"]
            )
    
    def _handle_error(self, error: Exception, context: str = ""):
        """处理错误"""
        error_msg = f"{context}: {str(error)}" if context else str(error)
        self.errors.append(error_msg)
        
        # 使用增强的错误日志
        logger.error(
            f"{self.source.value} - {error_msg}",
            exception=error,
            extra={
                'source': self.source.value,
                'context': context,
                'error_count': len(self.errors)
            }
        )
    
    def _parse_severity(self, score: float) -> str:
        """根据分数解析严重性等级"""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        else:
            return "UNKNOWN"
