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
            self.collected_data = self.collect(**kwargs)
            successful = len(self.collected_data)
            failed = len(self.errors)
            total = successful + failed
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
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
                    logger.error(f"保存数据失败: {e}")
            
            logger.info(f"采集完成 {self.source.value}: 成功={successful}, 失败={failed}, 耗时={duration:.2f}秒")
            return result
            
        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            error_msg = f"采集失败: {str(e)}"
            logger.error(f"{self.source.value} {error_msg}")
            logger.error(traceback.format_exc())
            
            return CollectionResult(
                source=self.source,
                total_collected=0,
                successful=0,
                failed=1,
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                errors=[error_msg]
            )
    
    def _handle_error(self, error: Exception, context: str = ""):
        """处理错误"""
        error_msg = f"{context}: {str(error)}" if context else str(error)
        self.errors.append(error_msg)
        logger.error(f"{self.source.value} - {error_msg}")
    
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
