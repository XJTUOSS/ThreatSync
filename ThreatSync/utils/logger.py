"""
日志工具
"""
import logging
import logging.handlers
import os
import sys
import traceback
import json
from pathlib import Path
from typing import Optional, Dict, Any, Union
from datetime import datetime


class ThreatSyncLogger:
    """增强的日志管理器"""
    
    def __init__(self, name: str = "ThreatSync", level: str = "INFO", 
                 log_file: Optional[str] = None, max_size: str = "10MB", 
                 backup_count: int = 5, enable_file_rotation: bool = True,
                 enable_error_file: bool = True):
        """
        初始化日志管理器
        
        Args:
            name: 日志器名称
            level: 日志级别
            log_file: 日志文件路径
            max_size: 单个日志文件最大大小
            backup_count: 保留的日志文件数量
            enable_file_rotation: 是否启用文件轮转
            enable_error_file: 是否启用单独的错误日志文件
        """
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.enable_error_file = enable_error_file
        
        # 避免重复添加处理器
        if not self.logger.handlers:
            self._setup_handlers(log_file, max_size, backup_count, enable_file_rotation)
    
    def _parse_size(self, size_str: str) -> int:
        """解析大小字符串为字节数"""
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def _setup_handlers(self, log_file: Optional[str], max_size: str, 
                       backup_count: int, enable_file_rotation: bool):
        """设置日志处理器"""
        # 详细格式化器
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # 简单格式化器（控制台用）
        simple_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # 控制台处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(simple_formatter)
        console_handler.setLevel(logging.INFO)  # 控制台只显示INFO及以上级别
        self.logger.addHandler(console_handler)
        
        # 文件处理器
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            if enable_file_rotation:
                # 使用轮转文件处理器
                max_bytes = self._parse_size(max_size)
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file, 
                    maxBytes=max_bytes, 
                    backupCount=backup_count,
                    encoding='utf-8'
                )
            else:
                # 普通文件处理器
                file_handler = logging.FileHandler(log_file, encoding='utf-8')
            
            file_handler.setFormatter(detailed_formatter)
            file_handler.setLevel(logging.DEBUG)  # 文件记录所有级别
            self.logger.addHandler(file_handler)
            
            # 单独的错误日志文件
            if self.enable_error_file:
                error_log_file = log_path.parent / f"{log_path.stem}_error{log_path.suffix}"
                
                if enable_file_rotation:
                    max_bytes = self._parse_size(max_size)
                    error_handler = logging.handlers.RotatingFileHandler(
                        str(error_log_file),
                        maxBytes=max_bytes,
                        backupCount=backup_count,
                        encoding='utf-8'
                    )
                else:
                    error_handler = logging.FileHandler(str(error_log_file), encoding='utf-8')
                
                error_handler.setFormatter(detailed_formatter)
                error_handler.setLevel(logging.ERROR)  # 只记录错误和严重错误
                self.logger.addHandler(error_handler)
    
    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """调试日志"""
        if extra:
            self.logger.debug(f"{message} | Extra: {json.dumps(extra, ensure_ascii=False)}")
        else:
            self.logger.debug(message)
    
    def info(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """信息日志"""
        if extra:
            self.logger.info(f"{message} | Extra: {json.dumps(extra, ensure_ascii=False)}")
        else:
            self.logger.info(message)
    
    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """警告日志"""
        if extra:
            self.logger.warning(f"{message} | Extra: {json.dumps(extra, ensure_ascii=False)}")
        else:
            self.logger.warning(message)
    
    def error(self, message: str, exception: Optional[Exception] = None, 
              extra: Optional[Dict[str, Any]] = None, include_trace: bool = True):
        """
        错误日志
        
        Args:
            message: 错误消息
            exception: 异常对象
            extra: 额外信息
            include_trace: 是否包含堆栈追踪
        """
        error_msg = message
        
        if exception:
            error_msg += f" | Exception: {type(exception).__name__}: {str(exception)}"
        
        if extra:
            error_msg += f" | Extra: {json.dumps(extra, ensure_ascii=False)}"
        
        if include_trace and (exception or sys.exc_info()[0]):
            if exception:
                # 如果提供了异常对象，获取其堆栈
                trace_lines = traceback.format_exception(type(exception), exception, exception.__traceback__)
            else:
                # 否则获取当前堆栈
                trace_lines = traceback.format_exception(*sys.exc_info())
            
            trace_str = ''.join(trace_lines)
            error_msg += f"\n堆栈追踪:\n{trace_str}"
        
        self.logger.error(error_msg)
    
    def critical(self, message: str, exception: Optional[Exception] = None, 
                 extra: Optional[Dict[str, Any]] = None, include_trace: bool = True):
        """
        严重错误日志
        
        Args:
            message: 错误消息
            exception: 异常对象
            extra: 额外信息
            include_trace: 是否包含堆栈追踪
        """
        error_msg = message
        
        if exception:
            error_msg += f" | Exception: {type(exception).__name__}: {str(exception)}"
        
        if extra:
            error_msg += f" | Extra: {json.dumps(extra, ensure_ascii=False)}"
        
        if include_trace and (exception or sys.exc_info()[0]):
            if exception:
                # 如果提供了异常对象，获取其堆栈
                trace_lines = traceback.format_exception(type(exception), exception, exception.__traceback__)
            else:
                # 否则获取当前堆栈
                trace_lines = traceback.format_exception(*sys.exc_info())
            
            trace_str = ''.join(trace_lines)
            error_msg += f"\n堆栈追踪:\n{trace_str}"
        
        self.logger.critical(error_msg)
    
    def log_exception(self, message: str = "发生未处理异常", 
                     exception: Optional[Exception] = None,
                     extra: Optional[Dict[str, Any]] = None):
        """
        记录异常的便捷方法
        
        Args:
            message: 自定义消息
            exception: 异常对象（如果不提供则自动获取当前异常）
            extra: 额外信息
        """
        if exception is None and sys.exc_info()[0] is not None:
            # 如果在异常处理块中调用，自动获取当前异常
            exception = sys.exc_info()[1]
        
        self.error(message, exception=exception, extra=extra, include_trace=True)
    
    def log_function_call(self, func_name: str, args: tuple = None, 
                         kwargs: dict = None, result: Any = None, 
                         duration: float = None):
        """
        记录函数调用信息
        
        Args:
            func_name: 函数名
            args: 位置参数
            kwargs: 关键字参数
            result: 返回结果
            duration: 执行时间（秒）
        """
        call_info = {
            'function': func_name,
            'timestamp': datetime.now().isoformat()
        }
        
        if args:
            call_info['args'] = str(args)
        
        if kwargs:
            call_info['kwargs'] = str(kwargs)
        
        if result is not None:
            call_info['result'] = str(result)[:200]  # 限制长度
        
        if duration is not None:
            call_info['duration_seconds'] = duration
        
        self.debug(f"函数调用: {func_name}", extra=call_info)
    
    def log_api_request(self, method: str, url: str, status_code: int = None,
                       response_time: float = None, request_data: dict = None,
                       response_data: dict = None, error: str = None):
        """
        记录API请求信息
        
        Args:
            method: HTTP方法
            url: 请求URL
            status_code: 响应状态码
            response_time: 响应时间（秒）
            request_data: 请求数据
            response_data: 响应数据
            error: 错误信息
        """
        api_info = {
            'method': method,
            'url': url,
            'timestamp': datetime.now().isoformat()
        }
        
        if status_code:
            api_info['status_code'] = status_code
        
        if response_time:
            api_info['response_time_seconds'] = response_time
        
        if request_data:
            api_info['request_data'] = str(request_data)[:500]  # 限制长度
        
        if response_data:
            api_info['response_data'] = str(response_data)[:500]  # 限制长度
        
        if error:
            api_info['error'] = error
            self.error(f"API请求失败: {method} {url}", extra=api_info)
        else:
            self.info(f"API请求: {method} {url}", extra=api_info)
    
    def log_data_collection(self, source: str, collected_count: int, 
                           failed_count: int = 0, duration: float = None,
                           extra_info: dict = None):
        """
        记录数据采集信息
        
        Args:
            source: 数据源名称
            collected_count: 采集成功数量
            failed_count: 采集失败数量
            duration: 采集时间（秒）
            extra_info: 额外信息
        """
        collection_info = {
            'source': source,
            'collected_count': collected_count,
            'failed_count': failed_count,
            'total_count': collected_count + failed_count,
            'success_rate': collected_count / (collected_count + failed_count) if (collected_count + failed_count) > 0 else 0,
            'timestamp': datetime.now().isoformat()
        }
        
        if duration:
            collection_info['duration_seconds'] = duration
            collection_info['items_per_second'] = collected_count / duration if duration > 0 else 0
        
        if extra_info:
            collection_info.update(extra_info)
        
        self.info(f"数据采集完成: {source} - 成功:{collected_count}, 失败:{failed_count}", 
                 extra=collection_info)


# 向后兼容的Logger类
class Logger(ThreatSyncLogger):
    """向后兼容的Logger类"""
    pass


# 全局日志实例
logger = ThreatSyncLogger()
