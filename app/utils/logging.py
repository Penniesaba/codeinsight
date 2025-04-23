#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
日志工具模块
----------
提供统一的日志记录功能，包括上下文跟踪和性能监控
"""

import logging
import time
import functools
import traceback
import inspect
import sys
from contextlib import contextmanager

# 获取指定名称的日志记录器
def get_logger(name):
    """
    获取指定名称的日志记录器
    
    参数:
        name: 日志记录器名称，通常使用模块名称(__name__)
        
    返回:
        带有额外辅助方法的日志记录器
    """
    logger = logging.getLogger(name)
    
    # 添加额外的辅助方法
    logger.exception_with_traceback = lambda msg, *args, **kwargs: _log_with_traceback(logger, logging.ERROR, msg, *args, **kwargs)
    logger.error_with_traceback = lambda msg, *args, **kwargs: _log_with_traceback(logger, logging.ERROR, msg, *args, **kwargs)
    logger.critical_with_traceback = lambda msg, *args, **kwargs: _log_with_traceback(logger, logging.CRITICAL, msg, *args, **kwargs)
    
    return logger

def _log_with_traceback(logger, level, msg, *args, **kwargs):
    """添加完整的异常堆栈跟踪到日志"""
    exc_info = kwargs.pop('exc_info', True)
    stack_info = kwargs.pop('stack_info', True)
    
    # 获取异常堆栈信息
    if exc_info:
        if not isinstance(exc_info, tuple):
            exc_info = sys.exc_info()
    
    # 记录日志并添加堆栈信息
    kwargs['exc_info'] = exc_info
    kwargs['stack_info'] = stack_info
    logger.log(level, msg, *args, **kwargs)

@contextmanager
def log_context(logger, action, **context_vars):
    """
    日志上下文管理器，记录操作的开始、结束和执行时间
    
    参数:
        logger: 日志记录器
        action: 操作描述
        context_vars: 希望记录的上下文变量
    
    用法:
        with log_context(logger, '处理任务', task_id=123, file_path='/tmp/data.txt'):
            # 执行操作
            process_task(task_id)
    """
    start_time = time.time()
    
    # 记录开始信息
    context_str = ', '.join([f'{k}={v}' for k, v in context_vars.items()])
    logger.info(f"开始 {action} - {context_str}" if context_str else f"开始 {action}")
    
    try:
        yield  # 执行上下文内的代码
        
        # 记录成功完成的信息
        duration = time.time() - start_time
        logger.info(f"完成 {action} - 耗时 {duration:.3f}秒")
        
    except Exception as e:
        # 记录异常信息
        duration = time.time() - start_time
        logger.error(f"执行 {action} 失败 - 耗时 {duration:.3f}秒: {str(e)}", exc_info=True)
        raise  # 重新抛出异常

def log_function_call(level=logging.DEBUG):
    """
    装饰器: 记录函数调用，参数和返回值
    
    参数:
        level: 日志级别
        
    用法:
        @log_function_call()
        def process_data(data_id, user_name):
            # 函数实现
            return result
    """
    def decorator(func):
        # 获取函数所在模块的日志记录器
        logger = logging.getLogger(func.__module__)
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # 获取调用者信息
            caller_frame = inspect.currentframe().f_back
            caller_filename = caller_frame.f_code.co_filename
            caller_lineno = caller_frame.f_lineno
            caller_info = f"{caller_filename}:{caller_lineno}"
            
            # 格式化参数字符串（避免太长）
            args_str = str(args)[:100] + "..." if len(str(args)) > 100 else str(args)
            kwargs_str = str(kwargs)[:100] + "..." if len(str(kwargs)) > 100 else str(kwargs)
            
            # 记录函数调用信息
            func_name = f"{func.__module__}.{func.__name__}"
            logger.log(level, f"调用函数 {func_name}(args={args_str}, kwargs={kwargs_str}) - 来自 {caller_info}")
            
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                # 记录函数返回信息
                result_str = str(result)[:100] + "..." if len(str(result)) > 100 else str(result)
                logger.log(level, f"函数 {func_name} 返回 {result_str} - 耗时 {duration:.3f}秒")
                
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error(f"函数 {func_name} 抛出异常 {type(e).__name__}: {str(e)} - 耗时 {duration:.3f}秒", exc_info=True)
                raise
        
        return wrapper
    
    return decorator

# 简单使用示例
if __name__ == "__main__":
    # 获取日志记录器
    logger = get_logger(__name__)
    
    # 记录不同级别的日志
    logger.debug("这是一条调试日志")
    logger.info("这是一条信息日志")
    logger.warning("这是一条警告日志")
    logger.error("这是一条错误日志")
    
    # 使用上下文记录日志
    with log_context(logger, "示例操作", param1="value1", param2=123):
        logger.info("正在执行操作...")
        # 模拟一些耗时操作
        time.sleep(0.5)
    
    # 使用函数调用装饰器
    @log_function_call()
    def example_function(a, b):
        return a + b
    
    example_function(1, 2) 