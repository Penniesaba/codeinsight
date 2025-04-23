# CodeInsight 日志系统

## 概述

CodeInsight项目使用了增强版的日志系统，支持以下功能：

- 在日志中显示文件名和行号信息，便于快速定位问题
- 日志文件自动旋转，防止单一日志文件过大
- 控制台日志着色，提高可读性
- 方便的日志上下文管理和函数调用记录
- 支持详细的异常堆栈跟踪

## 基本用法

### 获取日志记录器

在每个模块中推荐使用以下方式获取日志记录器：

```python
from app.utils.logging import get_logger

# 使用模块名作为日志记录器名称
logger = get_logger(__name__)
```

### 记录不同级别的日志

```python
# 调试信息（开发环境中使用）
logger.debug("这是调试信息")

# 一般信息
logger.info("处理任务完成")

# 警告信息
logger.warning("配置文件不完整，使用默认配置")

# 错误信息
logger.error("无法连接数据库")

# 严重错误
logger.critical("系统无法启动")
```

### 记录异常信息

```python
try:
    # 执行可能抛出异常的代码
    result = some_function()
except Exception as e:
    # 自动包含异常堆栈
    logger.exception(f"处理失败: {str(e)}")
    
    # 或使用增强版异常日志（包含更多上下文）
    logger.error_with_traceback(f"处理失败: {str(e)}")
```

## 高级功能

### 使用上下文管理器记录操作

上下文管理器会自动记录操作的开始和结束，以及执行时间：

```python
from app.utils.logging import log_context

with log_context(logger, "分析代码库", repo_url=url, language=lang):
    # 执行分析操作
    analyze_repository(repo_url, language)
```

日志输出示例：
```
2023-04-25 10:15:20 - app.analyzer - INFO - 开始 分析代码库 - repo_url=https://github.com/example/repo, language=python
2023-04-25 10:15:25 - app.analyzer - INFO - 完成 分析代码库 - 耗时 5.231秒
```

### 使用函数调用装饰器

自动记录函数的调用参数、返回值和执行时间：

```python
from app.utils.logging import log_function_call

@log_function_call()
def process_data(data_id, options=None):
    # 函数实现
    return result
```

日志输出示例：
```
2023-04-25 10:20:15 - app.processor - DEBUG - 调用函数 app.processor.process_data(args=(123,), kwargs={'options': {'verbose': True}}) - 来自 /home/user/project/app/routes.py:157
2023-04-25 10:20:16 - app.processor - DEBUG - 函数 app.processor.process_data 返回 {'status': 'success', 'count': 42} - 耗时 0.852秒
```

## 日志配置

日志系统在`run.py`中初始化，默认配置：

- 日志文件位置: `logs/app.log`
- 日志文件大小上限: 10MB，超过后自动旋转，保留5个历史文件
- 日志级别: 通过环境配置`LOG_LEVEL`控制，默认为`INFO`
- 控制台日志: 自动着色（在支持ANSI颜色的终端）

## 最佳实践

1. **使用正确的日志级别**
   - DEBUG: 详细的调试信息，仅在开发环境启用
   - INFO: 确认程序按预期运行的信息
   - WARNING: 表明有可能的问题，但程序仍在工作
   - ERROR: 错误事件，可能会影响功能但不会导致程序终止
   - CRITICAL: 严重错误，可能导致程序终止

2. **包含上下文信息**
   - 在日志中包含足够的上下文（如ID、URL等）
   - 使用结构化的日志格式，便于后期分析

3. **使用上下文管理器跟踪长时间操作**
   - 对于耗时操作，使用`log_context`记录开始和结束
   - 帮助识别性能瓶颈

4. **异常处理**
   - 总是记录异常信息
   - 使用`logger.exception`或`logger.error_with_traceback`保留堆栈信息

5. **敏感信息安全**
   - 不要在日志中包含密码、令牌等敏感信息
   - 如有必要，对敏感信息进行脱敏处理

## 示例

完整的日志使用示例可参考`app/utils/logging.py`文件末尾的示例代码。 