#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CodeInsight 应用程序入口
------------------------
这个脚本是应用程序的入口点，负责初始化并启动Web服务器。
"""

import os
import logging
import platform
from logging.handlers import RotatingFileHandler
from app import create_app
from config import config

# 获取环境配置
env = os.environ.get('FLASK_ENV', 'default')
app = create_app(config[env])

# 初始化必要的文件夹
def init_folders():
    """创建应用程序所需的文件夹结构"""
    folders = [
        app.config['CACHE_DIR'],
        app.config['LOG_DIR'],
        app.config['REPO_CACHE_DIR'],
        app.config['ANALYSIS_CACHE_DIR']
    ]
    
    for folder in folders:
        if not os.path.exists(folder):
            os.makedirs(folder)
            app.logger.info(f"创建文件夹: {folder}")

# 颜色常量定义（用于控制台日志着色）
COLORS = {
    'RESET': '\033[0m',
    'DEBUG': '\033[36m',    # 青色
    'INFO': '\033[32m',     # 绿色
    'WARNING': '\033[33m',  # 黄色
    'ERROR': '\033[31m',    # 红色
    'CRITICAL': '\033[41m', # 红底
}

# 自定义日志格式化器
class ColoredFormatter(logging.Formatter):
    """添加颜色的日志格式化器"""
    
    def __init__(self, fmt=None, datefmt=None, style='%', use_colors=True):
        super().__init__(fmt, datefmt, style)
        self.use_colors = use_colors and platform.system() != 'Windows'  # Windows控制台可能不支持ANSI颜色
    
    def format(self, record):
        # 在日志级别前后添加颜色代码
        levelname = record.levelname
        if self.use_colors and levelname in COLORS:
            colored_levelname = f"{COLORS[levelname]}{levelname}{COLORS['RESET']}"
            record.levelname = colored_levelname
        
        return super().format(record)

# 配置日志
def setup_logging():
    """配置应用日志"""
    log_level = getattr(logging, app.config['LOG_LEVEL'])
    log_file = app.config['LOG_FILE']
    log_dir = os.path.dirname(log_file)
    
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 定义日志格式
    file_format = '%(asctime)s - %(name)s - %(levelname)s - %(pathname)s:%(lineno)d - [线程:%(thread)d] - %(message)s'
    console_format = '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    
    # 设置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # 清除之前的处理器
    if root_logger.handlers:
        root_logger.handlers.clear()
    
    # 文件处理器（带旋转功能）
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(logging.Formatter(file_format))
    
    # 控制台处理器（带颜色）
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(ColoredFormatter(console_format))
    
    # 添加处理器到根日志记录器
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # 设置第三方库的日志级别（防止日志过多）
    for logger_name in ['werkzeug', 'urllib3', 'git', 'matplotlib']:
        logging.getLogger(logger_name).setLevel(logging.WARNING)
    
    # 记录系统环境信息
    app.logger.info(f"日志系统初始化完成 (级别: {app.config['LOG_LEVEL']})")
    app.logger.info(f"系统信息: {platform.system()} {platform.release()} - Python {platform.python_version()}")

if __name__ == '__main__':
    # 初始化系统
    setup_logging()
    init_folders()
    
    # 启动信息
    app.logger.info(f"CodeInsight 启动于环境: {env}")
    app.logger.info(f"调试模式: {'开启' if app.debug else '关闭'}")
    
    # 启动应用
    app.run(host='0.0.0.0', port=5000) 