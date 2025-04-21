#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CodeInsight 应用程序入口
------------------------
这个脚本是应用程序的入口点，负责初始化并启动Web服务器。
"""

import os
import logging
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

# 配置日志
def setup_logging():
    """配置应用日志"""
    log_level = getattr(logging, app.config['LOG_LEVEL'])
    log_file = app.config['LOG_FILE']
    log_dir = os.path.dirname(log_file)
    
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 配置root logger
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    
    app.logger.info("日志系统初始化完成")

if __name__ == '__main__':
    # 初始化系统
    setup_logging()
    init_folders()
    
    # 启动信息
    app.logger.info(f"CodeInsight 启动于环境: {env}")
    app.logger.info(f"调试模式: {'开启' if app.debug else '关闭'}")
    
    # 启动应用
    app.run(host='0.0.0.0', port=5000) 