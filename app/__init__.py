#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Flask应用初始化模块
-----------------
这个模块负责创建和配置Flask应用实例，注册蓝图和扩展。
"""

import os
import logging
from flask import Flask

def create_app(config):
    """
    工厂函数，创建Flask应用实例
    
    参数:
        config: 配置对象
        
    返回:
        配置好的Flask应用实例
    """
    # 创建应用实例
    app = Flask(__name__)
    
    # 加载配置
    app.config.from_object(config)
    
    # 确保必要的目录存在
    _ensure_directories(app)
    
    # 注册扩展
    _register_extensions(app)
    
    # 注册蓝图
    _register_blueprints(app)
    
    # 注册错误处理器
    _register_error_handlers(app)
    
    # 注册上下文处理器
    _register_context_processors(app)
    
    # 注册Shell上下文
    _register_shell_context(app)
    
    # 返回配置好的应用
    return app

def _ensure_directories(app):
    """确保应用所需的目录存在"""
    directories = [
        app.config['CACHE_DIR'],
        app.config['LOG_DIR'],
        app.config['REPO_CACHE_DIR'],
        app.config['ANALYSIS_CACHE_DIR'],
        os.path.join(app.config['CACHE_DIR'], 'qlresults')
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)

def _register_extensions(app):
    """注册Flask扩展"""
    # 在这里注册扩展，例如：
    # bootstrap.init_app(app)
    # csrf.init_app(app)
    
    from flask_bootstrap import Bootstrap5
    bootstrap = Bootstrap5(app)

def _register_blueprints(app):
    """注册蓝图"""
    # 导入蓝图
    from app.routes import main_bp
    
    # 注册蓝图
    app.register_blueprint(main_bp)

def _register_error_handlers(app):
    """注册错误处理器"""
    
    @app.errorhandler(404)
    def page_not_found(e):
        """处理404错误"""
        app.logger.warning(f"页面未找到: {e}")
        return "页面未找到", 404
    
    @app.errorhandler(500)
    def internal_server_error(e):
        """处理500错误"""
        app.logger.error(f"服务器内部错误: {e}")
        return "服务器内部错误", 500

def _register_context_processors(app):
    """注册模板上下文处理器"""
    
    @app.context_processor
    def inject_common_variables():
        """向模板注入公共变量"""
        return {
            'app_name': 'CodeInsight',
            'app_version': '1.0.0'
        }

def _register_shell_context(app):
    """注册Shell上下文，方便调试"""
    
    @app.shell_context_processor
    def make_shell_context():
        """为Flask shell提供上下文"""
        return {
            'app': app
        } 