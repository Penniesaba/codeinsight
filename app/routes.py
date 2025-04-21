#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
应用路由模块
----------
这个模块定义了应用的所有路由和视图函数。
"""

import os
import uuid
import logging
import json
import glob
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, send_from_directory
import threading

# 创建蓝图
main_bp = Blueprint('main', __name__)

# 导入相关模块
from app.codeql.analyzer import CodeQLAnalyzer
from app.llm.enhancer import LLMEnhancer
from app.utils.git import clone_repository
from app.utils.report import generate_report, load_report

# 设置日志记录器
logger = logging.getLogger(__name__)

# 添加日期格式化过滤器
@main_bp.app_template_filter('datetime_format')
def datetime_format(value, format='%Y-%m-%d %H:%M:%S'):
    """格式化日期时间"""
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(format)

@main_bp.route('/', methods=['GET'])
def index():
    """
    首页路由
    显示仓库输入表单
    """
    logger.debug("访问首页")
    return render_template('index.html')

@main_bp.route('/analyze', methods=['POST'])
def analyze():
    """
    分析仓库路由
    接收仓库URL，启动分析过程
    """
    # 获取表单数据
    repo_url = request.form.get('repo_url')
    language = request.form.get('language', 'auto')
    clone_protocol = request.form.get('clone_protocol', 'http')  # 获取克隆协议
    
    if not repo_url:
        flash('请输入有效的仓库URL', 'danger')
        return redirect(url_for('main.index'))
    
    logger.info(f"收到分析请求: {repo_url}, 语言: {language}, 协议: {clone_protocol}")
    
    try:
        # 生成唯一的任务ID
        task_id = str(uuid.uuid4())
        
        # 创建任务目录
        task_dir = os.path.join(current_app.config['REPO_CACHE_DIR'], task_id)
        os.makedirs(task_dir, exist_ok=True)
        
        # 记录任务信息，状态设为'initializing'
        task_info = {
            'id': task_id,
            'repo_url': repo_url,
            'language': language,
            'protocol': clone_protocol,
            'status': 'initializing',
            'created_at': datetime.now().isoformat()
        }
        
        # 保存任务信息
        task_info_path = os.path.join(task_dir, 'task_info.json')
        with open(task_info_path, 'w', encoding='utf-8') as f:
            json.dump(task_info, f, ensure_ascii=False, indent=2)
        
        # 启动后台任务进行仓库克隆
        threading.Thread(target=clone_repo_background, args=(task_id, repo_url, task_dir, clone_protocol, task_info_path)).start()
        
        # 重定向到分析进度页面
        return redirect(url_for('main.analysis_progress', task_id=task_id))
    
    except Exception as e:
        logger.error(f"仓库分析请求失败: {str(e)}", exc_info=True)
        flash(f'分析请求失败: {str(e)}', 'danger')
        return redirect(url_for('main.index'))

def clone_repo_background(task_id, repo_url, task_dir, clone_protocol, task_info_path):
    """
    后台线程函数，用于克隆仓库并更新状态
    """
    try:
        # 读取最新的任务信息
        with open(task_info_path, 'r', encoding='utf-8') as f:
            task_info = json.load(f)
        
        # 更新状态为正在克隆
        task_info['status'] = 'cloning'
        task_info['clone_started_at'] = datetime.now().isoformat()
        with open(task_info_path, 'w', encoding='utf-8') as f:
            json.dump(task_info, f, ensure_ascii=False, indent=2)
            
        # 克隆仓库
        logger.info(f"正在克隆仓库: {repo_url}")
        repo_path = clone_repository(repo_url, task_dir, protocol=clone_protocol)
        
        # 更新状态为克隆完成
        task_info['status'] = 'cloned'
        task_info['clone_completed_at'] = datetime.now().isoformat()
        task_info['repo_path'] = repo_path
        with open(task_info_path, 'w', encoding='utf-8') as f:
            json.dump(task_info, f, ensure_ascii=False, indent=2)
        
        logger.info(f"仓库克隆完成: {repo_url} -> {repo_path}")
    
    except Exception as e:
        logger.error(f"仓库克隆失败: {str(e)}", exc_info=True)
        
        # 更新状态为失败
        with open(task_info_path, 'r', encoding='utf-8') as f:
            task_info = json.load(f)
        
        task_info['status'] = 'failed'
        task_info['error'] = str(e)
        with open(task_info_path, 'w', encoding='utf-8') as f:
            json.dump(task_info, f, ensure_ascii=False, indent=2)

@main_bp.route('/analysis/progress/<task_id>', methods=['GET'])
def analysis_progress(task_id):
    """
    分析进度页面
    显示分析任务的进度
    """
    logger.debug(f"访问任务进度页面: {task_id}")
    
    # 获取任务信息
    task_dir = os.path.join(current_app.config['REPO_CACHE_DIR'], task_id)
    task_info_path = os.path.join(task_dir, 'task_info.json')
    
    if not os.path.exists(task_info_path):
        flash('无效的任务ID', 'danger')
        return redirect(url_for('main.index'))
    
    with open(task_info_path, 'r', encoding='utf-8') as f:
        task_info = json.load(f)
    
    # 渲染进度页面
    return render_template('progress.html', task_id=task_id, task_info=task_info)

@main_bp.route('/api/analysis/status/<task_id>', methods=['GET'])
def analysis_status(task_id):
    """
    分析状态API
    返回当前分析任务的状态
    """
    # 获取任务信息
    task_dir = os.path.join(current_app.config['REPO_CACHE_DIR'], task_id)
    task_info_path = os.path.join(task_dir, 'task_info.json')
    
    if not os.path.exists(task_info_path):
        return jsonify({'error': '无效的任务ID'}), 404
    
    with open(task_info_path, 'r', encoding='utf-8') as f:
        task_info = json.load(f)
    
    # 如果任务状态是'cloned'，启动分析
    if task_info['status'] == 'cloned':
        # 更新状态为'analyzing'
        task_info['status'] = 'analyzing'
        task_info['analyze_started_at'] = datetime.now().isoformat()
        with open(task_info_path, 'w', encoding='utf-8') as f:
            json.dump(task_info, f, ensure_ascii=False, indent=2)
        
        try:
            # 创建分析器
            analyzer = CodeQLAnalyzer(current_app.config)
            
            # 开始分析
            logger.info(f"开始CodeQL分析: {task_id}")
            codeql_results = analyzer.analyze_repository(task_info['repo_path'], task_info['language'])
            
            # 更新状态为'enhancing'
            task_info['status'] = 'enhancing'
            task_info['codeql_completed_at'] = datetime.now().isoformat()
            with open(task_info_path, 'w', encoding='utf-8') as f:
                json.dump(task_info, f, ensure_ascii=False, indent=2)
            
            # 创建LLM增强器
            enhancer = LLMEnhancer(current_app.config)
            
            # 生成增强报告
            logger.info(f"开始LLM增强分析: {task_id}")
            enhanced_report = enhancer.enhance_results(codeql_results, task_info['repo_path'])
            
            # 保存分析结果
            results_dir = os.path.join(current_app.config['ANALYSIS_CACHE_DIR'], task_id)
            os.makedirs(results_dir, exist_ok=True)
            
            with open(os.path.join(results_dir, 'codeql_results.json'), 'w', encoding='utf-8') as f:
                json.dump(codeql_results, f, ensure_ascii=False, indent=2)
                
            with open(os.path.join(results_dir, 'enhanced_report.json'), 'w', encoding='utf-8') as f:
                json.dump(enhanced_report, f, ensure_ascii=False, indent=2)
            
            # 更新任务状态为'completed'
            task_info['status'] = 'completed'
            task_info['completed_at'] = datetime.now().isoformat()
            with open(task_info_path, 'w', encoding='utf-8') as f:
                json.dump(task_info, f, ensure_ascii=False, indent=2)
                
            logger.info(f"分析完成: {task_id}")
            
        except Exception as e:
            # 分析失败
            logger.error(f"分析失败: {str(e)}", exc_info=True)
            task_info['status'] = 'failed'
            task_info['error'] = str(e)
            with open(task_info_path, 'w', encoding='utf-8') as f:
                json.dump(task_info, f, ensure_ascii=False, indent=2)
    
    # 返回当前状态
    phase_message = {
        'initializing': '正在初始化分析环境...',
        'cloning': '正在克隆仓库...',
        'cloned': '仓库已克隆，准备分析...',
        'analyzing': '正在进行CodeQL分析...',
        'enhancing': '正在通过AI增强分析结果...',
        'completed': '分析完成',
        'failed': '分析失败'
    }
    
    return jsonify({
        'status': task_info['status'],
        'message': phase_message.get(task_info['status'], _get_status_message(task_info['status'])),
        'progress': _calculate_progress(task_info['status']),
        'redirect': url_for('main.report', task_id=task_id) if task_info['status'] == 'completed' else None,
        'error': task_info.get('error'),
        # 添加时间信息用于前端显示
        'created_at': task_info.get('created_at'),
        'clone_started_at': task_info.get('clone_started_at'),
        'clone_completed_at': task_info.get('clone_completed_at'),
        'analyze_started_at': task_info.get('analyze_started_at'),
        'codeql_completed_at': task_info.get('codeql_completed_at'),
        'completed_at': task_info.get('completed_at')
    })

@main_bp.route('/api/task/<task_id>/info', methods=['GET'])
def task_info(task_id):
    """
    任务信息API
    返回任务的详细信息
    """
    task_dir = os.path.join(current_app.config['REPO_CACHE_DIR'], task_id)
    task_info_path = os.path.join(task_dir, 'task_info.json')
    
    if not os.path.exists(task_info_path):
        return jsonify({'error': '无效的任务ID'}), 404
    
    with open(task_info_path, 'r', encoding='utf-8') as f:
        task_info = json.load(f)
    
    # 移除敏感信息
    task_info.pop('repo_path', None)
    
    return jsonify(task_info)

@main_bp.route('/report/<task_id>', methods=['GET'])
def report(task_id):
    """
    报告页面
    显示分析报告
    """
    logger.debug(f"访问报告页面: {task_id}")
    
    # 获取任务信息
    task_dir = os.path.join(current_app.config['REPO_CACHE_DIR'], task_id)
    task_info_path = os.path.join(task_dir, 'task_info.json')
    
    if not os.path.exists(task_info_path):
        flash('无效的任务ID', 'danger')
        return redirect(url_for('main.index'))
    
    with open(task_info_path, 'r', encoding='utf-8') as f:
        task_info = json.load(f)
    
    # 如果任务未完成，重定向到进度页面
    if task_info['status'] != 'completed':
        return redirect(url_for('main.analysis_progress', task_id=task_id))
    
    # 加载分析报告
    results_dir = os.path.join(current_app.config['ANALYSIS_CACHE_DIR'], task_id)
    report_path = os.path.join(results_dir, 'enhanced_report.json')
    
    if not os.path.exists(report_path):
        flash('报告文件不存在', 'danger')
        return redirect(url_for('main.index'))
    
    with open(report_path, 'r', encoding='utf-8') as f:
        report_data = json.load(f)
    
    # 生成HTML报告
    return render_template('report.html', 
                          task_id=task_id, 
                          task_info=task_info, 
                          report=report_data)

@main_bp.route('/report/export/<task_id>', methods=['GET'])
def export_report(task_id):
    """
    导出报告
    将报告导出为JSON或PDF格式
    """
    format_type = request.args.get('format', 'json')
    
    # 获取任务信息
    task_dir = os.path.join(current_app.config['REPO_CACHE_DIR'], task_id)
    task_info_path = os.path.join(task_dir, 'task_info.json')
    
    if not os.path.exists(task_info_path):
        flash('无效的任务ID', 'danger')
        return redirect(url_for('main.index'))
    
    # 加载分析报告
    results_dir = os.path.join(current_app.config['ANALYSIS_CACHE_DIR'], task_id)
    report_path = os.path.join(results_dir, 'enhanced_report.json')
    
    if not os.path.exists(report_path):
        flash('报告文件不存在', 'danger')
        return redirect(url_for('main.index'))
    
    if format_type == 'json':
        # 直接返回JSON文件
        return send_from_directory(
            results_dir, 
            'enhanced_report.json', 
            as_attachment=True,
            download_name=f'codeql_report_{task_id}.json'
        )
    elif format_type == 'pdf':
        # 生成PDF并返回
        # 这里需要实现PDF生成逻辑
        flash('PDF导出功能正在开发中', 'warning')
        return redirect(url_for('main.report', task_id=task_id))
    else:
        flash('不支持的导出格式', 'danger')
        return redirect(url_for('main.report', task_id=task_id))

@main_bp.route('/history', methods=['GET'])
def history():
    """
    历史分析记录
    显示所有历史分析任务
    """
    logger.debug("访问历史记录页面")
    
    # 分页参数
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # 获取历史记录
    history_list, pagination = get_history_records(page, per_page)
    
    # 渲染历史记录页面
    return render_template(
        'history.html', 
        history_list=history_list, 
        page=page, 
        pagination=pagination
    )

def get_history_records(page=1, per_page=10):
    """
    获取历史分析记录
    
    参数:
        page: 当前页码
        per_page: 每页显示数量
        
    返回:
        history_list: 历史记录列表
        pagination: 分页信息
    """
    # 获取所有任务目录
    repo_cache_dir = current_app.config['REPO_CACHE_DIR']
    task_dirs = glob.glob(os.path.join(repo_cache_dir, '*'))
    
    # 读取任务信息
    history_list = []
    for task_dir in task_dirs:
        task_info_path = os.path.join(task_dir, 'task_info.json')
        if os.path.exists(task_info_path):
            try:
                with open(task_info_path, 'r', encoding='utf-8') as f:
                    task_info = json.load(f)
                
                # 移除敏感信息
                if 'repo_path' in task_info:
                    task_info.pop('repo_path')
                
                history_list.append(task_info)
            except Exception as e:
                logger.error(f"读取任务信息失败: {str(e)}")
    
    # 按时间排序（最新的在前）
    history_list.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    # 计算分页信息
    total = len(history_list)
    start = (page - 1) * per_page
    end = start + per_page
    records = history_list[start:end]
    
    # 构建分页对象
    pagination = {
        'page': page,
        'per_page': per_page,
        'total': total,
        'pages': (total + per_page - 1) // per_page
    }
    
    return records, pagination

def _get_status_message(status):
    """
    获取状态对应的消息
    """
    messages = {
        'initializing': '正在初始化分析环境...',
        'cloning': '正在克隆仓库...',
        'cloned': '仓库已克隆，准备分析...',
        'analyzing': '正在进行CodeQL分析...',
        'enhancing': '正在通过AI增强分析结果...',
        'completed': '分析完成',
        'failed': '分析失败'
    }
    return messages.get(status, '未知状态')

def _calculate_progress(status):
    """
    计算分析进度百分比
    """
    progress_map = {
        'initializing': 5,
        'cloning': 10,
        'cloned': 20,
        'analyzing': 50,
        'enhancing': 80,
        'completed': 100,
        'failed': 100
    }
    return progress_map.get(status, 0) 