#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
报告工具模块
---------
这个模块提供了报告生成和处理的工具函数。
"""

import os
import json
import logging
import datetime
import uuid
from pathlib import Path

# 设置日志记录器
logger = logging.getLogger(__name__)

def generate_report(analysis_results, enhanced_results, repo_info, output_dir):
    """
    生成完整的分析报告
    
    参数:
        analysis_results: CodeQL原始分析结果
        enhanced_results: LLM增强后的结果
        repo_info: 仓库信息
        output_dir: 输出目录
        
    返回:
        报告文件路径
    """
    logger.info(f"生成分析报告，输出到: {output_dir}")
    
    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    
    # 生成报告ID
    report_id = str(uuid.uuid4())
    report_file = os.path.join(output_dir, f"report_{report_id}.json")
    
    # 构建报告数据
    report_data = {
        'report_id': report_id,
        'generated_at': datetime.datetime.now().isoformat(),
        'repository': repo_info,
        'summary': enhanced_results['summary'],
        'overview': enhanced_results.get('overview', '未生成概述'),
        'vulnerabilities': enhanced_results['vulnerabilities']
    }
    
    # 保存报告文件
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
    
    logger.info(f"报告已生成: {report_file}")
    return report_file

def load_report(report_file):
    """
    加载分析报告
    
    参数:
        report_file: 报告文件路径
        
    返回:
        报告数据字典
    """
    logger.debug(f"加载报告: {report_file}")
    
    if not os.path.exists(report_file):
        logger.error(f"报告文件不存在: {report_file}")
        raise FileNotFoundError(f"报告文件不存在: {report_file}")
    
    try:
        with open(report_file, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        logger.debug(f"报告加载成功: {report_file}")
        return report_data
    
    except json.JSONDecodeError as e:
        logger.error(f"报告文件格式错误: {str(e)}")
        raise ValueError(f"报告文件格式错误: {str(e)}")

def format_report_for_html(report_data):
    """
    将报告数据格式化为适合HTML显示的格式
    
    参数:
        report_data: 报告数据
        
    返回:
        格式化后的报告数据
    """
    logger.debug("将报告格式化为HTML格式")
    
    # 复制原始数据，避免修改原始数据
    formatted_data = report_data.copy()
    
    # 处理日期格式
    if 'generated_at' in formatted_data:
        try:
            dt = datetime.datetime.fromisoformat(formatted_data['generated_at'])
            formatted_data['generated_at_formatted'] = dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            formatted_data['generated_at_formatted'] = formatted_data['generated_at']
    
    # 添加安全评分
    formatted_data['security_score'] = calculate_security_score(report_data)
    
    # 处理严重性标签的颜色
    severity_colors = {
        'critical': 'danger',
        'high': 'danger',
        'medium': 'warning',
        'low': 'info',
        'warning': 'secondary',
        'note': 'light'
    }
    
    # 为每个漏洞添加颜色标签
    for vuln in formatted_data.get('vulnerabilities', []):
        severity = vuln.get('severity', '').lower()
        vuln['severity_color'] = severity_colors.get(severity, 'secondary')
    
    return formatted_data

def calculate_security_score(report_data):
    """
    根据漏洞情况计算安全评分
    
    参数:
        report_data: 报告数据
        
    返回:
        0到100之间的安全评分
    """
    # 获取漏洞统计
    severity_dist = report_data.get('summary', {}).get('severity_distribution', {})
    
    # 计算加权得分
    # 不同严重级别的权重
    weights = {
        'critical': 10,
        'high': 5,
        'medium': 2,
        'low': 1,
        'warning': 0.5,
        'note': 0.1
    }
    
    # 计算扣分
    weighted_sum = sum(
        count * weights.get(severity, 0)
        for severity, count in severity_dist.items()
    )
    
    # 总漏洞数量
    total_vulns = sum(severity_dist.values())
    
    # 基础分100分，根据加权漏洞数扣分
    base_score = 100
    if total_vulns > 0:
        deduction = min(weighted_sum, base_score)
        score = base_score - deduction
    else:
        score = base_score
    
    # 确保分数在0-100之间
    score = max(0, min(100, score))
    
    return round(score, 1)

def export_report_as_json(report_data, output_file):
    """
    将报告导出为JSON文件
    
    参数:
        report_data: 报告数据
        output_file: 输出文件路径
        
    返回:
        输出文件路径
    """
    logger.info(f"导出报告为JSON: {output_file}")
    
    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
    
    logger.info(f"JSON报告已导出: {output_file}")
    return output_file

def clean_old_reports(reports_dir, max_age_days=30):
    """
    清理旧的报告文件
    
    参数:
        reports_dir: 报告目录
        max_age_days: 最大保留天数
        
    返回:
        已删除的文件数量
    """
    logger.info(f"清理旧报告，目录: {reports_dir}, 最大保留天数: {max_age_days}")
    
    if not os.path.exists(reports_dir):
        logger.warning(f"报告目录不存在: {reports_dir}")
        return 0
    
    # 计算截止日期
    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=max_age_days)
    deleted_count = 0
    
    # 遍历目录中的所有JSON文件
    for file_path in Path(reports_dir).glob('*.json'):
        # 获取文件修改时间
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
        
        # 如果文件过期，删除它
        if mtime < cutoff_date:
            try:
                os.remove(file_path)
                logger.debug(f"已删除过期报告: {file_path}")
                deleted_count += 1
            except OSError as e:
                logger.error(f"删除报告文件失败: {file_path}, 错误: {str(e)}")
    
    logger.info(f"共删除 {deleted_count} 个过期报告")
    return deleted_count 