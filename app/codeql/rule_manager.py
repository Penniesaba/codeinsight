#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CodeQL规则集管理器
---------------
这个模块负责管理和组织CodeQL规则集，包括内置规则和自定义规则。
"""

import os
import json
import logging
import re
import shutil
import tempfile
import requests
from pathlib import Path
from urllib.parse import urlparse

# 设置日志记录器
logger = logging.getLogger(__name__)

class RuleManager:
    """
    CodeQL规则集管理器类
    负责管理和组织CodeQL规则集
    """
    
    def __init__(self, config):
        """
        初始化规则集管理器
        
        参数:
            config: 配置对象，包含规则集相关配置
        """
        self.config = config
        self.queries_path = config['CODEQL_QUERIES_PATH']
        self.custom_rules_path = os.path.join(os.path.dirname(self.queries_path), 'custom_rules')
        
        # 确保自定义规则目录存在
        self._ensure_custom_rules_directories()
        
        # 规则集类别
        self.rule_categories = {
            'security': '安全漏洞',
            'code-quality': '代码质量',
            'correctness': '代码正确性',
            'complexity': '代码复杂度',
            'maintainability': '可维护性',
            'performance': '性能问题'
        }
        
        # 语言映射
        self.language_map = {
            'python': 'Python',
            'javascript': 'JavaScript/TypeScript',
            'java': 'Java',
            'cpp': 'C/C++',
            'csharp': 'C#',
            'go': 'Go',
            'ruby': 'Ruby',
            'swift': 'Swift',
            'rust': 'Rust'
        }
        
        # GitHub API相关
        self.github_api_base = "https://api.github.com"
        self.github_raw_base = "https://raw.githubusercontent.com"
        self.codeql_repo = "github/codeql"
        self.codeql_branch = "main"  # 默认分支
        
        logger.debug("规则集管理器初始化完成")
    
    def _ensure_custom_rules_directories(self):
        """确保自定义规则目录存在"""
        languages = ['python', 'javascript', 'java', 'cpp', 'csharp', 'go', 'ruby', 'swift', 'rust']
        
        for language in languages:
            lang_dir = os.path.join(self.custom_rules_path, language)
            os.makedirs(lang_dir, exist_ok=True)
    
    def get_available_rules(self, language):
        """
        获取指定语言的可用规则
        
        参数:
            language: 代码语言
            
        返回:
            规则列表，包含规则元数据
        """
        rules = []
        
        # 检查自定义规则
        custom_rules = self._get_custom_rules(language)
        if custom_rules:
            rules.extend(custom_rules)
        
        # 检查内置规则套件
        builtin_rules = self._get_builtin_rules(language)
        if builtin_rules:
            rules.extend(builtin_rules)
        
        return rules
    
    def _get_custom_rules(self, language):
        """
        获取指定语言的自定义规则
        
        参数:
            language: 代码语言
            
        返回:
            规则列表，包含规则元数据
        """
        rules = []
        lang_dir = os.path.join(self.custom_rules_path, language)
        
        if not os.path.exists(lang_dir):
            return rules
        
        for file_name in os.listdir(lang_dir):
            if file_name.endswith('.ql'):
                rule_path = os.path.join(lang_dir, file_name)
                rule_meta = self._extract_rule_metadata(rule_path)
                
                if rule_meta:
                    rule_meta['path'] = rule_path
                    rule_meta['type'] = 'custom'
                    rules.append(rule_meta)
        
        return rules
    
    def _get_builtin_rules(self, language):
        """
        获取指定语言的内置规则
        
        参数:
            language: 代码语言
            
        返回:
            规则列表，包含规则元数据
        """
        rules = []
        
        # 标准查询包目录
        standard_suites_path = os.path.join(self.queries_path, 'ql', 'src', 'codeql-suites')
        
        # 安全与质量规则套件
        security_quality_suite = f"{language}-security-and-quality.qls"
        suite_path = os.path.join(standard_suites_path, security_quality_suite)
        
        if os.path.exists(suite_path):
            rule_meta = {
                'id': f"{language}-security-and-quality",
                'name': f"{self.language_map.get(language, language)} 安全与质量规则套件",
                'description': f"适用于{self.language_map.get(language, language)}的综合性安全和代码质量规则集",
                'severity': 'medium',
                'path': suite_path,
                'type': 'builtin',
                'category': 'security',
                'language': language
            }
            rules.append(rule_meta)
        
        # 安全扩展规则套件
        security_extended_suite = f"{language}-security-extended.qls"
        extended_path = os.path.join(standard_suites_path, security_extended_suite)
        
        if os.path.exists(extended_path):
            rule_meta = {
                'id': f"{language}-security-extended",
                'name': f"{self.language_map.get(language, language)} 安全扩展规则套件",
                'description': f"适用于{self.language_map.get(language, language)}的扩展安全规则集，包含更多深度安全检查",
                'severity': 'high',
                'path': extended_path,
                'type': 'builtin',
                'category': 'security',
                'language': language
            }
            rules.append(rule_meta)
        
        # 查找单独的QL文件（CWE规则等）
        security_dir = os.path.join(self.queries_path, 'ql', 'src', 'Security')
        
        if os.path.exists(security_dir):
            for cwe_dir in os.listdir(security_dir):
                if cwe_dir.startswith('CWE-'):
                    cwe_path = os.path.join(security_dir, cwe_dir)
                    if os.path.isdir(cwe_path):
                        for file_name in os.listdir(cwe_path):
                            if file_name.endswith('.ql'):
                                rule_path = os.path.join(cwe_path, file_name)
                                rule_meta = self._extract_rule_metadata(rule_path)
                                
                                if rule_meta:
                                    rule_meta['path'] = rule_path
                                    rule_meta['type'] = 'builtin'
                                    rule_meta['cwe'] = cwe_dir
                                    rules.append(rule_meta)
        
        return rules
    
    def _extract_rule_metadata(self, rule_path):
        """
        从规则文件提取元数据
        
        参数:
            rule_path: 规则文件路径
            
        返回:
            规则元数据字典
        """
        try:
            with open(rule_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 使用正则表达式提取元数据
            name_match = re.search(r'@name\s+(.*)', content)
            desc_match = re.search(r'@description\s+(.*)', content)
            severity_match = re.search(r'@problem.severity\s+(.*)', content)
            sec_severity_match = re.search(r'@security-severity\s+(.*)', content)
            precision_match = re.search(r'@precision\s+(.*)', content)
            id_match = re.search(r'@id\s+(.*)', content)
            tags_match = re.search(r'@tags\s+(.*(?:\n\s+\*\s+.*)*)', content)
            
            # 提取标签
            tags = []
            if tags_match:
                tags_text = tags_match.group(1)
                tags = re.findall(r'[a-zA-Z0-9/-]+', tags_text)
            
            # 确定类别
            category = 'unknown'
            for tag in tags:
                if tag in self.rule_categories:
                    category = tag
                    break
                elif tag.startswith('security'):
                    category = 'security'
                    break
            
            # 确定语言
            language = 'unknown'
            for lang in self.language_map:
                if lang in rule_path.lower() or f"/{lang}/" in rule_path.lower():
                    language = lang
                    break
            
            return {
                'id': id_match.group(1) if id_match else os.path.basename(rule_path),
                'name': name_match.group(1) if name_match else os.path.basename(rule_path),
                'description': desc_match.group(1) if desc_match else '',
                'severity': severity_match.group(1) if severity_match else 'warning',
                'security_severity': sec_severity_match.group(1) if sec_severity_match else None,
                'precision': precision_match.group(1) if precision_match else 'medium',
                'tags': tags,
                'category': category,
                'language': language
            }
        
        except Exception as e:
            logger.error(f"提取规则元数据失败: {rule_path}, 错误: {str(e)}")
            return None
    
    def import_rule_from_github(self, language, rule_id, source_path):
        """
        从GitHub CodeQL仓库导入规则到自定义规则目录
        
        参数:
            language: 目标语言
            rule_id: 规则ID 
            source_path: 源文件路径或GitHub URL
            
        返回:
            导入成功返回规则元数据，否则返回None
        """
        try:
            target_dir = os.path.join(self.custom_rules_path, language)
            os.makedirs(target_dir, exist_ok=True)
            
            # 检查source_path是否为URL
            is_url = source_path.startswith(('http://', 'https://'))
            
            # 如果是本地文件路径
            if not is_url:
                if os.path.exists(source_path):
                    # 生成目标文件名
                    base_name = os.path.basename(source_path)
                    target_path = os.path.join(target_dir, base_name)
                    
                    # 复制文件
                    shutil.copy2(source_path, target_path)
                    logger.info(f"成功从本地导入规则 {rule_id} 到 {target_path}")
                else:
                    logger.error(f"本地规则文件不存在: {source_path}")
                    return None
            else:
                # 处理GitHub URL
                rule_content = self._fetch_rule_from_github(source_path)
                if not rule_content:
                    return None
                
                # 从URL中提取文件名
                parsed_url = urlparse(source_path)
                path_parts = parsed_url.path.split('/')
                file_name = path_parts[-1] if path_parts[-1] else f"{rule_id}.ql"
                
                # 确保文件名以.ql结尾
                if not file_name.endswith('.ql'):
                    file_name += '.ql'
                
                # 保存规则文件
                target_path = os.path.join(target_dir, file_name)
                with open(target_path, 'w', encoding='utf-8') as f:
                    f.write(rule_content)
                
                logger.info(f"成功从GitHub导入规则 {rule_id} 到 {target_path}")
            
            # 提取规则元数据
            rule_meta = self._extract_rule_metadata(target_path)
            if rule_meta:
                rule_meta['path'] = target_path
                rule_meta['type'] = 'custom'
                rule_meta['import_source'] = source_path
                
                # 记录导入时间
                from datetime import datetime
                rule_meta['import_date'] = datetime.now().isoformat()
                
                return rule_meta
            
            return None
            
        except Exception as e:
            logger.error(f"导入规则失败: {str(e)}")
            return None
    
    def _fetch_rule_from_github(self, url):
        """
        从GitHub获取规则内容
        
        参数:
            url: GitHub URL或规则路径
            
        返回:
            规则内容字符串，失败返回None
        """
        try:
            # 直接处理完整URL
            if url.startswith(('http://', 'https://')):
                # 对于GitHub原始内容URL
                if 'raw.githubusercontent.com' in url:
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        return response.text
                    else:
                        logger.error(f"获取GitHub规则失败: HTTP {response.status_code}")
                        return None
                
                # 对于GitHub仓库文件URL，转换为原始内容URL
                elif 'github.com' in url:
                    # 将github.com/user/repo/blob/branch/path 转换为 raw.githubusercontent.com/user/repo/branch/path
                    raw_url = url.replace('github.com', 'raw.githubusercontent.com')
                    raw_url = raw_url.replace('/blob/', '/')
                    response = requests.get(raw_url, timeout=10)
                    if response.status_code == 200:
                        return response.text
                    else:
                        logger.error(f"获取GitHub规则失败: HTTP {response.status_code}")
                        return None
            
            # 处理相对路径（假设是相对于CodeQL仓库的路径）
            else:
                # 构建原始内容URL
                path = url.lstrip('/')  # 移除开头的斜杠
                raw_url = f"{self.github_raw_base}/{self.codeql_repo}/{self.codeql_branch}/{path}"
                response = requests.get(raw_url, timeout=10)
                if response.status_code == 200:
                    return response.text
                else:
                    logger.error(f"获取GitHub规则失败: HTTP {response.status_code}")
                    return None
                
        except Exception as e:
            logger.error(f"获取GitHub规则内容失败: {str(e)}")
            return None
    
    def search_github_rules(self, language, keywords=None, category=None, limit=20):
        """
        搜索GitHub CodeQL仓库中的规则
        
        参数:
            language: 目标语言
            keywords: 搜索关键词
            category: 规则类别
            limit: 最大返回结果数量
            
        返回:
            规则列表
        """
        try:
            # 构建GitHub API搜索请求
            search_query = f"repo:{self.codeql_repo} path:{language}/ql/src extension:ql"
            
            if keywords:
                search_query += f" {keywords}"
            
            if category:
                search_query += f" {category}"
            
            headers = {}
            # 如果配置了GitHub令牌，添加到请求头
            if 'GITHUB_TOKEN' in self.config:
                headers['Authorization'] = f"token {self.config['GITHUB_TOKEN']}"
            
            search_url = f"{self.github_api_base}/search/code?q={search_query}&per_page={limit}"
            
            response = requests.get(search_url, headers=headers, timeout=15)
            
            if response.status_code != 200:
                logger.error(f"GitHub API请求失败: HTTP {response.status_code}")
                return []
            
            results = response.json()
            
            # 处理搜索结果
            rules = []
            for item in results.get('items', []):
                rule_url = item['html_url']
                rule_path = item['path']
                rule_name = os.path.basename(rule_path)
                
                # 获取规则内容以提取元数据
                raw_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                
                rules.append({
                    'id': rule_name.replace('.ql', ''),
                    'name': rule_name,
                    'path': rule_path,
                    'url': rule_url,
                    'raw_url': raw_url,
                    'repository': self.codeql_repo
                })
            
            return rules
            
        except Exception as e:
            logger.error(f"搜索GitHub规则失败: {str(e)}")
            return []
    
    def create_ruleset(self, name, language, rule_ids, description=""):
        """
        创建自定义规则集
        
        参数:
            name: 规则集名称
            language: 规则集适用语言
            rule_ids: 规则ID列表
            description: 规则集描述
            
        返回:
            规则集文件路径
        """
        try:
            # 生成规则集文件名
            safe_name = name.lower().replace(' ', '_')
            ruleset_path = os.path.join(self.custom_rules_path, f"{safe_name}.qls")
            
            # 获取规则路径
            rules = self.get_available_rules(language)
            rule_paths = {}
            
            for rule in rules:
                rule_paths[rule['id']] = rule['path']
            
            # 构建规则集内容
            content = f"# {name}\n"
            content += f"# {description}\n\n"
            
            for rule_id in rule_ids:
                if rule_id in rule_paths:
                    content += f"- import {rule_paths[rule_id]}\n"
            
            # 写入文件
            with open(ruleset_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"成功创建规则集: {ruleset_path}")
            return ruleset_path
            
        except Exception as e:
            logger.error(f"创建规则集失败: {str(e)}")
            return None 