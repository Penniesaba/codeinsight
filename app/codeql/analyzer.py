#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CodeQL分析器模块
--------------
这个模块负责执行CodeQL分析，包括数据库创建、查询执行和结果处理。
"""

import os
import subprocess
import json
import logging
import tempfile
import shutil
from pathlib import Path

from .rule_manager import RuleManager

# 设置日志记录器
logger = logging.getLogger(__name__)

class CodeQLAnalyzer:
    """
    CodeQL分析器类
    负责执行CodeQL查询并处理结果
    """
    
    def __init__(self, config):
        """
        初始化CodeQL分析器
        
        参数:
            config: 配置对象，包含CodeQL相关配置
        """
        self.config = config
        self.codeql_path = config['CODEQL_CLI_PATH']
        self.queries_path = config['CODEQL_QUERIES_PATH']
        
        # 初始化规则管理器
        self.rule_manager = RuleManager(config)
        
        # 检查CodeQL CLI是否可用
        self._check_codeql_availability()
        
        # 验证规则库路径
        self._verify_query_packs()
        
        logger.debug("CodeQL分析器初始化完成")
    
    def _check_codeql_availability(self):
        """检查CodeQL CLI是否可用"""
        try:
            result = subprocess.run(
                [self.codeql_path, 'version'],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info(f"CodeQL版本: {result.stdout.strip()}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"CodeQL CLI不可用: {str(e)}")
            raise RuntimeError(f"CodeQL CLI不可用，请确保已正确安装: {str(e)}")
    
    def _verify_query_packs(self):
        """验证规则库是否存在"""
        # 检查规则库目录
        suites_path = os.path.join(self.queries_path, 'ql', 'src', 'codeql-suites')
        if os.path.exists(suites_path):
            # 统计查询套件数量
            qls_files = [f for f in os.listdir(suites_path) if f.endswith('.qls')]
            logger.info(f"找到 {len(qls_files)} 个查询套件文件")
            
            # 检查每种语言的规则套件
            for language in ['python', 'javascript', 'java', 'cpp', 'csharp', 'go', 'ruby']:
                security_suite = f"{language}-security-and-quality.qls"
                suite_path = os.path.join(suites_path, security_suite)
                
                if os.path.exists(suite_path):
                    logger.info(f"已验证规则库: {security_suite}")
                else:
                    logger.warning(f"未找到规则库: {security_suite}")
        else:
            logger.warning(f"查询套件目录不存在: {suites_path}")
            logger.warning("CodeQL分析可能无法使用标准安全规则集")
    
    def analyze_repository(self, repo_path, language='auto', rule_set=None):
        """
        分析代码仓库
        
        参数:
            repo_path: 代码仓库路径
            language: 代码语言，如auto, javascript, python等
            rule_set: 使用的规则集，如果为None则使用默认规则集
            
        返回:
            分析结果字典
        """
        logger.info(f"开始分析仓库: {repo_path}, 语言: {language}, 规则集: {rule_set}")
        
        # 创建临时目录存放数据库
        with tempfile.TemporaryDirectory() as db_dir:
            try:
                # 1. 创建CodeQL数据库
                db_path = os.path.join(db_dir, 'codeql_db')
                self._create_database(repo_path, db_path, language)
                
                # 2. 运行查询
                query_results = self._run_queries(db_path, language, rule_set)
                
                # 3. 处理结果
                analysis_results = self._process_results(query_results, repo_path)
                
                return analysis_results
                
            except Exception as e:
                logger.error(f"仓库分析失败: {str(e)}", exc_info=True)
                raise RuntimeError(f"仓库分析失败: {str(e)}")
    
    def _create_database(self, repo_path, db_path, language):
        """
        创建CodeQL数据库
        
        参数:
            repo_path: 代码仓库路径
            db_path: 数据库输出路径
            language: 代码语言
        """
        logger.info(f"创建CodeQL数据库: {db_path}")
        
        cmd = [
            self.codeql_path, 'database', 'create',
            '--language=' + (language if language != 'auto' else ''),
            '--source-root=' + repo_path,
            db_path
        ]
        
        # 如果语言是auto，则移除--language参数
        if language == 'auto':
            cmd.remove('--language=')
        
        try:
            logger.debug(f"执行命令: {' '.join(cmd)}")
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            logger.info("数据库创建成功")
        except subprocess.CalledProcessError as e:
            logger.error(f"数据库创建失败: {e.stderr}")
            raise RuntimeError(f"CodeQL数据库创建失败: {e.stderr}")
    
    def _run_queries(self, db_path, language, rule_set=None):
        """
        运行CodeQL查询
        
        参数:
            db_path: 数据库路径
            language: 代码语言
            rule_set: 使用的规则集，如果为None则使用默认规则集
            
        返回:
            查询结果列表
        """
        logger.info(f"运行CodeQL查询")
        
        # 确定要运行的查询包
        if language == 'auto':
            # 检测数据库中的语言
            language = self._detect_database_language(db_path)
        
        # 获取要运行的规则或规则集
        if rule_set:
            # 运行指定的规则集
            logger.info(f"使用指定规则集: {rule_set}")
            query_packs = [rule_set]
            custom_rules = []
        else:
            # 获取标准查询包和自定义规则
            standard_packs = self._get_query_packs(language)
            custom_rules = self.rule_manager._get_custom_rules(language)
            custom_rules = [rule['path'] for rule in custom_rules]
            
            query_packs = standard_packs
        
        results = []
        
        # 首先运行标准查询包（批量方式）
        if query_packs:
            logger.info(f"运行标准查询包，共 {len(query_packs)} 个")
            
            for query_pack in query_packs:
                logger.info(f"运行查询包: {query_pack}")
                
                # 创建临时结果文件
                with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
                    results_path = temp_file.name
                
                try:
                    # 运行查询
                    cmd = [
                        self.codeql_path, 'database', 'analyze',
                        '--format=json',
                        f'--output={results_path}',
                        db_path, query_pack
                    ]
                    
                    logger.debug(f"执行命令: {' '.join(cmd)}")
                    subprocess.run(
                        cmd,
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    # 读取结果
                    with open(results_path, 'r', encoding='utf-8') as f:
                        pack_results = json.load(f)
                        results.extend(pack_results)
                    
                except subprocess.CalledProcessError as e:
                    logger.error(f"查询执行失败: {e.stderr}")
                    # 继续执行其他查询包，不中断过程
                finally:
                    # 删除临时文件
                    if os.path.exists(results_path):
                        os.unlink(results_path)
        
        # 然后逐条运行自定义规则
        if custom_rules:
            logger.info(f"运行自定义规则，共 {len(custom_rules)} 条")
            
            for rule_path in custom_rules:
                rule_name = os.path.basename(rule_path)
                logger.info(f"运行自定义规则: {rule_name}")
                
                try:
                    # 逐条运行规则
                    rule_results = self._run_single_query(db_path, rule_path)
                    if rule_results:
                        results.extend(rule_results)
                        logger.info(f"规则 {rule_name} 找到 {len(rule_results)} 个问题")
                    else:
                        logger.info(f"规则 {rule_name} 未找到问题")
                        
                except Exception as e:
                    logger.error(f"自定义规则 {rule_name} 执行失败: {str(e)}")
        
        logger.info(f"查询完成，共找到 {len(results)} 条结果")
        return results
    
    def _run_single_query(self, db_path, query_path):
        """
        运行单个查询规则
        
        参数:
            db_path: 数据库路径
            query_path: 查询文件路径
            
        返回:
            查询结果列表
        """
        # 创建临时结果文件
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            results_path = temp_file.name
        
        try:
            # 构建命令
            cmd = [
                self.codeql_path, 'database', 'analyze',
                '--format=json',
                f'--output={results_path}',
                '--ram=2000',  # 设置内存限制，避免大型代码库分析时内存溢出
                '--threads=2',  # 设置线程数
                db_path, query_path
            ]
            
            logger.debug(f"执行命令: {' '.join(cmd)}")
            
            # 执行命令
            process = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300  # 设置超时时间
            )
            
            # 读取结果
            if os.path.exists(results_path) and os.path.getsize(results_path) > 0:
                with open(results_path, 'r', encoding='utf-8') as f:
                    try:
                        results = json.load(f)
                        return results
                    except json.JSONDecodeError:
                        logger.warning(f"解析结果文件失败: {results_path}")
                        return []
            else:
                logger.info(f"查询未返回结果")
                return []
                
        except subprocess.CalledProcessError as e:
            logger.error(f"查询执行失败: {e.stderr}")
            return []
        except subprocess.TimeoutExpired:
            logger.error(f"查询执行超时")
            return []
        except Exception as e:
            logger.error(f"查询执行出错: {str(e)}")
            return []
        finally:
            # 删除临时文件
            if os.path.exists(results_path):
                os.unlink(results_path)
    
    def _get_custom_rules(self, language):
        """
        获取指定语言的自定义规则
        
        参数:
            language: 代码语言
            
        返回:
            规则文件路径列表
        """
        custom_rules_dir = os.path.join(os.path.dirname(self.queries_path), 'custom_rules', language)
        rules = []
        
        if os.path.exists(custom_rules_dir):
            for file_name in os.listdir(custom_rules_dir):
                if file_name.endswith('.ql'):
                    rule_path = os.path.join(custom_rules_dir, file_name)
                    rules.append(rule_path)
        
        logger.info(f"找到 {language} 语言的自定义规则 {len(rules)} 条")
        return rules
    
    def _detect_database_language(self, db_path):
        """
        检测数据库的语言
        
        参数:
            db_path: 数据库路径
            
        返回:
            检测到的语言
        """
        logger.info("检测数据库语言")
        
        cmd = [
            self.codeql_path, 'database', 'info',
            '--format=json',
            db_path
        ]
        
        try:
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            db_info = json.loads(result.stdout)
            languages = db_info.get('languages', [])
            
            if languages:
                primary_language = languages[0].lower()
                logger.info(f"检测到主要语言: {primary_language}")
                return primary_language
            else:
                logger.warning("未检测到语言，使用默认的 'javascript'")
                return 'javascript'
                
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            logger.error(f"语言检测失败: {str(e)}")
            logger.warning("使用默认的 'javascript'")
            return 'javascript'
    
    def _get_query_packs(self, language):
        """
        获取指定语言的查询包
        
        参数:
            language: 代码语言
            
        返回:
            查询包列表
        """
        # 标准查询包映射
        standard_packs = {
            'javascript': ['javascript-security-and-quality.qls'],
            'python': ['python-security-and-quality.qls'],
            'java': ['java-security-and-quality.qls'],
            'cpp': ['cpp-security-and-quality.qls'],
            'csharp': ['csharp-security-and-quality.qls'],
            'go': ['go-security-and-quality.qls'],
            'ruby': ['ruby-security-and-quality.qls'],
            'swift': ['swift-security-and-quality.qls'],
            'rust': ['rust-security-and-quality.qls'],
            'actions': ['actions-security-and-quality.qls']
        }
        
        # 获取标准查询包
        standard = standard_packs.get(language, [])
        standard_pack_paths = []
        
        for pack in standard:
            # 首先尝试从 codeql-suites 目录获取查询包
            suite_path = os.path.join(self.queries_path, 'ql', 'src', 'codeql-suites', pack)
            
            if os.path.exists(suite_path):
                standard_pack_paths.append(suite_path)
                logger.debug(f"找到查询套件: {suite_path}")
            else:
                # 如果找不到，使用原有路径格式
                alt_path = f"codeql/{language}/ql/src/Security/{pack}"
                standard_pack_paths.append(alt_path)
                logger.debug(f"使用替代查询套件路径: {alt_path}")
        
        return standard_pack_paths
    
    def _process_results(self, query_results, repo_path):
        """
        处理查询结果
        
        参数:
            query_results: 查询结果列表
            repo_path: 代码仓库路径
            
        返回:
            处理后的结果字典
        """
        logger.info("处理查询结果")
        
        # 按漏洞类型分组结果
        vulnerabilities_by_type = {}
        
        for result in query_results:
            # 提取基本信息
            query_id = result.get('ruleId', 'unknown')
            query_name = result.get('ruleName', 'Unknown Query')
            query_desc = result.get('ruleDescription', '')
            severity = result.get('severity', 'warning')
            
            # 处理位置信息
            locations = []
            for location in result.get('locations', []):
                uri = location.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                
                # 确保路径是相对于仓库根目录的
                if uri.startswith(repo_path):
                    uri = os.path.relpath(uri, repo_path)
                
                start_line = location.get('physicalLocation', {}).get('region', {}).get('startLine', 0)
                end_line = location.get('physicalLocation', {}).get('region', {}).get('endLine', start_line)
                
                locations.append({
                    'file': uri,
                    'start_line': start_line,
                    'end_line': end_line
                })
            
            # 提取代码片段
            code_snippets = []
            for loc in locations:
                file_path = os.path.join(repo_path, loc['file'])
                if os.path.exists(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            
                            # 提取上下文（前后各3行）
                            start = max(0, loc['start_line'] - 4)
                            end = min(len(lines), loc['end_line'] + 3)
                            
                            snippet = ''.join(lines[start:end])
                            code_snippets.append({
                                'file': loc['file'],
                                'start_line': start + 1,
                                'end_line': end,
                                'code': snippet
                            })
                    except Exception as e:
                        logger.warning(f"无法读取代码片段: {file_path}, 错误: {str(e)}")
            
            # 添加到结果集
            vuln_type = query_name.split(':')[0] if ':' in query_name else query_name
            
            if vuln_type not in vulnerabilities_by_type:
                vulnerabilities_by_type[vuln_type] = {
                    'type': vuln_type,
                    'description': query_desc,
                    'severity': severity,
                    'instances': []
                }
            
            vulnerabilities_by_type[vuln_type]['instances'].append({
                'query_id': query_id,
                'query_name': query_name,
                'locations': locations,
                'code_snippets': code_snippets
            })
        
        # 转换为列表形式
        vulnerabilities = list(vulnerabilities_by_type.values())
        
        # 按严重性排序
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'warning': 4, 'note': 5}
        vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'].lower(), 999))
        
        # 构建最终结果
        analysis_results = {
            'summary': {
                'total_vulnerabilities': len(query_results),
                'vulnerability_types': len(vulnerabilities),
                'severity_distribution': self._count_severity(vulnerabilities)
            },
            'vulnerabilities': vulnerabilities
        }
        
        return analysis_results
    
    def _count_severity(self, vulnerabilities):
        """
        统计各严重级别的漏洞数量
        
        参数:
            vulnerabilities: 漏洞列表
            
        返回:
            各严重级别的统计结果
        """
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'warning': 0,
            'note': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln['severity'].lower()
            instance_count = len(vuln['instances'])
            
            if severity in counts:
                counts[severity] += instance_count
            else:
                counts['warning'] += instance_count
        
        return counts
    
    # 添加获取可用规则集的方法
    def get_available_rule_sets(self, language):
        """
        获取指定语言的可用规则集
        
        参数:
            language: 代码语言
            
        返回:
            规则集列表
        """
        return self.rule_manager.get_available_rules(language)
    
    # 添加导入GitHub规则的方法
    def import_rule_from_github(self, language, rule_id, source_path):
        """
        从GitHub导入规则
        
        参数:
            language: 目标语言
            rule_id: 规则ID
            source_path: 源文件路径或GitHub URL
            
        返回:
            导入成功返回规则元数据，否则返回None
        """
        return self.rule_manager.import_rule_from_github(language, rule_id, source_path)
    
    # 添加搜索GitHub规则的方法
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
        return self.rule_manager.search_github_rules(language, keywords, category, limit)
    
    # 添加创建自定义规则集的方法
    def create_custom_rule_set(self, name, language, rule_ids, description=""):
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
        return self.rule_manager.create_ruleset(name, language, rule_ids, description) 