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
import uuid  # 添加uuid模块导入
import datetime  # 添加日期时间模块导入

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
        
        # 获取缓存目录
        self.cache_dir = config.get('CACHE_DIR', os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'cache'))
        
        # 创建qlresults目录
        self.qlresults_dir = os.path.join(self.cache_dir, 'qlresults')
        os.makedirs(self.qlresults_dir, exist_ok=True)
        
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
        
        # 提取任务ID
        task_id = self._extract_task_id(repo_path)
        
        # 创建临时目录存放数据库
        with tempfile.TemporaryDirectory() as db_dir:
            try:
                # 1. 创建CodeQL数据库
                db_path = os.path.join(db_dir, 'codeql_db')
                self._create_database(repo_path, db_path, language)
                
                # 2. 运行查询
                query_results = self._run_queries(db_path, language, rule_set, task_id)
                
                # 3. 处理结果
                analysis_results = self._process_results(query_results, repo_path)
                
                return analysis_results
                
            except Exception as e:
                logger.error(f"仓库分析失败: {str(e)}", exc_info=True)
                raise RuntimeError(f"仓库分析失败: {str(e)}")
    
    def _extract_task_id(self, repo_path):
        """
        从仓库路径中提取任务ID
        
        参数:
            repo_path: 仓库路径
            
        返回:
            任务ID或None
        """
        try:
            # 假设路径格式为 /path/to/cache/repos/{task_id}/repo_name
            parts = repo_path.split(os.sep)
            repos_index = parts.index('repos')
            if repos_index < len(parts) - 1:
                return parts[repos_index + 1]
        except (ValueError, IndexError):
            pass
        
        # 如果无法从路径提取，生成一个新的ID
        return str(uuid.uuid4())
    
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
    
    def _run_queries(self, db_path, language, rule_set=None, task_id=None):
        """
        运行CodeQL查询
        
        参数:
            db_path: 数据库路径
            language: 代码语言
            rule_set: 使用的规则集，如果为None则使用默认规则集
            task_id: 分析任务ID
            
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
            logger.info(f"使用指定规则集: {rule_set}")
            query_packs = [rule_set]
        else:
            query_packs = self._get_query_packs(language)

        # 无论如何都加载自定义规则
            custom_rules = self.rule_manager._get_custom_rules(language)
            custom_rules = [rule['path'] for rule in custom_rules]
            
        logger.debug(f"自定义规则路径: {custom_rules}")
        
        results = []
        
        # 首先运行标准查询包（批量方式）
        if query_packs:
            logger.info(f"运行标准查询包，共 {len(query_packs)} 个")
            
            for query_pack in query_packs:


                logger.info(f"运行查询包: {query_pack}")
                
                # 确定结果文件路径
                timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
                pack_name = os.path.basename(query_pack)
                result_filename = f"{pack_name}_{timestamp}.sarif"
                
                # 如果有任务ID，则保存到任务的qlresults目录
                task_results_dir = None
                if task_id:
                    task_results_dir = os.path.join(self.qlresults_dir, task_id)
                    os.makedirs(task_results_dir, exist_ok=True)
                    results_path = os.path.join(task_results_dir, result_filename)
                else:
                    # 创建临时结果文件
                    with tempfile.NamedTemporaryFile(suffix='.sarif', delete=False) as temp_file:
                        results_path = temp_file.name
                
                try:
                    # 运行查询
                    cmd = [
                        self.codeql_path, 'database', 'analyze',
                        '--format=sarif-latest',
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
                        sarif_content = f.read()
                        pack_results = json.loads(sarif_content)
                        
                        # 确定是否有结果
                        result_count = 0
                        for run in pack_results.get('runs', []):
                            result_count += len(run.get('results', []))
                        
                        # 添加到结果列表
                        results.append(pack_results)
                        
                        # 记录日志
                        if result_count > 0:
                            logger.info(f"查询包 {query_pack} 找到 {result_count} 个问题")
                            if task_id:
                                logger.info(f"SARIF结果文件保存在: {results_path}")
                        else:
                            logger.info(f"查询包 {query_pack} 未找到问题")
                            # 如果没有找到问题且有任务ID，删除结果文件以节省空间
                            if task_id and os.path.exists(results_path):
                                os.unlink(results_path)
                    
                except subprocess.CalledProcessError as e:
                    logger.error(f"查询执行失败: {e.stderr}")
                    # 保存错误日志
                    if task_results_dir:
                        error_file = os.path.join(task_results_dir, f"{pack_name}_{timestamp}_error.log")
                        with open(error_file, 'w', encoding='utf-8') as f:
                            f.write(f"命令: {' '.join(cmd)}\n")
                            f.write(f"错误: {e.stderr}\n")
                    # 继续执行其他查询包，不中断过程
                finally:
                    # 如果是临时文件且没有任务ID，则删除
                    if not task_id and os.path.exists(results_path):
                        os.unlink(results_path)
        
        # 然后逐条运行自定义规则
        if custom_rules:
            logger.info(f"运行自定义规则，共 {len(custom_rules)} 条")
            
            for rule_path in custom_rules:
                rule_name = os.path.basename(rule_path)
                logger.info(f"运行自定义规则: {rule_name}")
                
                try:
                    # 逐条运行规则
                    rule_results = self._run_single_query(db_path, rule_path, task_id)
                    if rule_results:
                        results.extend(rule_results)
                        logger.info(f"规则 {rule_name} 找到 {len(rule_results)} 个问题")
                    else:
                        logger.info(f"规则 {rule_name} 未找到问题")
                        
                except Exception as e:
                    logger.error(f"自定义规则 {rule_name} 执行失败: {str(e)}")
        
        logger.info(f"查询完成，共找到 {len(results)} 条结果")
        return results
    
    def _run_single_query(self, db_path, query_path, task_id=None):
        """
        运行单个查询规则
        
        参数:
            db_path: 数据库路径
            query_path: 查询文件路径
            task_id: 任务ID，用于保存结果
            
        返回:
            查询结果列表
        """
        # 生成一个唯一的结果文件名
        rule_name = os.path.basename(query_path).replace('.ql', '')
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        result_filename = f"{rule_name}_{timestamp}.sarif"
        
        # 创建任务结果目录
        task_results_dir = None
        if task_id:
            task_results_dir = os.path.join(self.qlresults_dir, task_id)
            os.makedirs(task_results_dir, exist_ok=True)
            results_path = os.path.join(task_results_dir, result_filename)
        else:
            # 创建临时结果文件
            with tempfile.NamedTemporaryFile(suffix='.sarif', delete=False) as temp_file:
                results_path = temp_file.name
        
        try:
            # 构建命令
            cmd = [
                self.codeql_path, 'database', 'analyze',
                '--format=sarif-latest',
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
            
            # 保存命令输出到日志文件
            if task_results_dir:
                stdout_file = os.path.join(task_results_dir, f"{rule_name}_{timestamp}_stdout.log")
                with open(stdout_file, 'w', encoding='utf-8') as f:
                    f.write(process.stdout)
                
                stderr_file = os.path.join(task_results_dir, f"{rule_name}_{timestamp}_stderr.log")
                with open(stderr_file, 'w', encoding='utf-8') as f:
                    f.write(process.stderr)
            
            # 读取结果
            if os.path.exists(results_path) and os.path.getsize(results_path) > 0:
                with open(results_path, 'r', encoding='utf-8') as f:
                    try:
                        # 读取原始内容
                        sarif_content = f.read()
                        
                        # 解析SARIF格式并计算问题数量
                        try:
                            sarif_doc = json.loads(sarif_content)
                            
                            # 计算结果数量
                            result_count = 0
                            for run in sarif_doc.get('runs', []):
                                result_count += len(run.get('results', []))
                            
                            if result_count > 0:
                                logger.info(f"规则 {os.path.basename(query_path)} 找到 {result_count} 个问题")
                                logger.info(f"SARIF结果文件保存在: {results_path}")
                                
                                # 增强sarif_doc，添加规则名称和规则文件路径信息
                                rule_name = os.path.basename(query_path).replace('.ql', '')
                                sarif_doc['_meta'] = {
                                    'rule_name': rule_name,
                                    'rule_path': query_path,
                                    'results_path': results_path
                                }
                                
                                return sarif_doc
                            else:
                                logger.info(f"规则 {os.path.basename(query_path)} 未找到问题")
                                # 如果没有找到问题但有任务ID，删除结果文件以节省空间
                                if task_id and os.path.exists(results_path):
                                    os.unlink(results_path)
                                return None
                                
                        except json.JSONDecodeError as e:
                            # 尝试清理JSON内容
                            try:
                                # 寻找有效的JSON部分
                                json_start = sarif_content.find('{')
                                json_end = sarif_content.rfind('}') + 1
                                
                                if json_start >= 0 and json_end > json_start:
                                    clean_json = sarif_content[json_start:json_end]
                                    sarif_doc = json.loads(clean_json)
                                    
                                    # 计算结果数量
                                    result_count = 0
                                    for run in sarif_doc.get('runs', []):
                                        result_count += len(run.get('results', []))
                                    
                                    if result_count > 0:
                                        logger.info(f"规则 {os.path.basename(query_path)} 找到 {result_count} 个问题")
                                        logger.info(f"SARIF结果文件保存在: {results_path}")
                                        
                                        # 增强sarif_doc，添加规则名称和规则文件路径信息
                                        rule_name = os.path.basename(query_path).replace('.ql', '')
                                        sarif_doc['_meta'] = {
                                            'rule_name': rule_name,
                                            'rule_path': query_path,
                                            'results_path': results_path
                                        }
                                        
                                        return sarif_doc
                                    else:
                                        logger.info(f"规则 {os.path.basename(query_path)} 未找到问题")
                                        # 如果没有找到问题但有任务ID，删除结果文件以节省空间
                                        if task_id and os.path.exists(results_path):
                                            os.unlink(results_path)
                                        return None
                                        
                                else:
                                    logger.warning(f"无法在结果中找到有效的JSON内容: {results_path}")
                                    # 保存原始内容以便调试
                                    if task_results_dir:
                                        debug_file = os.path.join(task_results_dir, f"{rule_name}_{timestamp}_debug.txt")
                                        with open(debug_file, 'w', encoding='utf-8') as f:
                                            f.write(sarif_content)
                                    logger.debug(f"原始内容（前100字符）: {sarif_content[:100]}")
                                    return None
                                    
                            except Exception as json_e:
                                logger.warning(f"清理JSON失败: {str(json_e)}")
                                # 保存原始内容以便调试
                                if task_results_dir:
                                    debug_file = os.path.join(task_results_dir, f"{rule_name}_{timestamp}_debug.txt")
                                    with open(debug_file, 'w', encoding='utf-8') as f:
                                        f.write(sarif_content)
                                logger.debug(f"原始内容（前100字符）: {sarif_content[:100]}")
                                return None
                                
                    except Exception as read_e:
                        logger.warning(f"读取结果文件失败: {str(read_e)}")
                        return None
            else:
                logger.info(f"查询未返回结果")
                return None
                
        except subprocess.CalledProcessError as e:
            logger.error(f"查询执行失败: {e.stderr}")
            # 保存错误信息到日志文件
            if task_results_dir:
                error_file = os.path.join(task_results_dir, f"{rule_name}_{timestamp}_error.log")
                with open(error_file, 'w', encoding='utf-8') as f:
                    f.write(f"命令: {' '.join(cmd)}\n")
                    f.write(f"错误: {e.stderr}\n")
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"查询执行超时")
            return None
        except Exception as e:
            logger.error(f"查询执行出错: {str(e)}")
            return None
        finally:
            # 如果是临时文件且没有任务ID，则删除
            if not task_id and os.path.exists(results_path):
                os.unlink(results_path)
    
    def _extract_vulnerability_details(self, rule_id, rule_name, rule):
        """
        提取并增强漏洞详细信息
        
        参数:
            rule_id: 规则ID
            rule_name: 规则名称
            rule: 规则对象
            
        返回:
            增强的漏洞信息字典
        """
        # 检查是否是自定义规则
        is_custom_rule = 'custom_rules' in rule_id if isinstance(rule_id, str) else False
        
        # 从规则标签中提取安全分类信息
        tags = rule.get('properties', {}).get('tags', [])
        owasp_category = None
        cwe_id = None
        
        for tag in tags:
            if isinstance(tag, str):
                if tag.startswith('owasp'):
                    owasp_category = tag
                elif tag.startswith('cwe'):
                    cwe_id = tag
        
        # 确定漏洞严重性
        severity = rule.get('defaultConfiguration', {}).get('level', 'warning')
        severity_map = {
            'error': 'high',
            'warning': 'medium',
            'note': 'low',
            'none': 'info'
        }
        severity = severity_map.get(severity, severity)
        
        # 根据规则ID和名称映射安全信息
        rule_base_name = rule_name.lower() if rule_name else ''
        
        # 默认值
        security_impact = ""
        common_fixes = ""
        best_practices = ""
        owasp_link = ""
        cwe_link = ""
        cvss_score = 0
        
        # 根据规则类型添加详细信息
        if 'unsafe-input' in rule_base_name or 'unsafe-input' in rule_id:
            owasp_category = owasp_category or 'A1:2021-Injection'
            cwe_id = cwe_id or 'CWE-20: Improper Input Validation'
            owasp_link = 'https://owasp.org/Top10/A03_2021-Injection/'
            cwe_link = 'https://cwe.mitre.org/data/definitions/20.html'
            cvss_score = 7.5
            security_impact = """
                <p>不安全的输入处理可导致:</p>
                <ul>
                    <li><strong>注入攻击</strong>: 攻击者可能注入恶意代码或命令到应用程序中</li> 
                    <li><strong>数据篡改</strong>: 可能导致应用程序处理非预期数据</li>
                    <li><strong>应用程序逻辑受损</strong>: 可能绕过业务逻辑验证</li>
                </ul>
            """
            common_fixes = """
                <p>修复不安全的输入处理:</p>
                <ol>
                    <li>始终对所有外部来源的数据进行验证</li>
                    <li>实施白名单验证而非黑名单过滤</li>
                    <li>对所有用户输入应用适当的编码或转义</li>
                    <li>使用参数化查询而非字符串拼接</li>
                </ol>
            """
            best_practices = """
                <p>防止不安全输入的最佳实践:</p>
                <ul>
                    <li>实施集中式的输入验证机制</li>
                    <li>在服务器端进行验证，不要仅依赖客户端验证</li>
                    <li>考虑使用OWASP ESAPI等安全库来处理输入验证</li>
                    <li>定期进行安全代码审查和渗透测试</li>
                </ul>
            """
        elif 'unsafe-error' in rule_base_name or 'error-handling' in rule_id:
            owasp_category = owasp_category or 'A10:2021-Server-Side Request Forgery'
            cwe_id = cwe_id or 'CWE-209: Information Exposure Through an Error Message'
            owasp_link = 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
            cwe_link = 'https://cwe.mitre.org/data/definitions/209.html'
            cvss_score = 5.0
            security_impact = """
                <p>不安全的错误处理可导致:</p>
                <ul>
                    <li><strong>信息泄露</strong>: 错误消息可能泄露敏感信息、内部路径或技术细节</li> 
                    <li><strong>攻击面暴露</strong>: 暴露应用程序的内部工作方式，帮助攻击者构建更有效的攻击</li>
                    <li><strong>调试信息泄露</strong>: 泄露堆栈跟踪或系统配置信息</li>
                </ul>
            """
            common_fixes = """
                <p>修复不安全的错误处理:</p>
                <ol>
                    <li>实现集中式的错误处理机制</li>
                    <li>向用户显示通用错误消息，同时在服务器端记录详细信息</li>
                    <li>确保生产环境中禁用详细的错误信息</li>
                    <li>使用适当的日志记录机制，并确保敏感信息在记录前被脱敏</li>
                </ol>
            """
            best_practices = """
                <p>错误处理最佳实践:</p>
                <ul>
                    <li>使用try-catch块捕获所有可能的异常</li>
                    <li>区分用户消息和系统日志</li>
                    <li>在生产环境中实施强大的错误处理机制</li>
                    <li>定期审查错误处理和日志机制</li>
                </ul>
            """
        elif 'xss' in rule_base_name or 'cross-site' in rule_base_name:
            owasp_category = owasp_category or 'A7:2021-Cross-Site Scripting'
            cwe_id = cwe_id or 'CWE-79: Improper Neutralization of Input During Web Page Generation'
            owasp_link = 'https://owasp.org/Top10/A03_2021-Injection/'
            cwe_link = 'https://cwe.mitre.org/data/definitions/79.html'
            cvss_score = 6.1
            security_impact = """
                <p>XSS漏洞可导致:</p>
                <ul>
                    <li><strong>会话劫持</strong>: 攻击者可以窃取用户的会话令牌</li> 
                    <li><strong>凭证盗窃</strong>: 可能通过伪造登录表单窃取用户凭证</li>
                    <li><strong>内容篡改</strong>: 攻击者可以修改网页内容，欺骗用户</li>
                    <li><strong>恶意重定向</strong>: 将用户重定向到钓鱼网站</li>
                </ul>
            """
            common_fixes = """
                <p>修复XSS漏洞:</p>
                <ol>
                    <li>对所有输出进行编码，使用适当的上下文相关编码</li>
                    <li>实施内容安全政策(CSP)</li>
                    <li>使用现代框架的内置XSS保护功能</li>
                    <li>验证输入并过滤危险内容</li>
                </ol>
            """
            best_practices = """
                <p>防止XSS的最佳实践:</p>
                <ul>
                    <li>使用安全的JavaScript框架如React、Vue等，它们有内置的XSS保护</li>
                    <li>实施强大的CSP策略</li>
                    <li>使用HttpOnly和Secure标志保护Cookie</li>
                    <li>定期进行安全测试和代码审计</li>
                </ul>
            """
        
        # 返回增强的漏洞信息
        return {
            'owasp_category': owasp_category,
            'cwe_id': cwe_id,
            'owasp_link': owasp_link,
            'cwe_link': cwe_link,
            'severity': severity,
            'cvss_score': cvss_score,
            'security_impact': security_impact,
            'common_fixes': common_fixes,
            'best_practices': best_practices,
            'is_custom_rule': is_custom_rule
        }

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
        
        # 处理 sarif 格式结果
        processed_results = []
        result_items_with_issues = 0
        
        # 修复：增加结果统计计数
        total_results = len(query_results)
        processed_count = 0
        valid_results = 0
        
        for result_item in query_results:
            processed_count += 1
            
            # 跳过空结果
            if not result_item:
                continue
                
            valid_results += 1
                
            # 处理字符串结果（尝试解析为JSON）
            if isinstance(result_item, str):
                try:
                    # 尝试清理SARIF字符串，有些输出可能在JSON之前或之后有额外文本
                    json_start = result_item.find('{')
                    json_end = result_item.rfind('}') + 1
                    if json_start >= 0 and json_end > json_start:
                        clean_json = result_item[json_start:json_end]
                        result_item = json.loads(clean_json)
                    else:
                        result_item = json.loads(result_item)
                except json.JSONDecodeError:
                    logger.warning(f"无法解析结果字符串为JSON: {result_item[:100]}...")
                    continue
            
            # 跳过非字典类型的结果
            if not isinstance(result_item, dict):
                logger.warning(f"跳过非字典类型结果: {type(result_item)}")
                continue
            
            # 检查是否有结果
            has_results = False
            result_count = 0
            
            # 修复：正确处理SARIF格式
            if 'runs' in result_item:
                for run in result_item.get('runs', []):
                    results = run.get('results', [])
                    if results:
                        has_results = True
                        result_count += len(results)
            
            if has_results:
                result_items_with_issues += 1
                logger.info(f"发现包含 {result_count} 个问题的结果")
                
            # 添加到已处理结果列表
            processed_results.append(result_item)
        
        logger.info(f"成功处理 {len(processed_results)}/{total_results} 个结果文件，{result_items_with_issues} 个包含问题")
        
        # 使用处理后的结果
        for sarif_doc in processed_results:
            # 获取自定义元数据
            meta = sarif_doc.get('_meta', {})
            rule_path = meta.get('rule_path', '')
            
            # 处理 sarif 格式
            for run in sarif_doc.get('runs', []):
                # 获取规则信息
                rules_dict = {}
                tool_info = run.get('tool', {}).get('driver', {})
                tool_name = tool_info.get('name', 'CodeQL')
                
                for rule in tool_info.get('rules', []):
                    rule_id = rule.get('id', 'unknown')
                    rules_dict[rule_id] = rule
                
                # 处理结果
                for result in run.get('results', []):
                    # 提取基本信息
                    rule_id = result.get('ruleId', 'unknown')
                    rule = rules_dict.get(rule_id, {})
                    
                    # 获取规则名称和描述
                    query_name = rule.get('name', rule_id)
                    query_desc = rule.get('fullDescription', {}).get('text', '') or rule.get('shortDescription', {}).get('text', '')
                    message = result.get('message', {}).get('text', '')
                    
                    # 增强漏洞信息
                    enhanced_info = self._extract_vulnerability_details(rule_id, query_name, rule)
                    severity = enhanced_info.get('severity', 'warning')
            
                    # 处理位置信息
                    locations = []
                    for location in result.get('locations', []):
                        uri = location.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                        
                        # 确保路径是相对于仓库根目录的
                        if uri.startswith(repo_path):
                            uri = os.path.relpath(uri, repo_path)
                        
                        region = location.get('physicalLocation', {}).get('region', {})
                        start_line = region.get('startLine', 0)
                        end_line = region.get('endLine', start_line)
                        
                        # 尝试获取更多位置信息
                        start_column = region.get('startColumn', 0)
                        end_column = region.get('endColumn', 0)
                        
                        locations.append({
                            'file': uri,
                            'start_line': start_line,
                            'end_line': end_line,
                            'start_column': start_column,
                            'end_column': end_column
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
                    
                    # 提供修复建议
                    fix_suggestions = None
                    if message:
                        fix_suggestions = {
                            'description': message,
                            'code_example': None  # 可在未来版本中基于规则自动生成示例代码
                        }
                    
                    # 添加参考资料
                    references = []
                    if enhanced_info.get('owasp_link'):
                        references.append({
                            'title': f'OWASP: {enhanced_info.get("owasp_category", "")}',
                            'url': enhanced_info.get('owasp_link')
                        })
                    if enhanced_info.get('cwe_link'):
                        references.append({
                            'title': f'CWE: {enhanced_info.get("cwe_id", "")}',
                            'url': enhanced_info.get('cwe_link')
                        })
                    
                    # 确定漏洞类型（增强可读性）
                    vuln_type = query_name.split(':')[0] if ':' in query_name else query_name
                    vuln_type = vuln_type.replace('_', ' ').replace('-', ' ').title()
                    
                    # 添加到结果集
                    if vuln_type not in vulnerabilities_by_type:
                        vulnerabilities_by_type[vuln_type] = {
                            'type': vuln_type,
                            'description': query_desc,
                            'severity': severity,
                            'owasp_category': enhanced_info.get('owasp_category'),
                            'cwe_id': enhanced_info.get('cwe_id'),
                            'owasp_link': enhanced_info.get('owasp_link'),
                            'cwe_link': enhanced_info.get('cwe_link'),
                            'cvss_score': enhanced_info.get('cvss_score'),
                            'security_impact': enhanced_info.get('security_impact'),
                            'common_fixes': enhanced_info.get('common_fixes'),
                            'best_practices': enhanced_info.get('best_practices'),
                            'instances': []
                        }
                    
                    vulnerabilities_by_type[vuln_type]['instances'].append({
                        'query_id': rule_id,
                        'query_name': query_name,
                        'message': message,
                        'locations': locations,
                        'code_snippets': code_snippets,
                        'fix_suggestions': fix_suggestions,
                        'references': references
                    })
        
        # 转换为列表形式
        vulnerabilities = list(vulnerabilities_by_type.values())
        
        # 按严重性排序
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'warning': 4, 'note': 5}
        vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'].lower(), 999))
        
        # 构建最终结果
        total_instances = sum(len(vuln['instances']) for vuln in vulnerabilities)
        
        # 确保报告有内容
        # 修复：如果日志中显示有问题但解析失败，添加默认漏洞信息，更加精确的判断
        if total_instances == 0 and (result_items_with_issues > 0 or valid_results > 0):
            # 检测到了问题但解析失败了，添加一个默认的漏洞类型
            logger.warning("检测到问题但解析失败，添加默认漏洞信息")
            vulnerabilities.append({
                'type': '潜在安全问题',
                'description': '系统检测到潜在安全问题，但无法提供详细信息。详情请查看日志。',
                'severity': 'warning',
                'owasp_category': 'A6:2021-Vulnerable and Outdated Components',
                'cwe_id': 'CWE-1000: Research Concepts',
                'owasp_link': 'https://owasp.org/Top10/',
                'cwe_link': 'https://cwe.mitre.org/',
                'cvss_score': 5.0,
                'security_impact': '<p>系统已检测到安全问题，但无法确定具体影响。</p>',
                'common_fixes': '<p>请查看日志获取更多信息，并考虑手动审查相关代码。</p>',
                'instances': [{
                    'query_name': '自定义规则', 
                    'message': '检测到代码可能存在安全漏洞，但无法获取详细信息',
                    'locations': [], 
                    'code_snippets': [],
                    'references': [
                        {'title': 'OWASP Top 10', 'url': 'https://owasp.org/Top10/'},
                        {'title': 'CWE Top 25', 'url': 'https://cwe.mitre.org/top25/'},
                    ]
                }]
            })
            total_instances = 1
        
        analysis_results = {
            'summary': {
                'total_vulnerabilities': total_instances,
                'vulnerability_types': len(vulnerabilities),
                'severity_distribution': self._count_severity(vulnerabilities)
            },
            'vulnerabilities': vulnerabilities
        }
        
        logger.info(f"分析完成，共发现 {total_instances} 个安全问题，{len(vulnerabilities)} 种漏洞类型")
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