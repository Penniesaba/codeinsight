 #!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
LLM增强器模块
-----------
这个模块负责使用大语言模型增强代码分析结果，提供更好的漏洞描述和修复建议。
"""

import os
import json
import logging
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# 设置日志记录器
logger = logging.getLogger(__name__)

class LLMEnhancer:
    """
    大语言模型增强器类
    负责使用LLM增强分析结果
    """
    
    def __init__(self, config):
        """
        初始化LLM增强器
        
        参数:
            config: 配置对象，包含LLM相关配置
        """
        self.config = config
        self.api_key = config['LLM_API_KEY']
        self.model = config['LLM_MODEL']
        self.api_url = config['LLM_API_URL']
        
        # 检查API密钥是否可用
        if not self.api_key:
            logger.warning("未设置LLM API密钥，将使用模拟增强模式")
        
        logger.debug("LLM增强器初始化完成")
    
    def enhance_results(self, analysis_results, repo_path):
        """
        增强分析结果
        
        参数:
            analysis_results: CodeQL分析结果
            repo_path: 代码仓库路径
            
        返回:
            增强后的结果
        """
        logger.info("开始增强分析结果")
        
        # 如果没有API密钥，使用模拟增强
        if not self.api_key:
            logger.info("使用模拟增强模式")
            return self._mock_enhance_results(analysis_results)
        
        # 复制原始结果
        enhanced_results = {
            'summary': analysis_results['summary'],
            'vulnerabilities': []
        }
        
        # 创建线程池处理并行任务
        with ThreadPoolExecutor(max_workers=5) as executor:
            # 提交增强任务
            future_to_vuln = {}
            for vuln in analysis_results['vulnerabilities']:
                future = executor.submit(
                    self._enhance_vulnerability,
                    vuln,
                    repo_path
                )
                future_to_vuln[future] = vuln
            
            # 收集结果
            for future in as_completed(future_to_vuln):
                original_vuln = future_to_vuln[future]
                try:
                    enhanced_vuln = future.result()
                    enhanced_results['vulnerabilities'].append(enhanced_vuln)
                except Exception as e:
                    logger.error(f"增强漏洞失败: {str(e)}", exc_info=True)
                    # 如果增强失败，使用原始数据
                    enhanced_results['vulnerabilities'].append(original_vuln)
        
        # 添加总结
        try:
            enhanced_results['overview'] = self._generate_overview(enhanced_results)
        except Exception as e:
            logger.error(f"生成总结失败: {str(e)}", exc_info=True)
            enhanced_results['overview'] = self._mock_overview(enhanced_results)
        
        # 按严重性重新排序
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'warning': 4, 'note': 5}
        enhanced_results['vulnerabilities'].sort(
            key=lambda x: severity_order.get(x['severity'].lower(), 999)
        )
        
        logger.info("分析结果增强完成")
        return enhanced_results
    
    def _enhance_vulnerability(self, vulnerability, repo_path):
        """
        增强单个漏洞信息
        
        参数:
            vulnerability: 漏洞信息
            repo_path: 代码仓库路径
            
        返回:
            增强后的漏洞信息
        """
        vuln_type = vulnerability['type']
        description = vulnerability['description']
        instances = vulnerability['instances']
        
        logger.info(f"增强漏洞类型: {vuln_type}")
        
        # 复制原始数据
        enhanced_vuln = vulnerability.copy()
        
        # 为漏洞类型提供更详细的描述
        enhanced_description = self._generate_detailed_description(vuln_type, description)
        
        # 为每个实例提供修复建议
        enhanced_instances = []
        for instance in instances:
            # 复制原始实例
            enhanced_instance = instance.copy()
            
            # 生成修复建议
            try:
                fix_suggestions = self._generate_fix_suggestions(
                    vuln_type, 
                    instance['query_name'], 
                    instance['code_snippets']
                )
                enhanced_instance['fix_suggestions'] = fix_suggestions
            except Exception as e:
                logger.error(f"生成修复建议失败: {str(e)}", exc_info=True)
                enhanced_instance['fix_suggestions'] = {
                    'description': '无法生成修复建议',
                    'code_example': ''
                }
            
            enhanced_instances.append(enhanced_instance)
        
        # 更新增强后的漏洞信息
        enhanced_vuln['enhanced_description'] = enhanced_description
        enhanced_vuln['instances'] = enhanced_instances
        enhanced_vuln['common_fixes'] = self._generate_common_fixes(vuln_type, description)
        
        return enhanced_vuln
    
    def _generate_detailed_description(self, vuln_type, original_description):
        """
        生成详细的漏洞描述
        
        参数:
            vuln_type: 漏洞类型
            original_description: 原始描述
            
        返回:
            增强后的描述
        """
        prompt = f"""
        请详细解释以下安全漏洞类型，包括其工作原理、风险级别、可能的攻击场景和一般影响：

        漏洞类型: {vuln_type}
        原始描述: {original_description}

        请提供一个结构化的详细中文解释，包括以下几部分：
        1. 漏洞概述
        2. 技术原理
        3. 风险级别及影响
        4. 常见攻击场景
        """
        
        try:
            response = self._call_llm_api(prompt)
            # 提取回复内容
            detailed_description = self._extract_description(response, vuln_type)
            
            if not detailed_description or len(detailed_description) < 50:
                raise ValueError("生成的描述太短或为空")
                
            return detailed_description
        except Exception as e:
            logger.error(f"生成详细描述失败: {str(e)}", exc_info=True)
            return self._mock_detailed_description(vuln_type, original_description)
    
    def _generate_fix_suggestions(self, vuln_type, query_name, code_snippets):
        """
        生成修复建议
        
        参数:
            vuln_type: 漏洞类型
            query_name: 查询名称
            code_snippets: 代码片段
            
        返回:
            修复建议
        """
        if not code_snippets:
            return {
                'description': '没有可用的代码片段来生成修复建议',
                'code_example': ''
            }
        
        # 使用第一个代码片段
        snippet = code_snippets[0]
        file_path = snippet['file']
        start_line = snippet['start_line']
        end_line = snippet['end_line']
        code = snippet['code']
        
        prompt = f"""
        我需要你帮助修复以下代码中的安全漏洞:

        漏洞类型: {vuln_type}
        具体问题: {query_name}
        文件路径: {file_path}
        代码（{start_line}-{end_line}行）:

        ```
        {code}
        ```

        请提供:
        1. 详细的漏洞修复说明（中文）
        2. 修复后的代码示例
        3. 解释为什么这个修复可以解决问题
        """
        
        try:
            response = self._call_llm_api(prompt)
            
            # 解析响应，提取修复建议
            fix_description, code_example = self._extract_fix_suggestions(response)
            
            if not fix_description or len(fix_description) < 20:
                raise ValueError("生成的修复说明太短或为空")
                
            return {
                'description': fix_description,
                'code_example': code_example
            }
        except Exception as e:
            logger.error(f"生成修复建议失败: {str(e)}", exc_info=True)
            return self._mock_fix_suggestions(vuln_type, query_name)
    
    def _generate_common_fixes(self, vuln_type, description):
        """
        生成通用的修复建议
        
        参数:
            vuln_type: 漏洞类型
            description: 漏洞描述
            
        返回:
            通用修复建议
        """
        prompt = f"""
        请提供关于如何防范和修复以下安全漏洞的通用最佳实践和建议：

        漏洞类型: {vuln_type}
        漏洞描述: {description}

        请提供：
        1. 一般性修复策略
        2. 防御性编程建议
        3. 代码审查要点
        4. 相关的安全标准或指南

        请以中文回答，提供具体且实用的建议。
        """
        
        try:
            response = self._call_llm_api(prompt)
            common_fixes = self._extract_common_fixes(response)
            
            if not common_fixes or len(common_fixes) < 50:
                raise ValueError("生成的通用修复建议太短或为空")
                
            return common_fixes
        except Exception as e:
            logger.error(f"生成通用修复建议失败: {str(e)}", exc_info=True)
            return self._mock_common_fixes(vuln_type)
    
    def _generate_overview(self, enhanced_results):
        """
        生成分析结果的总体概述
        
        参数:
            enhanced_results: 增强后的结果
            
        返回:
            概述文本
        """
        summary = enhanced_results['summary']
        vulnerabilities = enhanced_results['vulnerabilities']
        
        # 准备漏洞类型列表和严重程度信息
        vuln_types = [v['type'] for v in vulnerabilities]
        severity_dist = summary['severity_distribution']
        
        prompt = f"""
        请根据以下软件安全分析结果，生成一个全面的安全评估总结报告：

        总计发现的漏洞数量: {summary['total_vulnerabilities']}
        漏洞类型数量: {summary['vulnerability_types']}
        严重程度分布:
        - 严重: {severity_dist.get('critical', 0)}
        - 高危: {severity_dist.get('high', 0)}
        - 中危: {severity_dist.get('medium', 0)}
        - 低危: {severity_dist.get('low', 0)}
        - 警告: {severity_dist.get('warning', 0)}

        发现的漏洞类型:
        {", ".join(vuln_types)}

        请提供:
        1. 安全状况总体评估
        2. 重点关注的高危漏洞分析
        3. 安全改进的优先级建议
        4. 如何进行持续的安全监控

        请以中文回答，语言专业、客观，针对研发和安全团队提供有价值的见解。
        """
        
        try:
            response = self._call_llm_api(prompt)
            overview = self._extract_overview(response)
            
            if not overview or len(overview) < 100:
                raise ValueError("生成的总结报告太短或为空")
                
            return overview
        except Exception as e:
            logger.error(f"生成总结报告失败: {str(e)}", exc_info=True)
            return self._mock_overview(enhanced_results)
    
    def _call_llm_api(self, prompt):
        """
        调用LLM API
        
        参数:
            prompt: 提示文本
            
        返回:
            API响应
        """
        # 通义千问API请求格式
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        data = {
            "model": self.model,
            "input": {
                "messages": [
                    {
                        "role": "system",
                        "content": "你是一个专业的代码安全分析助手，擅长解释和提供安全漏洞的修复方案。请用中文回复。"
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            },
            "parameters": {}
        }
        
        logger.debug(f"发送LLM API请求: {self.api_url}")
        
        # 尝试调用API，失败后重试
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    headers=headers,
                    json=data,
                    timeout=30
                )
                
                response.raise_for_status()
                result = response.json()
                
                # 提取回复内容
                if "output" in result and "text" in result["output"]:
                    return result["output"]["text"]
                
                # 如果没有按预期格式返回，尝试其他格式
                if "choices" in result and len(result["choices"]) > 0:
                    if "message" in result["choices"][0]:
                        return result["choices"][0]["message"]["content"]
                    elif "text" in result["choices"][0]:
                        return result["choices"][0]["text"]
                
                # 尝试通用提取
                return str(result)
                
            except requests.RequestException as e:
                logger.warning(f"API请求失败 (尝试 {attempt+1}/{max_retries}): {str(e)}")
                if attempt == max_retries - 1:
                    raise
                time.sleep(2)  # 重试前等待
    
    # 辅助方法：提取响应内容
    def _extract_description(self, response, vuln_type):
        """从API响应中提取漏洞描述"""
        # 简单实现：直接返回响应
        return response.strip()
    
    def _extract_fix_suggestions(self, response):
        """从API响应中提取修复建议和代码示例"""
        lines = response.split('\n')
        
        description = []
        code_example = []
        in_code_block = False
        
        for line in lines:
            if line.strip().startswith('```'):
                in_code_block = not in_code_block
                continue
                
            if in_code_block:
                code_example.append(line)
            else:
                description.append(line)
        
        return '\n'.join(description).strip(), '\n'.join(code_example).strip()
    
    def _extract_common_fixes(self, response):
        """从API响应中提取通用修复建议"""
        return response.strip()
    
    def _extract_overview(self, response):
        """从API响应中提取总结概述"""
        return response.strip()
    
    # 模拟方法（当LLM API不可用时使用）
    def _mock_enhance_results(self, analysis_results):
        """模拟增强分析结果"""
        logger.info("使用模拟方法增强结果")
        
        # 复制原始结果
        enhanced_results = {
            'summary': analysis_results['summary'],
            'vulnerabilities': []
        }
        
        # 模拟增强每个漏洞
        for vuln in analysis_results['vulnerabilities']:
            enhanced_vuln = vuln.copy()
            
            # 添加模拟的增强描述
            enhanced_vuln['enhanced_description'] = self._mock_detailed_description(
                vuln['type'], vuln['description']
            )
            
            # 添加模拟的共同修复建议
            enhanced_vuln['common_fixes'] = self._mock_common_fixes(vuln['type'])
            
            # 为每个实例添加模拟的修复建议
            enhanced_instances = []
            for instance in vuln['instances']:
                enhanced_instance = instance.copy()
                enhanced_instance['fix_suggestions'] = self._mock_fix_suggestions(
                    vuln['type'], instance['query_name']
                )
                enhanced_instances.append(enhanced_instance)
            
            enhanced_vuln['instances'] = enhanced_instances
            enhanced_results['vulnerabilities'].append(enhanced_vuln)
        
        # 添加模拟的总结
        enhanced_results['overview'] = self._mock_overview(enhanced_results)
        
        return enhanced_results
    
    def _mock_detailed_description(self, vuln_type, original_description):
        """生成模拟的详细描述"""
        return f"""
        ## 漏洞概述
        {vuln_type}是一种常见的安全漏洞，可能导致应用程序面临严重的安全风险。
        
        ## 技术原理
        此类漏洞通常由于开发人员未正确验证或处理用户输入，导致攻击者能够执行恶意操作。
        {original_description}
        
        ## 风险级别及影响
        根据漏洞的具体情况，其风险级别可能从低到高不等。高风险情况下，可能导致数据泄露、系统被控制或服务中断。
        
        ## 常见攻击场景
        攻击者可能会利用此漏洞来执行未授权操作，如访问敏感数据、提升权限或导致拒绝服务。
        """
    
    def _mock_fix_suggestions(self, vuln_type, query_name):
        """生成模拟的修复建议"""
        return {
            'description': f"""
            针对{vuln_type}类型的漏洞，建议进行以下修复：
            
            1. 对所有用户输入进行严格验证和过滤
            2. 使用参数化查询或预编译语句
            3. 实施最小权限原则
            4. 定期更新和补丁系统
            
            具体针对"{query_name}"，应当特别注意输入验证和输出编码。
            """,
            'code_example': f"""
            // 修复示例代码
            // 请根据实际情况调整
            
            // 不安全的实现
            // query = "SELECT * FROM users WHERE username = '" + username + "'";
            
            // 安全的实现
            PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE username = ?");
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            """
        }
    
    def _mock_common_fixes(self, vuln_type):
        """生成模拟的通用修复建议"""
        return f"""
        ## 一般性修复策略
        
        针对{vuln_type}类型的漏洞，建议采取以下通用修复策略：
        
        1. **输入验证**：对所有用户输入进行严格的验证，确保其符合预期的格式和范围。
        
        2. **输出编码**：在显示用户提供的数据前对其进行适当编码，防止XSS和注入攻击。
        
        3. **使用安全库和框架**：优先使用经过安全审查的库和框架，而不是自己实现安全功能。
        
        4. **定期安全审查**：定期对代码进行安全审查，及时发现和修复潜在的漏洞。
        
        ## 防御性编程建议
        
        1. 始终假设用户输入是恶意的，并据此设计代码。
        
        2. 实施最小权限原则，确保代码只拥有完成任务所需的最小权限。
        
        3. 使用安全默认值，避免在出错时暴露敏感信息。
        
        ## 代码审查要点
        
        1. 检查所有用户输入的验证逻辑
        
        2. 审查敏感操作的权限控制
        
        3. 确保不存在硬编码的密钥或凭证
        
        ## 相关安全标准和指南
        
        - OWASP安全编码实践
        - CWE (Common Weakness Enumeration)
        - NIST安全指南
        """
    
    def _mock_overview(self, enhanced_results):
        """生成模拟的总结概述"""
        summary = enhanced_results['summary']
        vulnerabilities = enhanced_results['vulnerabilities']
        
        critical_count = summary['severity_distribution'].get('critical', 0)
        high_count = summary['severity_distribution'].get('high', 0)
        
        risk_level = "低"
        if critical_count > 0:
            risk_level = "严重"
        elif high_count > 0:
            risk_level = "高"
        elif summary['total_vulnerabilities'] > 10:
            risk_level = "中"
        
        # 找出最严重的几类漏洞
        top_vulns = sorted(
            vulnerabilities, 
            key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'warning': 4, 'note': 5}.get(x['severity'].lower(), 999)
        )[:3]
        
        top_types = [v['type'] for v in top_vulns]
        
        return f"""
        # 安全分析总结报告
        
        ## 安全状况总体评估
        
        本次安全扫描共发现{summary['total_vulnerabilities']}个潜在安全问题，涉及{summary['vulnerability_types']}种不同类型的漏洞。根据发现的漏洞严重程度和数量，当前代码的整体安全风险评级为**{risk_level}**。
        
        安全漏洞严重程度分布：
        - 严重级别: {summary['severity_distribution'].get('critical', 0)}个
        - 高危级别: {summary['severity_distribution'].get('high', 0)}个
        - 中危级别: {summary['severity_distribution'].get('medium', 0)}个
        - 低危级别: {summary['severity_distribution'].get('low', 0)}个
        - 警告级别: {summary['severity_distribution'].get('warning', 0)}个
        
        ## 重点关注的高危漏洞分析
        
        根据扫描结果，以下漏洞类型应优先处理：
        
        1. {top_types[0] if len(top_types) > 0 else '无高危漏洞'}
        2. {top_types[1] if len(top_types) > 1 else ''}
        3. {top_types[2] if len(top_types) > 2 else ''}
        
        这些漏洞可能导致数据泄露、未授权访问或应用程序稳定性问题，应当尽快修复。
        
        ## 安全改进的优先级建议
        
        1. **立即修复严重和高危漏洞**：优先解决所有严重和高危级别的安全问题，特别是那些可能导致远程代码执行、信息泄露或权限提升的漏洞。
        
        2. **加强输入验证和输出编码**：针对XSS、SQL注入等常见漏洞，实施更严格的输入验证和输出编码机制。
        
        3. **更新依赖库**：检查并更新所有过时的依赖库，确保使用最新的安全补丁。
        
        4. **实施安全编码规范**：建立并遵循安全编码规范，在开发过程中预防常见安全问题。
        
        ## 持续安全监控建议
        
        1. **集成自动化安全扫描**：在CI/CD流程中集成自动化安全扫描，确保新代码不会引入新的安全问题。
        
        2. **定期安全审计**：每季度进行一次全面的安全审计，检查代码和配置中的潜在安全问题。
        
        3. **安全培训**：为开发团队提供定期的安全意识培训，提高团队的安全意识和技能。
        
        4. **建立安全响应流程**：制定明确的安全漏洞响应流程，确保发现安全问题时能够快速响应和修固。
        """