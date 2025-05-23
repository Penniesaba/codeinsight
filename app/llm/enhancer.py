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
        
        # 定义SARIF分析的提示模板
        self.sarif_analysis_prompt = """
        你是一个专业的代码安全专家，请对以下CodeQL生成的SARIF格式安全分析结果进行全面分析，以中文详细输出：

        ```json
        {sarif_content}
        ```

        请提供以下内容（全部使用中文回答）：

        1. 漏洞总体分析：
           a. 发现的漏洞类型及总数
           b. 最严重的漏洞类别及其影响
           c. 代码库的总体安全评分（1-10分）

        2. 详细漏洞分析：针对每种漏洞类型提供：
           a. 漏洞名称和OWASP/CWE分类
           b. 漏洞原理和成因
           c. 安全风险和潜在影响
           d. 典型攻击场景
           e. CVSS评分和严重性级别

        3. 修复建议：针对每种漏洞提供：
           a. 具体的修复方法
           b. 最佳安全实践
           c. 安全编码指南

        4. 安全增强建议：
           a. 代码审查重点
           b. 安全测试策略
           c. 长期安全改进计划

        请以结构化的方式组织你的回答，使用markdown格式，确保内容专业、全面且有针对性。
        """
        
        # 检查API密钥是否可用
        if not self.api_key:
            logger.warning("未设置LLM API密钥，将使用模拟增强模式")
            self.api_key = None  # 显式设置为None，确保使用模拟模式
        else:
            logger.info(f"检测到LLM API密钥: {self.api_key[:4]}***，API地址: {self.api_url}")
            # 这里不再检查密钥是否为默认密钥，只要有值就认为是有效的
        
        logger.debug("LLM增强器初始化完成")
    
    def analyze_sarif_file(self, sarif_file_path, task_id=None):
        """
        直接分析SARIF文件并生成增强报告
        
        参数:
            sarif_file_path: SARIF文件路径
            task_id: 任务ID，用于保存结果
            
        返回:
            基于SARIF的增强分析结果
        """
        logger.info(f"开始分析SARIF文件: {sarif_file_path}")
        
        try:
            # 读取SARIF文件
            with open(sarif_file_path, 'r', encoding='utf-8') as f:
                sarif_content = f.read()
            
            # 如果没有API密钥，使用模拟增强
            if not self.api_key:
                logger.info("使用模拟增强模式分析SARIF文件")
                mock_result = self._mock_sarif_analysis(sarif_content, task_id)
                # 添加说明，表明这是模拟数据
                mock_result['is_mock'] = True
                mock_result['overview'] = "# 安全分析概述 (模拟数据)\n\n" + mock_result['overview'].strip()
                logger.warning("生成的结果为模拟数据，请配置有效的LLM API密钥以获取真实分析")
                return mock_result
            
            # 解析SARIF内容
            sarif_data = json.loads(sarif_content)
            
            # 获取仓库路径（如果有）
            repo_path = None
            if task_id:
                repo_path = os.path.join(self.config['REPO_CACHE_DIR'], task_id)
                if not os.path.exists(repo_path):
                    logger.warning(f"仓库路径不存在: {repo_path}，无法提取完整代码片段")
                    repo_path = None
            
            # 提取基本信息
            basic_info = self._extract_sarif_basic_info(sarif_data)
            
            # 如果有仓库路径，尝试从源文件中提取完整代码片段
            if repo_path:
                logger.info(f"尝试从仓库提取代码片段: {repo_path}")
                self._enhance_code_snippets(basic_info, repo_path)
            else:
                logger.warning("仓库路径不可用，将使用SARIF提供的代码片段")
                # 确保每个代码位置都有snippet字段
                for location in basic_info.get('code_locations', []):
                    if not location.get('snippet'):
                        location['snippet'] = f"// 无代码片段可用\n// 文件: {location.get('file_path')}\n// 行: {location.get('start_line')}-{location.get('end_line')}"
            
            # 构建提示
            prompt = self.sarif_analysis_prompt.format(sarif_content=sarif_content)
            
            # 调用LLM API
            llm_analysis = self._call_llm_api(prompt)
            
            # 解析LLM响应，构建结构化报告
            structured_analysis = self._structure_sarif_analysis(llm_analysis, basic_info)
            
            # 保存分析结果
            if task_id:
                results_dir = os.path.join(self.config['ANALYSIS_CACHE_DIR'], task_id)
                os.makedirs(results_dir, exist_ok=True)
                
                analysis_path = os.path.join(results_dir, 'sarif_analysis.json')
                with open(analysis_path, 'w', encoding='utf-8') as f:
                    json.dump(structured_analysis, f, ensure_ascii=False, indent=2)
                
                llm_response_path = os.path.join(results_dir, 'llm_sarif_response.txt')
                with open(llm_response_path, 'w', encoding='utf-8') as f:
                    f.write(llm_analysis)
                    
                logger.info(f"SARIF分析结果已保存至: {analysis_path}")
            
            return structured_analysis
            
        except Exception as e:
            logger.error(f"SARIF文件分析失败: {str(e)}", exc_info=True)
            return self._mock_sarif_analysis("", task_id)
    
    def _extract_sarif_basic_info(self, sarif_data):
        """
        从SARIF数据中提取基本信息
        
        参数:
            sarif_data: 解析后的SARIF数据
            
        返回:
            基本信息字典
        """
        basic_info = {
            'total_results': 0,
            'rule_counts': {},
            'severity_counts': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'rules': {},
            'code_locations': []  # 新增：存储有问题的代码位置信息
        }
        
        # 处理每一个run
        for run in sarif_data.get('runs', []):
            # 获取driver信息
            driver = run.get('tool', {}).get('driver', {})
            
            # 获取规则信息
            rules = {}
            for rule in driver.get('rules', []):
                rule_id = rule.get('id', 'unknown')
                rules[rule_id] = {
                    'name': rule.get('name', rule_id),
                    'description': rule.get('shortDescription', {}).get('text', '') or rule.get('fullDescription', {}).get('text', ''),
                    'severity': rule.get('defaultConfiguration', {}).get('level', 'warning'),
                    'count': 0
                }
            
            # 处理结果
            for result in run.get('results', []):
                basic_info['total_results'] += 1
                
                rule_id = result.get('ruleId', 'unknown')
                
                # 更新规则计数
                if rule_id in basic_info['rule_counts']:
                    basic_info['rule_counts'][rule_id] += 1
                else:
                    basic_info['rule_counts'][rule_id] = 1
                
                # 更新规则信息中的计数
                if rule_id in rules:
                    rules[rule_id]['count'] += 1
                
                # 更新严重性计数 (提升一级)
                severity = rules.get(rule_id, {}).get('severity', 'warning')
                # 将漏洞级别提升一级
                if severity == 'error':
                    basic_info['severity_counts']['critical'] += 1  # 高危→严重
                elif severity == 'warning':
                    basic_info['severity_counts']['high'] += 1      # 中危→高危
                elif severity == 'note':
                    basic_info['severity_counts']['medium'] += 1    # 低危→中危
                else:
                    basic_info['severity_counts']['low'] += 1       # 其他→低危
                
                # 提取代码位置信息
                if 'locations' in result:
                    for location in result.get('locations', []):
                        physical_location = location.get('physicalLocation', {})
                        artifact_location = physical_location.get('artifactLocation', {})
                        region = physical_location.get('region', {})
                        
                        if artifact_location and region:
                            file_path = artifact_location.get('uri', '')
                            start_line = region.get('startLine', 0)
                            end_line = region.get('endLine', start_line)
                            start_column = region.get('startColumn', 1)
                            end_column = region.get('endColumn', 1)
                            
                            # 提取代码片段
                            snippet = physical_location.get('contextRegion', {}).get('snippet', {}).get('text', '')
                            if not snippet:
                                snippet = region.get('snippet', {}).get('text', '')
                            
                            # 如果还是没有片段，尝试从result的message中提取
                            if not snippet and 'message' in result:
                                message_text = result.get('message', {}).get('text', '')
                                if message_text:
                                    # 有些SARIF文件在消息中包含代码片段
                                    snippet = f"// 从消息中提取的代码:\n{message_text}"
                            
                            # 添加到位置列表
                            code_location = {
                                'rule_id': rule_id,
                                'rule_name': rules.get(rule_id, {}).get('name', rule_id),
                                'severity': severity,
                                'file_path': file_path,
                                'start_line': start_line,
                                'end_line': end_line,
                                'start_column': start_column,
                                'end_column': end_column,
                                'snippet': snippet,
                                'is_enhanced': False
                            }
                            basic_info['code_locations'].append(code_location)
        
        # 合并规则信息
        basic_info['rules'] = rules
        
        return basic_info
    
    def _structure_sarif_analysis(self, llm_response, basic_info):
        """
        将LLM响应结构化为分析报告
        
        参数:
            llm_response: LLM的分析响应
            basic_info: 从SARIF提取的基本信息
            
        返回:
            结构化的分析报告
        """
        # 提取分析部分
        sections = self._extract_analysis_sections(llm_response)
        
        # 提取LLM识别的漏洞
        vulnerabilities = []
        
        # 构建结构化分析结果
        structured_analysis = {
            'summary': {
                'total_vulnerabilities': basic_info['total_results'],
                'vulnerability_types': len(basic_info['rule_counts']),
                'severity_distribution': basic_info['severity_counts']
            },
            'overview': sections.get('overview', ''),
            'vulnerabilities': [],
            'code_locations': basic_info.get('code_locations', [])  # 添加代码位置信息
        }
        
        # 如果没有从LLM提取到漏洞，使用基本信息构建
        if not vulnerabilities:
            # 按严重性对规则排序
            severity_order = {'error': 0, 'warning': 1, 'note': 2, 'recommendation': 3}
            sorted_rules = sorted(
                basic_info['rules'].items(),
                key=lambda x: (severity_order.get(x[1]['severity'], 999), -x[1]['count'])
            )
            
            # 为每个规则创建漏洞条目
            for rule_id, rule_info in sorted_rules:
                if rule_info['count'] == 0:
                    continue
                    
                # 获取漏洞类型
                vuln_type = rule_info['name']
                
                # 创建漏洞条目
                vulnerability = {
                    'type': vuln_type,
                    'description': rule_info['description'],
                    'severity': self._map_severity(rule_info['severity']),
                    'count': rule_info['count'],
                    'instances': [],
                    'enhanced_description': sections.get('general_description', ''),
                    'common_fixes': sections.get('general_fixes', '')
                }
                
                structured_analysis['vulnerabilities'].append(vulnerability)
        else:
            # 使用LLM分析的漏洞信息
            for vuln in vulnerabilities:
                structured_analysis['vulnerabilities'].append(vuln)
        
        return structured_analysis
    
    def _extract_analysis_sections(self, llm_response):
        """
        从LLM响应中提取各部分内容
        
        参数:
            llm_response: LLM的分析响应
            
        返回:
            分析部分字典
        """
        sections = {
            'overview': '',
            'vulnerabilities': [],
            'general_description': '',
            'general_fixes': ''
        }
        
        # 简单划分响应内容
        parts = llm_response.split("\n## ")
        
        # 第一部分通常是总体分析
        if parts and parts[0]:
            sections['overview'] = parts[0].replace("# ", "")
        
        # 查找漏洞分析部分
        vuln_analysis = None
        fixes = None
        
        for part in parts:
            if part.startswith("详细漏洞分析") or "漏洞分析" in part.lower():
                vuln_analysis = part
            elif part.startswith("修复建议") or "修复" in part.lower():
                fixes = part
            elif part.startswith("安全增强建议") or "安全建议" in part.lower():
                sections['general_fixes'] += "\n" + part
        
        # 提取一般描述
        if vuln_analysis:
            sections['general_description'] = vuln_analysis
            
            # TODO: 进一步解析漏洞分析，将每种漏洞提取为单独条目
            # 这需要更复杂的文本解析，暂时使用整体描述
        
        # 提取修复建议
        if fixes:
            if sections['general_fixes']:
                sections['general_fixes'] += "\n" + fixes
            else:
                sections['general_fixes'] = fixes
        
        return sections
    
    def _map_severity(self, codeql_severity):
        """
        将CodeQL严重性映射到标准严重性级别
        
        参数:
            codeql_severity: CodeQL的严重性
            
        返回:
            标准严重性
        """
        severity_map = {
            'error': 'critical',     # 高危 → 严重
            'warning': 'high',       # 中危 → 高危
            'note': 'medium',        # 低危 → 中危
            'recommendation': 'low'  # 推荐 → 低危
        }
        return severity_map.get(codeql_severity, 'medium')
    
    def _mock_sarif_analysis(self, sarif_content, task_id=None):
        """
        模拟SARIF分析，用于测试或API不可用时
        
        参数:
            sarif_content: SARIF内容（可能为空）
            task_id: 任务ID
            
        返回:
            模拟的分析结果
        """
        logger.info("使用模拟SARIF分析")
        
        # 基本信息
        summary = {
            'total_vulnerabilities': 12,
            'vulnerability_types': 5,
            'severity_distribution': {
                'critical': 2,
                'high': 4,
                'medium': 4,
                'low': 2
            },
            'security_score': 7.5
        }
        
        # 漏洞列表
        vulnerabilities = [
            {
                'type': 'SQL注入漏洞',
                'severity': 'critical',
                'count': 3,
                'owasp_category': 'A1:2021-注入',
                'cwe_id': 'CWE-89',
                'description': '## SQL注入漏洞描述\n\nSQL注入是一种代码注入技术，可能会破坏应用程序的安全性。它允许攻击者干扰应用程序与其数据库之间的查询，可能导致访问或修改未经授权的数据。\n\n### 漏洞原因\n\n* 用户输入未经验证就直接用于构建SQL查询\n* 使用字符串拼接而非参数化查询\n* 错误处理不当，泄露数据库信息',
                'enhanced_description': '## SQL注入漏洞分析\n\nSQL注入是一种严重的安全漏洞，攻击者可以通过在应用程序输入点插入恶意SQL代码来操纵后端数据库。\n\n### 漏洞原理\n\n* 应用程序接收用户输入并将其直接拼接到SQL查询中\n* 缺少适当的输入验证和参数化查询\n* 使用动态SQL构造而不是预处理语句\n\n### 安全风险\n\n* 未经授权访问敏感数据\n* 绕过身份验证机制\n* 修改或删除数据库内容\n* 在某些情况下执行系统命令',
                'security_impact': '## 安全影响\n\n此漏洞可导致以下严重后果：\n\n1. **数据泄露** - 攻击者可以从数据库中提取敏感信息\n2. **身份验证绕过** - 可以通过操纵登录查询获得未授权访问\n3. **数据完整性损坏** - 通过INSERT, UPDATE或DELETE操作修改数据\n4. **服务拒绝** - 可能通过破坏关键数据使应用程序不可用\n\n在严重情况下，攻击者可能利用高级技术（如堆叠查询）执行多个操作，甚至获取服务器访问权限。',
                'common_fixes': '## 修复建议\n\n### 立即采取的措施\n\n1. **实施参数化查询/预处理语句**\n   ```java\n   // 不安全的方式\n   String query = "SELECT * FROM users WHERE username = \'" + username + "\'"; \n   \n   // 安全的方式\n   PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE username = ?");\n   stmt.setString(1, username);\n   ```\n\n2. **使用ORM框架**\n   如Hibernate、Entity Framework等提供额外的SQL注入保护层\n\n3. **实施输入验证**\n   * 验证输入类型、长度、格式和范围\n   * 实施白名单而非黑名单策略\n\n4. **最小权限原则**\n   * 为应用程序使用最小权限数据库账户\n   * 限制对敏感表的访问',
                'best_practices': '## 安全最佳实践\n\n1. **定期安全代码审查**\n   * 针对所有与数据库交互的代码\n   * 使用静态分析工具进行自动检测\n\n2. **防御纵深策略**\n   * 参数化查询（主要防御）\n   * 输入验证（附加保护层）\n   * 输出编码（减轻影响）\n   * WAF实施（外部保护）\n\n3. **安全测试**\n   * 实施自动化安全测试\n   * 包括SQL注入测试用例\n   * 定期进行渗透测试\n\n4. **监控与响应**\n   * 监控异常数据库查询\n   * 实施入侵检测系统\n   * 准备事件响应计划'
            },
            {
                'type': '跨站脚本攻击(XSS)',
                'severity': 'high',
                'count': 5,
                'owasp_category': 'A3:2021-注入和跨站脚本',
                'cwe_id': 'CWE-79',
                'description': '在网页应用中，未经处理的用户输入直接输出到页面，导致浏览器执行恶意脚本。',
                'enhanced_description': '## 跨站脚本(XSS)漏洞\n\n跨站脚本是一种常见的网络安全漏洞，允许攻击者向网页注入客户端脚本。当其他用户浏览受影响的页面时，注入的恶意代码会在他们的浏览器中执行。\n\n### 漏洞类型\n\n* **存储型XSS** - 恶意脚本永久存储在目标服务器上(如数据库)\n* **反射型XSS** - 恶意脚本通过URL参数反射给用户\n* **DOM型XSS** - 漏洞存在于客户端代码而非服务器响应\n\n### 技术原因\n\n* 未对用户输入进行充分验证和净化\n* 未对输出到HTML页面的内容进行适当编码\n* 过度信任用户提供的内容',
                'security_impact': '## 安全风险\n\n成功的XSS攻击可导致以下危害：\n\n1. **会话劫持** - 攻击者可窃取用户Cookie和会话令牌\n2. **凭证盗窃** - 可通过伪造登录表单获取用户凭证\n3. **恶意重定向** - 将用户引导至钓鱼站点\n4. **内容篡改** - 修改页面显示内容，损害品牌形象\n5. **浏览器控制** - 攻击者可获取完全的页面DOM访问权限\n\n在高权限用户受到攻击时，可能造成更严重的影响，包括敏感数据泄露和站点功能控制。',
                'common_fixes': '## 修复建议\n\n1. **输出编码**\n   * 根据输出环境使用正确的编码函数\n   * HTML上下文: `htmlspecialchars()`或等效函数\n   * JavaScript上下文: 适当的JavaScript编码\n   * CSS和URL上下文: 专用编码函数\n\n2. **内容安全策略(CSP)**\n   * 实施严格的CSP头部，限制脚本来源\n   * 使用nonce或hash值来验证可信脚本\n\n3. **输入验证**\n   * 对所有用户输入实施严格验证\n   * 采用"接受已知良好"而非"拒绝已知恶意"的策略\n\n4. **使用现代框架**\n   * 利用自动转义功能的模板系统\n   * React、Vue等现代框架提供内置XSS保护',
                'best_practices': '## 防御最佳实践\n\n1. **多层防御策略**\n   * 输入验证作为第一道防线\n   * 输出编码作为主要防御手段\n   * CSP作为额外保护层\n   * X-XSS-Protection头部提供浏览器保护\n\n2. **安全的API设计**\n   * 设计不易受XSS影响的API和组件\n   * 隔离不可信数据，避免直接插入DOM\n\n3. **定期安全测试**\n   * 自动化XSS扫描工具\n   * 渗透测试模拟真实攻击场景\n   * 代码审查识别潜在XSS向量\n\n4. **开发人员培训**\n   * 确保开发团队了解XSS风险\n   * 建立输出编码和安全实践指南'
            },
            {
                'type': '敏感信息泄露',
                'severity': 'medium',
                'count': 2,
                'owasp_category': 'A2:2021-加密缺陷',
                'cwe_id': 'CWE-200',
                'description': '敏感数据（如密码、个人信息）未经适当保护，可能导致未授权访问。',
                'enhanced_description': '## 敏感信息泄露漏洞\n\n敏感信息泄露发生在应用程序意外向未授权方披露敏感信息时。这可能由不安全的数据存储、不适当的错误处理或配置错误引起。\n\n### 漏洞表现\n\n* 详细的错误消息泄露内部系统信息\n* 源代码中的硬编码凭证和密钥\n* 注释中包含敏感信息\n* 日志文件中的明文敏感数据\n* 不安全的文件或目录权限\n\n敏感信息可能包括：API密钥、数据库凭证、个人身份信息(PII)、会话标识符、加密密钥和业务敏感数据。',
                'security_impact': '## 安全影响评估\n\n敏感信息泄露可能导致以下后果：\n\n1. **身份盗用** - 当个人身份信息泄露时\n2. **账户接管** - 如凭证或会话标识符被泄露\n3. **系统入侵** - 使用泄露的API密钥或内部系统详情\n4. **数据库攻击** - 利用连接字符串访问数据库\n5. **业务损失** - 商业秘密或专有算法泄露\n6. **合规违规** - GDPR、CCPA或行业特定法规的违规处罚\n\n此类漏洞通常构成更大攻击链的一部分，允许攻击者获取初始信息后进行深度渗透。',
                'common_fixes': '## 修复策略\n\n1. **安全处理错误**\n   * 为生产环境实施通用错误消息\n   * 避免在错误响应中包含技术细节\n   * 使用适当的日志记录系统收集详细错误\n\n2. **保护敏感数据**\n   * 对存储的敏感数据进行加密\n   * 对传输中的数据使用TLS/HTTPS\n   * 实施适当的密钥管理策略\n\n3. **配置审查**\n   * 禁用调试功能和开发特性\n   * 检查并移除不必要的HEAD/OPTIONS响应信息\n   * 审查HTTP响应头，移除敏感信息\n\n4. **代码安全**\n   * 使用安全的环境变量存储密钥\n   * 从源代码中移除硬编码凭证\n   * 在提交前审查代码，移除敏感注释',
                'best_practices': '## 最佳安全实践\n\n1. **分类和清单**\n   * 识别和分类所有敏感数据\n   * 维护应用程序处理的敏感数据清单\n   * 定期评估每类数据的保护需求\n\n2. **最小化暴露**\n   * 仅收集必要的敏感数据\n   * 按需访问敏感信息\n   * 尽快匿名化或删除不再需要的数据\n\n3. **安全开发流程**\n   * 使用安全编码指南\n   * 实施敏感数据处理策略\n   * 使用专门的工具扫描源代码中的密钥和凭证\n\n4. **监控与审计**\n   * 监控敏感数据访问\n   * 保留访问日志供审计\n   * 定期漏洞扫描测试信息泄露问题'
            },
            {
                'type': '不安全的密码存储',
                'severity': 'medium',
                'count': 1,
                'owasp_category': 'A2:2021-加密缺陷',
                'cwe_id': 'CWE-256',
                'description': '密码使用不安全的哈希算法存储，或密码强度策略不足。',
                'enhanced_description': '## 不安全的密码存储\n\n此漏洞涉及使用不安全的方法存储或处理用户密码，如果认证系统被攻击，可能导致凭证泄露。当应用程序使用弱哈希算法、没有使用盐值、直接使用明文存储密码或加密而非哈希处理密码时，就会出现此问题。\n\n### 常见问题模式\n\n* 使用过时/弱哈希算法(MD5, SHA1)\n* 没有应用加盐处理\n* 使用可逆加密而非单向哈希\n* 密码重置流程中的薄弱环节\n* 应用于哈希的迭代次数不足',
                'security_impact': '## 安全威胁分析\n\n不安全的密码存储会导致严重后果：\n\n1. **凭证泄露** - 数据库泄露时密码容易被恢复\n2. **账户接管** - 攻击者获取用户密码后可接管账户\n3. **密码重用问题** - 用户跨站点重用密码，导致其他系统遭受威胁\n4. **身份盗窃** - 结合其他泄露数据进行身份欺诈\n5. **声誉损害** - 密码泄露事件可能损害公司形象和用户信任\n\n密码一旦泄露，攻击者可以进行凭证填充攻击或暴力破解，影响范围可能超出被入侵的系统。',
                'common_fixes': '## 密码安全修复方案\n\n1. **使用强哈希算法**\n   * 采用专门设计的密码哈希函数:\n     - Argon2 (推荐首选)\n     - bcrypt\n     - PBKDF2\n   * 避免使用一般用途哈希(MD5, SHA系列)\n\n2. **正确实施盐值**\n   * 为每个密码使用唯一随机盐值\n   * 使用密码学安全的随机数生成器\n   * 将盐值与哈希一起存储\n\n3. **增加算法工作因子**\n   * 根据硬件能力调整工作因子\n   * 随着计算能力增长定期提高工作因子\n\n4. **安全实施示例**\n   ```java\n   // 使用bcrypt的示例(Java)\n   String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));\n   ```',
                'best_practices': '## 密码处理最佳实践\n\n1. **密码策略和管理**\n   * 实施强密码策略(长度、复杂性)\n   * 检查常见/已泄露密码\n   * 定期提示密码更新\n   * 实施账户锁定政策防止暴力破解\n\n2. **多因素认证**\n   * 将MFA作为密码保护的补充措施\n   * 为高权限账户强制使用MFA\n\n3. **零知识证明方法**\n   * 可能时考虑使用零知识验证技术\n   * 实施安全远程密码(SRP)等协议\n\n4. **安全编码与审计**\n   * 定期审查认证系统代码\n   * 使用专业库而非自行实现密码学\n   * 测试密码恢复过程的安全性'
            },
            {
                'type': '不安全的直接对象引用(IDOR)',
                'severity': 'low',
                'count': 1,
                'owasp_category': 'A1:2021-失效的访问控制',
                'cwe_id': 'CWE-639',
                'description': '系统通过可预测的对象引用直接暴露内部资源，未进行充分的访问控制验证。',
                'enhanced_description': '## 不安全的直接对象引用(IDOR)\n\n不安全的直接对象引用是一种访问控制漏洞，发生在应用程序使用用户提供的输入直接访问对象但未进行充分授权检查时。这可能允许攻击者访问或修改他们本不应有权限操作的资源。\n\n### 漏洞原理\n\n* 应用程序根据用户控制的参数检索对象\n* 缺少适当的访问控制验证\n* 过度依赖隐藏或模糊处理而非访问控制\n* 信任前端提供的对象标识符',
                'security_impact': '## 安全影响和风险\n\n不安全的直接对象引用可导致以下安全问题：\n\n1. **未授权数据访问** - 用户可访问他人的敏感信息和记录\n2. **水平权限提升** - 攻击者可执行同级别其他用户的操作\n3. **数据操纵** - 可能修改、删除不属于攻击者的数据\n4. **隐私泄露** - 个人信息可能被未授权方访问\n\n漏洞通常利用简单(更改URL参数或表单字段)，但影响可能严重，特别是涉及财务或医疗数据时。',
                'common_fixes': '## IDOR漏洞修复\n\n1. **基于用户实现访问控制**\n   * 在服务器端验证用户是否有权访问所请求资源\n   * 将用户会话与允许访问的数据关联\n   * 实例代码：\n   ```java\n   // 不安全示例\n   Record getRecord(int recordId) {\n       return recordRepository.findById(recordId);\n   }\n   \n   // 安全示例\n   Record getRecord(int recordId, int userId) {\n       Record record = recordRepository.findById(recordId);\n       if (record.getOwnerId() != userId) {\n           throw new AccessDeniedException();\n       }\n       return record;\n   }\n   ```\n\n2. **使用间接引用**\n   * 使用服务器端映射将公开标识符转换为实际数据库键\n   * 限制可在单个会话中访问的记录\n\n3. **实现基于属性的访问控制**\n   * 定义明确的访问控制策略\n   * 使用专门的访问控制框架',
                'best_practices': '## 安全最佳实践\n\n1. **深度防御策略**\n   * 在API和控制器级别实施统一的访问控制\n   * 对所有非公共资源的访问进行授权检查\n   * 实施最小权限原则\n\n2. **安全架构设计**\n   * 在应用程序设计阶段考虑访问控制\n   * 创建详细的授权矩阵，明确定义谁可以访问什么\n   * 使用基于访问控制列表(ACL)或基于角色的访问控制(RBAC)模型\n\n3. **测试方法**\n   * 执行授权测试，验证访问控制\n   * 实现自动化测试以验证权限边界\n   * 包括水平权限提升测试用例\n\n4. **日志与监控**\n   * 记录所有资源访问尝试\n   * 监控异常访问模式\n   * 建立资源访问基线和异常检测机制'
            }
        ]
        
        # 基于实际分析结果生成概述
        critical_count = summary['severity_distribution'].get('critical', 0)
        high_count = summary['severity_distribution'].get('high', 0)
        medium_count = summary['severity_distribution'].get('medium', 0)
        low_count = summary['severity_distribution'].get('low', 0)
        
        # 找出最严重的几类漏洞
        top_vulns = sorted(
            vulnerabilities, 
            key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'warning': 4, 'note': 5}.get(x['severity'].lower(), 999)
        )[:3]
        
        # 确定风险级别
        risk_level = "低"
        score = 90
        if critical_count > 0:
            risk_level = "严重"
            score = 60 - (critical_count * 5)
        elif high_count > 0:
            risk_level = "高"
            score = 75 - (high_count * 2)
        elif medium_count > 3:
            risk_level = "中"
            score = 85 - (medium_count * 1)
        
        score = max(min(score, 95), 30)  # 限制评分范围在30-95之间
        
        # 提取漏洞类型名称
        vuln_names = [v['type'] for v in top_vulns]
        
        # 自动生成概述
        overview = f"""
# 代码安全分析概述

通过对代码库的安全分析，我们发现了{summary['vulnerability_types']}类安全漏洞，总计{summary['total_vulnerabilities']}个问题。{'其中包含严重级别漏洞，需要立即修复。' if critical_count > 0 else ''}

## 主要发现

"""
        # 动态添加主要漏洞
        for i, vuln in enumerate(top_vulns[:3]):
            if i < len(top_vulns):
                vuln_desc = vuln.get('description', '')
                # 截取简短描述，避免过长
                short_desc = vuln_desc[:100] + '...' if len(vuln_desc) > 100 else vuln_desc
                overview += f"{i+1}. **{vuln['type']}** - {short_desc}\n"
        
        if not top_vulns:
            overview += "未发现重大安全漏洞。\n"
            
        overview += f"""
## 风险评估

总体安全评分为{score}分（满分100分），表示代码库存在{risk_level}风险。我们发现了{critical_count}个严重漏洞、{high_count}个高危漏洞、{medium_count}个中危漏洞和{low_count}个低危漏洞。

## 主要建议

"""
        # 根据发现的问题类型生成相应建议
        if critical_count > 0 or high_count > 0:
            overview += f"1. **立即修复所有严重和高危漏洞**，特别是{', '.join(vuln_names[:2]) if vuln_names else '已发现的安全问题'}\n"
        
        overview += """2. 实施安全编码实践，包括输入验证、输出编码和参数化查询
3. 建立安全代码审查流程，防止类似问题再次出现
4. 对开发团队进行安全编码培训

修复这些问题将显著提高应用程序的总体安全性，并减少被成功攻击的风险。
"""
        
        # 构建完整报告
        result = {
            'summary': summary,
            'vulnerabilities': vulnerabilities,
            'overview': overview,
            # 添加可能的其他部分
            'recommendations': {
                'immediate_actions': '优先修复所有严重和高危漏洞，特别是SQL注入和XSS问题。',
                'long_term': '实施安全开发生命周期(SDLC)，并定期进行安全培训和代码审查。'
            }
        }
        
        # 保存分析结果
        if task_id:
            results_dir = os.path.join(self.config['ANALYSIS_CACHE_DIR'], task_id)
            os.makedirs(results_dir, exist_ok=True)
            
            analysis_path = os.path.join(results_dir, 'sarif_analysis.json')
            with open(analysis_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            
            logger.info(f"模拟SARIF分析结果已保存至: {analysis_path}")
        
        return result
    
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
        
        # 准备漏洞数据详情
        vuln_details = []
        for v in vulnerabilities[:5]:  # 只取前5个最严重的漏洞
            vuln_details.append(f"- {v['type']}: {v['count']}个实例, 严重度:{v['severity']}, 描述:{v['description'][:100]}...")
            
        prompt = f"""
        请根据以下软件安全分析结果，生成一个全面且具体的安全评估总结报告，针对发现的实际问题提供深入分析：

        总计发现的漏洞数量: {summary['total_vulnerabilities']}
        漏洞类型数量: {summary['vulnerability_types']}
        
        严重程度分布:
        - 严重: {severity_dist.get('critical', 0)}
        - 高危: {severity_dist.get('high', 0)}
        - 中危: {severity_dist.get('medium', 0)}
        - 低危: {severity_dist.get('low', 0)}
        - 警告: {severity_dist.get('warning', 0)}

        主要漏洞类型及详情:
        {chr(10).join(vuln_details)}

        请提供:
        1. 安全状况总体评估 - 基于发现的实际问题，评估代码库的安全风险水平(1-100分)
        2. 各主要漏洞的详细分析 - 重点关注高危漏洞的原理、危害和影响范围
        3. 具体的修复建议 - 针对发现的每类问题提供明确、可操作的修复方案
        4. 安全改进的优先级建议 - 根据风险级别提出合理的修复顺序
        5. 长期安全策略建议 - 如何从流程和技术层面预防类似问题

        请以中文回答，以Markdown格式组织内容，确保分析专业、具体、针对实际发现的问题，避免泛泛而谈。使用清晰的标题结构和要点，方便阅读理解。
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
        # 检查是否使用OpenAI兼容模式
        use_openai_compatible = self.config.get('LLM_USE_OPENAI_COMPATIBLE', False)
        
        if use_openai_compatible:
            return self._call_openai_compatible_api(prompt)
        else:
            return self._call_standard_api(prompt)
    
    def _call_openai_compatible_api(self, prompt):
        """
        使用OpenAI兼容模式调用API
        
        参数:
            prompt: 提示文本
            
        返回:
            API响应
        """
        try:
            # 动态导入OpenAI库
            from openai import OpenAI
            
            # 创建客户端
            client = OpenAI(
                api_key=self.api_key,
                base_url=self.api_url
            )
            
            # 调用API
            logger.debug(f"使用OpenAI兼容模式发送请求: {self.api_url}, 模型: {self.model}")
            
            completion = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一个专业的代码安全分析助手，擅长解释和提供安全漏洞的修复方案。请用中文回复。"},
                    {"role": "user", "content": prompt}
                ]
            )
            
            # 提取回复内容
            return completion.choices[0].message.content
            
        except ImportError:
            logger.error("未安装OpenAI库，无法使用OpenAI兼容模式")
            logger.info("请使用pip install openai安装OpenAI库")
            # 回退到标准模式
            return self._call_standard_api(prompt)
        except Exception as e:
            logger.error(f"OpenAI兼容模式API调用失败: {str(e)}", exc_info=True)
            raise
    
    def _call_standard_api(self, prompt):
        """
        使用标准方式调用API
        
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
    
    def analyze_multiple_sarif_files(self, sarif_file_paths, task_id=None):
        """
        分析多个SARIF文件并合并结果
        
        参数:
            sarif_file_paths: SARIF文件路径列表
            task_id: 任务ID，用于保存结果
            
        返回:
            合并后的增强分析结果
        """
        logger.info(f"开始分析多个SARIF文件: {len(sarif_file_paths)}个文件")
        
        if not sarif_file_paths:
            logger.warning("没有提供SARIF文件路径")
            return self._mock_sarif_analysis("", task_id)
        
        # 如果只有一个文件，直接使用单文件分析
        if len(sarif_file_paths) == 1:
            return self.analyze_sarif_file(sarif_file_paths[0], task_id)
        
        try:
            # 合并SARIF数据结构
            merged_sarif = {
                'version': '2.1.0',
                'runs': [{
                    'tool': {
                        'driver': {
                            'name': 'CodeQL',
                            'rules': []
                        }
                    },
                    'results': [],
                    'artifacts': []
                }]
            }
            
            # 读取并合并所有SARIF文件
            rules_set = set()
            for file_path in sarif_file_paths:
                logger.info(f"处理SARIF文件: {file_path}")
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        sarif_content = f.read()
                    
                    sarif_data = json.loads(sarif_content)
                    
                    # 合并结果
                    for run in sarif_data.get('runs', []):
                        # 合并规则
                        for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
                            rule_id = rule.get('id')
                            if rule_id and rule_id not in rules_set:
                                rules_set.add(rule_id)
                                merged_sarif['runs'][0]['tool']['driver']['rules'].append(rule)
                        
                        # 合并结果
                        merged_sarif['runs'][0]['results'].extend(run.get('results', []))
                        
                        # 合并artifacts（可选）
                        if 'artifacts' in run:
                            merged_sarif['runs'][0]['artifacts'].extend(run.get('artifacts', []))
                
                except Exception as e:
                    logger.error(f"处理SARIF文件 {file_path} 失败: {str(e)}")
                    continue
            
            # 如果没有合并到任何结果，返回模拟数据
            if not merged_sarif['runs'][0]['results']:
                logger.warning("合并后的SARIF文件没有结果")
                return self._mock_sarif_analysis("", task_id)
            
            # 提取基本信息
            basic_info = self._extract_sarif_basic_info(merged_sarif)
            
            # 构建提示 - 限制内容大小以防止超出API限制
            merged_sarif_content = json.dumps(merged_sarif, ensure_ascii=False)
            
            # 如果内容太大，可能需要截断
            max_content_size = 20000  # 根据实际API限制调整
            if len(merged_sarif_content) > max_content_size:
                logger.warning(f"SARIF内容过大({len(merged_sarif_content)}字节)，将被截断")
                # 创建一个截断版本，保留关键信息
                truncated_sarif = {
                    'version': merged_sarif['version'],
                    'runs': [{
                        'tool': merged_sarif['runs'][0]['tool'],
                        'results': merged_sarif['runs'][0]['results'][:100]  # 只保留前100个结果
                    }]
                }
                merged_sarif_content = json.dumps(truncated_sarif, ensure_ascii=False)
                logger.info(f"截断后的SARIF内容大小: {len(merged_sarif_content)}字节")
            
            prompt = self.sarif_analysis_prompt.format(sarif_content=merged_sarif_content)
            
            # 调用LLM API
            if not self.api_key:
                logger.info("使用模拟增强模式分析合并的SARIF文件")
                mock_result = self._mock_sarif_analysis(merged_sarif_content, task_id)
                mock_result['is_mock'] = True
                mock_result['overview'] = "# 安全分析概述 (模拟数据)\n\n" + mock_result['overview'].strip()
                logger.warning("生成的结果为模拟数据，请配置有效的LLM API密钥以获取真实分析")
                return mock_result
                
            llm_analysis = self._call_llm_api(prompt)
            
            # 解析LLM响应，构建结构化报告
            structured_analysis = self._structure_sarif_analysis(llm_analysis, basic_info)
            
            # 保存分析结果
            if task_id:
                results_dir = os.path.join(self.config['ANALYSIS_CACHE_DIR'], task_id)
                os.makedirs(results_dir, exist_ok=True)
                
                analysis_path = os.path.join(results_dir, 'sarif_analysis.json')
                with open(analysis_path, 'w', encoding='utf-8') as f:
                    json.dump(structured_analysis, f, ensure_ascii=False, indent=2)
                
                # 也保存一份合并后的SARIF文件
                merged_sarif_path = os.path.join(results_dir, 'merged_sarif.json')
                with open(merged_sarif_path, 'w', encoding='utf-8') as f:
                    json.dump(merged_sarif, f, ensure_ascii=False, indent=2)
                
                llm_response_path = os.path.join(results_dir, 'llm_sarif_response.txt')
                with open(llm_response_path, 'w', encoding='utf-8') as f:
                    f.write(llm_analysis)
                    
                logger.info(f"合并的SARIF分析结果已保存至: {analysis_path}")
            
            return structured_analysis
            
        except Exception as e:
            logger.error(f"分析多个SARIF文件失败: {str(e)}", exc_info=True)
            return self._mock_sarif_analysis("", task_id)
    
    def _extract_code_from_file(self, repo_path, file_path, start_line, end_line, context_lines=5):
        """
        从仓库文件中提取完整代码片段
        
        参数:
            repo_path: 仓库路径
            file_path: 文件路径
            start_line: 开始行号
            end_line: 结束行号
            context_lines: 上下文行数
            
        返回:
            代码片段
        """
        try:
            # 尝试不同的路径组合
            possible_paths = [
                os.path.join(repo_path, file_path),  # 标准路径
                os.path.join(repo_path, os.path.basename(file_path)),  # 只使用文件名
                file_path if os.path.isabs(file_path) else os.path.join(repo_path, file_path)  # 尝试绝对路径
            ]
            
            # 找到第一个存在的文件路径
            full_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    full_path = path
                    logger.info(f"找到文件: {full_path}")
                    break
            
            # 如果所有路径都不存在
            if not full_path:
                logger.warning(f"无法找到文件, 尝试的路径: {possible_paths}")
                # 如果找不到文件，返回一个提示信息而不是None
                return f"// 无法找到文件: {file_path}\n// 开始行: {start_line}, 结束行: {end_line}"
                
            # 读取文件内容
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
                
            # 检查行号是否有效
            if start_line < 1:
                start_line = 1
            if end_line > len(lines):
                end_line = len(lines)
                
            # 计算要提取的行范围
            extract_start = max(1, start_line - context_lines)
            extract_end = min(len(lines), end_line + context_lines)
            
            # 提取代码片段
            snippet_lines = lines[extract_start-1:extract_end]
            
            # 添加行号前缀
            numbered_lines = []
            for i, line in enumerate(snippet_lines):
                line_num = i + extract_start
                # 高亮显示问题代码行
                if line_num >= start_line and line_num <= end_line:
                    numbered_lines.append(f"→ {line_num}: {line}")
                else:
                    numbered_lines.append(f"  {line_num}: {line}")
            
            snippet = ''.join(numbered_lines)
            logger.info(f"成功提取代码片段, 文件: {full_path}, 行: {extract_start}-{extract_end}")
            return snippet
            
        except Exception as e:
            logger.error(f"提取代码片段失败: {str(e)}", exc_info=True)
            # 返回错误信息而不是None
            return f"// 提取代码失败: {str(e)}\n// 文件: {file_path}\n// 开始行: {start_line}, 结束行: {end_line}"
    
    def _enhance_code_snippets(self, basic_info, repo_path):
        """
        增强代码片段，从仓库文件中提取更多上下文
        
        参数:
            basic_info: 基本信息字典
            repo_path: 仓库路径
        """
        for location in basic_info.get('code_locations', []):
            # 尝试从仓库文件中提取更完整的代码片段
            enhanced_snippet = self._extract_code_from_file(
                repo_path,
                location['file_path'],
                location['start_line'],
                location['end_line']
            )
            
            # 如果成功提取到代码，更新snippet
            if enhanced_snippet:
                location['original_snippet'] = location['snippet']  # 保留原始片段
                location['snippet'] = enhanced_snippet
                location['is_enhanced'] = True