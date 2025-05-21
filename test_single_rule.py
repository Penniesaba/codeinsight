#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
测试单个CodeQL规则分析功能
"""

import os
import sys
import logging
import json
import argparse

# 添加应用程序路径到系统路径
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app.codeql.analyzer import CodeQLAnalyzer

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)

# 测试配置
config = {
    'CODEQL_CLI_PATH': '/usr/local/bin/codeql',
    'CODEQL_QUERIES_PATH': '/home/xiao/project/codeinsight/app/codeql/queries',
    'CACHE_DIR': '/home/xiao/project/codeinsight/cache'
}

class CodeQLAnalyzerTester(CodeQLAnalyzer):
    """用于测试的CodeQL分析器子类，跳过CLI可用性检查"""
    
    def _check_codeql_availability(self):
        """重写可用性检查方法，直接返回成功"""
        logger = logging.getLogger(__name__)
        logger.info("跳过CodeQL CLI可用性检查")
        return True

def find_rules(language='javascript', search_term=None, include_experimental=False):
    """查找特定语言的规则，可选择按关键词过滤"""
    analyzer = CodeQLAnalyzerTester(config)
    
    # 定义可能的规则目录
    rule_directories = [
        f'/home/xiao/project/condeinsight/codeql/{language}/ql/src/Security',
        f'/home/xiao/project/codeinsight/codeql/{language}/ql/src/Security',
        f'/home/xiao/project/codeinsight/app/codeql/queries/{language}/ql/src/Security',
        f'/home/xiao/project/codeinsight/app/codeql/custom_rules/{language}'
    ]
    
    # 如果需要包含实验性规则
    if include_experimental:
        experimental_dirs = [
            f'/home/xiao/project/condeinsight/codeql/{language}/ql/src/experimental/Security',
            f'/home/xiao/project/codeinsight/codeql/{language}/ql/src/experimental/Security'
        ]
        rule_directories.extend(experimental_dirs)
    
    # 查找所有符合条件的规则
    rules = []
    for directory in rule_directories:
        if not os.path.exists(directory):
            continue
        
        for root, _, files in os.walk(directory):
            # 如果不包含实验性规则且路径包含experimental，则跳过
            if not include_experimental and 'experimental' in root:
                continue
                
            for file in files:
                if file.endswith('.ql'):
                    rule_path = os.path.join(root, file)
                    
                    # 如果有搜索词，检查文件名或内容是否匹配
                    if search_term:
                        if search_term.lower() in file.lower():
                            rules.append(rule_path)
                            continue
                        
                        # 在文件内容中搜索
                        try:
                            with open(rule_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                if search_term.lower() in content.lower():
                                    rules.append(rule_path)
                        except Exception:
                            pass
                    else:
                        rules.append(rule_path)
    
    return rules

def analyze_with_rule(repo_path, rule_path, language='javascript'):
    """使用指定规则分析仓库"""
    analyzer = CodeQLAnalyzerTester(config)
    
    print(f"使用规则 {os.path.basename(rule_path)} 分析仓库 {repo_path}")
    
    try:
        # 运行分析
        results = analyzer.analyze_repository_single_rule(repo_path, rule_path, language)
        
        # 打印结果摘要
        total_vulns = results['summary']['total_vulnerabilities']
        if total_vulns > 0:
            print(f"\n找到 {total_vulns} 个安全问题:")
            
            for vuln in results['vulnerabilities']:
                print(f"\n- {vuln['type']} (严重性: {vuln['severity']})")
                print(f"  描述: {vuln['description'][:100]}...")
                print(f"  OWASP: {vuln.get('owasp_category', 'N/A')}")
                print(f"  CWE: {vuln.get('cwe_id', 'N/A')}")
                
                for i, instance in enumerate(vuln['instances']):
                    print(f"\n  实例 {i+1}:")
                    print(f"  {instance.get('message', '无消息')}")
                    
                    for loc in instance.get('locations', []):
                        print(f"  文件: {loc['file']}, 行: {loc['start_line']}-{loc['end_line']}")
                    
                    if i >= 2:  # 只显示前3个实例
                        remaining = len(vuln['instances']) - 3
                        if remaining > 0:
                            print(f"\n  还有 {remaining} 个实例...")
                        break
        else:
            print("\n未发现安全问题")
        
        return results
        
    except Exception as e:
        print(f"分析失败: {str(e)}")
        return None

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='测试单个CodeQL规则')
    parser.add_argument('--repo', help='要分析的代码仓库路径', required=True)
    parser.add_argument('--rule', help='要使用的规则路径', required=False)
    parser.add_argument('--language', help='代码语言', default='javascript')
    parser.add_argument('--search', help='搜索规则的关键词', required=False)
    parser.add_argument('--list', help='仅列出找到的规则, 不执行分析', action='store_true')
    parser.add_argument('--experimental', help='包含实验性规则', action='store_true', default=False)
    
    args = parser.parse_args()
    
    # 如果指定了搜索词，查找匹配的规则
    if args.search:
        rules = find_rules(args.language, args.search, args.experimental)
        
        if not rules:
            print(f"未找到包含 '{args.search}' 的规则")
            return
        
        print(f"找到 {len(rules)} 个匹配 '{args.search}' 的规则:")
        for i, rule in enumerate(rules):
            # 标记实验性规则
            is_experimental = '/experimental/' in rule
            rule_type = '[实验性]' if is_experimental else '[标准]'
            print(f"{i+1}. {rule_type} {os.path.basename(rule)} - {rule}")
        
        if args.list:
            return
        
        # 如果有多个规则且没有指定具体规则，询问用户选择
        if len(rules) > 1 and not args.rule:
            choice = input("\n请选择要使用的规则编号 (输入0取消): ")
            try:
                index = int(choice) - 1
                if index < 0:
                    print("已取消")
                    return
                
                args.rule = rules[index]
            except (ValueError, IndexError):
                print("无效选择")
                return
        else:
            args.rule = rules[0]
    
    # 如果有规则路径，执行分析
    if args.rule:
        analyze_with_rule(args.repo, args.rule, args.language)
    else:
        print("错误: 必须通过--rule指定规则路径，或通过--search搜索规则")

if __name__ == "__main__":
    main() 