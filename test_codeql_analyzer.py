#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
测试CodeQL分析器的功能
"""

import os
import sys
import logging
import json

# 添加应用程序路径到系统路径
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app.codeql.analyzer import CodeQLAnalyzer

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)

# 测试配置
config = {
    'CODEQL_CLI_PATH': '/usr/local/bin/codeql',  # 修正为实际的codeql命令路径
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

def test_get_query_packs():
    """测试获取查询包功能"""
    analyzer = CodeQLAnalyzerTester(config)
    
    print("\n测试查询包获取功能:")
    for language in ['javascript', 'python', 'java']:
        packs = analyzer._get_query_packs(language)
        print(f"\n{language} 语言的查询包:")
        for pack in packs:
            print(f"  - {pack} {'(存在)' if os.path.exists(pack) else '(不存在)'}")

def test_get_custom_rules():
    """测试获取自定义规则功能"""
    analyzer = CodeQLAnalyzerTester(config)
    
    print("\n测试自定义规则获取功能:")
    for language in ['javascript', 'python', 'java']:
        rules = analyzer._get_custom_rules(language)
        print(f"\n{language} 语言的自定义规则:")
        for rule in rules:
            print(f"  - {rule} {'(存在)' if os.path.exists(rule) else '(不存在)'}")

def test_paths():
    """测试所有涉及的路径是否存在"""
    print("\n测试相关路径:")
    
    paths = [
        # 官方查询路径
        '/home/xiao/project/condeinsight/codeql/javascript',
        '/home/xiao/project/condeinsight/codeql/javascript/ql/src/Security',
        '/home/xiao/project/codeinsight/codeql/javascript',
        '/home/xiao/project/codeinsight/codeql/javascript/ql/src/Security',
        '/home/xiao/project/codeinsight/app/codeql/queries',
        
        # 自定义规则路径
        '/home/xiao/project/codeinsight/app/codeql/custom_rules/javascript',
        '/home/xiao/project/condeinsight/codeql/javascript/custom_rules',
        '/home/xiao/project/codeinsight/codeql/javascript/custom_rules',
        '/home/xiao/project/condeinsight/codeql/javascript/ql/src/experimental',
        '/home/xiao/project/codeinsight/codeql/javascript/ql/src/experimental'
    ]
    
    for path in paths:
        exists = os.path.exists(path)
        print(f"  - {path}: {'存在' if exists else '不存在'}")
        
        # 如果路径存在且是目录，列出内容
        if exists and os.path.isdir(path):
            try:
                files = os.listdir(path)
                if files:
                    print(f"    内容: {', '.join(files[:5])}{'...' if len(files) > 5 else ''}")
                else:
                    print("    目录为空")
            except Exception as e:
                print(f"    无法列出内容: {str(e)}")

def list_individual_rules():
    """列出可以单独运行的规则"""
    analyzer = CodeQLAnalyzerTester(config)
    
    print("\n找到可以单独运行的规则:")
    
    # 检查官方路径
    official_paths = [
        '/home/xiao/project/condeinsight/codeql/javascript/ql/src/Security',
        '/home/xiao/project/codeinsight/codeql/javascript/ql/src/Security',
        '/home/xiao/project/codeinsight/app/codeql/queries/javascript/ql/src/Security'
    ]
    
    all_rules = []
    
    # 查找所有.ql文件
    for base_path in official_paths:
        if os.path.exists(base_path):
            print(f"\n路径 {base_path} 中的规则:")
            count = 0
            
            for root, _, files in os.walk(base_path):
                for file in files:
                    if file.endswith('.ql'):
                        rule_path = os.path.join(root, file)
                        all_rules.append(rule_path)
                        
                        # 只打印前10个规则
                        if count < 10:
                            # 尝试读取规则描述
                            description = "无描述"
                            try:
                                with open(rule_path, 'r', encoding='utf-8') as f:
                                    content = f.read(500)  # 只读取前500个字符
                                    desc_match = content.split('/**', 1)
                                    if len(desc_match) > 1:
                                        desc_text = desc_match[1].split('*/', 1)[0]
                                        desc_lines = [line.strip(' *') for line in desc_text.split('\n')]
                                        description = ' '.join([line for line in desc_lines if line])[:100] + '...'
                            except Exception:
                                pass
                            
                            print(f"  {count+1}. {os.path.relpath(rule_path, base_path)}")
                            print(f"     描述: {description}")
                            count += 1
            
            print(f"  总计: {len(all_rules)} 条规则")
    
    # 查找自定义规则
    custom_rules = analyzer._get_custom_rules('javascript')
    if custom_rules:
        print("\n自定义规则:")
        for i, rule in enumerate(custom_rules[:10]):  # 只显示前10个
            print(f"  {i+1}. {os.path.basename(rule)}")
        
        print(f"  总计: {len(custom_rules)} 条自定义规则")
    
    return all_rules

def main():
    """主测试函数"""
    print("=== 开始测试CodeQL分析器 ===")
    
    # 测试相关路径
    test_paths()
    
    # 列出可用的单个规则
    list_individual_rules()
    
    # 测试查询包获取
    test_get_query_packs()
    
    # 测试自定义规则获取
    test_get_custom_rules()
    
    print("\n=== 测试完成 ===")

if __name__ == "__main__":
    main() 