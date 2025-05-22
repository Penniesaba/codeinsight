#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
测试Python自定义规则
"""

import os
import sys
import logging

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

def test_python_custom_rules():
    """测试Python自定义规则加载"""
    analyzer = CodeQLAnalyzerTester(config)
    
    # 获取自定义规则
    python_rules = analyzer._get_custom_rules('python')
    
    print(f"\n找到 {len(python_rules)} 个Python自定义规则:")
    for i, rule in enumerate(python_rules):
        exists = os.path.exists(rule)
        status = "存在" if exists else "不存在"
        print(f"{i+1}. {rule} [{status}]")
        
        # 尝试读取规则内容的前几行
        if exists:
            try:
                with open(rule, 'r', encoding='utf-8') as f:
                    content = f.readlines()[:5]  # 读取前5行
                print(f"   文件内容片段: {''.join(content).strip()}")
            except Exception as e:
                print(f"   无法读取文件: {str(e)}")
    
    print("\n验证Python规则加载路径:")
    
    # 检查规则目录
    rule_dirs = [
        "app/codeql/custom_rules/python",
        "/home/xiao/project/codeinsight/app/codeql/custom_rules/python",
        "/home/xiao/project/condeinsight/codeql/python/custom_rules",
        "/home/xiao/project/codeinsight/codeql/python/custom_rules"
    ]
    
    for dir_path in rule_dirs:
        exists = os.path.exists(dir_path)
        status = "存在" if exists else "不存在"
        print(f"目录 {dir_path}: [{status}]")
        
        if exists:
            files = os.listdir(dir_path)
            ql_files = [f for f in files if f.endswith('.ql')]
            print(f"   包含 {len(ql_files)} 个.ql文件: {', '.join(ql_files)}")

def main():
    """主函数"""
    print("=== 测试Python自定义规则 ===")
    test_python_custom_rules()
    print("=== 测试完成 ===")

if __name__ == "__main__":
    main() 