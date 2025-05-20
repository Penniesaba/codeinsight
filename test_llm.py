#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
测试LLM配置是否正确
"""

import os
import sys
from config import Config
from app.llm.enhancer import LLMEnhancer

def test_llm_config():
    """测试LLM配置是否正确"""
    print("测试LLM配置")
    print(f"API密钥: {Config.LLM_API_KEY}")
    print(f"模型名称: {Config.LLM_MODEL}")
    print(f"API地址: {Config.LLM_API_URL}")
    print(f"使用OpenAI兼容模式: {Config.LLM_USE_OPENAI_COMPATIBLE}")
    
    # 测试OpenAI库是否已安装
    try:
        from openai import OpenAI
        print("OpenAI库已安装")
    except ImportError:
        print("OpenAI库未安装，请运行: pip install openai")
        return

    # 测试LLM API调用
    try:
        # 创建一个配置字典
        config = {
            'LLM_API_KEY': Config.LLM_API_KEY,
            'LLM_MODEL': Config.LLM_MODEL,
            'LLM_API_URL': Config.LLM_API_URL,
            'LLM_USE_OPENAI_COMPATIBLE': Config.LLM_USE_OPENAI_COMPATIBLE
        }
        enhancer = LLMEnhancer(config)
        result = enhancer._call_llm_api("你好，请用一句话介绍一下自己。")
        print(f"LLM API调用成功，返回结果: {result}")
    except Exception as e:
        print(f"LLM API调用失败: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_llm_config() 