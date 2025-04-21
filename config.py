import os
from datetime import timedelta

# 基础配置
class Config:
    """应用程序配置类"""
    
    # 应用配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-please-change-in-production'
    
    # 路径配置
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    CACHE_DIR = os.path.join(BASE_DIR, 'cache')
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    REPO_CACHE_DIR = os.path.join(CACHE_DIR, 'repos')
    ANALYSIS_CACHE_DIR = os.path.join(CACHE_DIR, 'analysis')
    
    # CodeQL配置
    CODEQL_CLI_PATH = os.environ.get('CODEQL_CLI_PATH') or 'codeql'  # 确保CodeQL在PATH中，或设置环境变量
    CODEQL_QUERIES_PATH = os.path.join(BASE_DIR, 'app', 'codeql', 'queries')
    GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN') or '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' 
    
    # 大语言模型配置
    LLM_API_KEY = os.environ.get('LLM_API_KEY') or ''
    LLM_MODEL = os.environ.get('LLM_MODEL') or 'qwen-max'  # 默认使用通义千问
    LLM_API_URL = os.environ.get('LLM_API_URL') or 'https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation'
    
    # 缓存配置（替代数据库）
    CACHE_LIFETIME = timedelta(days=7)  # 缓存有效期
    
    # 日志配置
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_FILE = os.path.join(LOG_DIR, 'app.log')
    
    # Git配置
    GIT_TIMEOUT = 300  # Git操作超时时间(秒)

# 开发环境配置
class DevelopmentConfig(Config):
    """开发环境配置"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'

# 生产环境配置
class ProductionConfig(Config):
    """生产环境配置"""
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')  # 生产环境必须设置环境变量
    
    # 在生产环境中可以添加更多安全配置
    
# 测试环境配置
class TestingConfig(Config):
    """测试环境配置"""
    TESTING = True
    LOG_LEVEL = 'DEBUG'
    CACHE_DIR = os.path.join(Config.BASE_DIR, 'tests', 'cache')
    LOG_DIR = os.path.join(Config.BASE_DIR, 'tests', 'logs')

# 配置字典
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
} 