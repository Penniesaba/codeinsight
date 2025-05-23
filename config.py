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
    # 直接在配置文件中设置API密钥，不依赖环境变量
    # 注意：在实际部署时，建议使用环境变量存储密钥
    # 阿里云通义千问示例: sk-xxxx...
    # OpenAI示例: sk-xxxx...
    LLM_API_KEY = 'sk-c9416c5d823540e0a56b80a98684e8fe'  # 请将这里替换为您真实的API密钥
    LLM_MODEL = 'qwen-plus'  # 默认使用通义千问(qwen-plus)，也可以使用'gpt-3.5-turbo'或其他
    LLM_API_URL = 'https://dashscope.aliyuncs.com/compatible-mode/v1'  # 使用通义千问API接口
    LLM_USE_OPENAI_COMPATIBLE = True  # 使用OpenAI兼容模式
    
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