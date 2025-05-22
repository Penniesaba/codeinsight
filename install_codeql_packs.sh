#!/bin/bash

# 安装CodeQL依赖包
echo "安装CodeQL依赖包..."

# 检查codeql命令是否存在
if ! command -v codeql &> /dev/null; then
    echo "错误: codeql命令未找到，请确保CodeQL CLI已正确安装"
    exit 1
fi

# 设置库路径
CODEQL_CUSTOM_DIR="app/codeql/custom_rules"

# 确保自定义目录存在
mkdir -p "$CODEQL_CUSTOM_DIR"

# 进入自定义查询目录
cd "$CODEQL_CUSTOM_DIR" || exit 1

# 只为Python安装依赖
if [ -d "python" ]; then
    echo "为Python安装依赖..."
    cd "python" || exit 1
    
    # 检查是否存在qlpack.yml
    if [ -f "qlpack.yml" ]; then
        echo "运行 'codeql pack install' 安装依赖..."
        codeql pack install
    else
        echo "警告: python目录中未找到qlpack.yml文件"
    fi
else
    echo "警告: 未找到python目录"
fi

echo "完成!" 