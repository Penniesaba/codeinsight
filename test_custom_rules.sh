#!/bin/bash

# 定义颜色变量
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # 无颜色

echo -e "${YELLOW}开始测试自定义CodeQL规则...${NC}"

# 规则文件列表
RULES=(
    "app/codeql/custom_rules/python/UnsafeDeserialization_pickle.ql"
    "app/codeql/custom_rules/python/CommandInjectiontest.ql"
    "app/codeql/custom_rules/python/ResourceExhaustion.ql"
)

# 测试目录 - 指向我们创建的示例代码
TEST_REPO_PATH="$(pwd)/test_vulnerable_code"

# 确保测试目录存在
mkdir -p "$TEST_REPO_PATH"

# 1. 首先测试每个规则的编译
echo -e "\n${YELLOW}第一步：编译规则文件检查语法${NC}"
for rule in "${RULES[@]}"; do
    echo -e "\n测试编译: ${rule}"
    if ! codeql query compile "$rule"; then
        echo -e "${RED}编译失败: $rule${NC}"
        echo -e "继续测试其他规则..."
        continue
    else
        echo -e "${GREEN}编译成功: $rule${NC}"
    fi
done

# 2. 创建CodeQL数据库（如果还没有）
echo -e "\n${YELLOW}第二步：为测试代码创建CodeQL数据库${NC}"
DB_PATH="$(pwd)/test_vulnerable_code_db"

echo -e "创建数据库: $DB_PATH"
if ! codeql database create --overwrite --language=python --source-root="$TEST_REPO_PATH" "$DB_PATH"; then
    echo -e "${RED}创建数据库失败${NC}"
    exit 1
else
    echo -e "${GREEN}数据库创建成功${NC}"
fi

# 3. 在测试数据库上运行每个规则
echo -e "\n${YELLOW}第三步：在测试数据库上运行规则${NC}"
for rule in "${RULES[@]}"; do
    RULE_NAME=$(basename "$rule" .ql)
    echo -e "\n运行规则: ${RULE_NAME}"
    
    RESULTS_PATH="$(pwd)/results_${RULE_NAME}.sarif"
    
    if ! codeql database analyze "$DB_PATH" "$rule" --format=sarif-latest --output="$RESULTS_PATH"; then
        echo -e "${RED}规则运行失败: $rule${NC}"
        continue
    else
        # 检查结果文件
        if [ -f "$RESULTS_PATH" ]; then
            # 使用jq检查结果数量
            if command -v jq &> /dev/null; then
                ISSUE_COUNT=$(jq '.runs[0].results | length' "$RESULTS_PATH" 2>/dev/null || echo "0")
                if [ "$ISSUE_COUNT" -gt 0 ]; then
                    echo -e "${GREEN}规则检测到 $ISSUE_COUNT 个潜在问题${NC}"
                    # 提取并显示结果摘要
                    echo -e "${YELLOW}结果摘要:${NC}"
                    jq -r '.runs[0].results[] | "  - " + .message.text' "$RESULTS_PATH" 2>/dev/null || echo "  无法解析结果文件"
                else
                    echo -e "${YELLOW}规则未检测到问题${NC}"
                fi
            else
                # 如果没有jq，使用grep
                ISSUE_COUNT=$(grep -c "ruleId" "$RESULTS_PATH" || echo "0")
                if [ "$ISSUE_COUNT" -gt 0 ]; then
                    echo -e "${GREEN}规则检测到问题，但需要安装jq来显示详细信息${NC}"
                else
                    echo -e "${YELLOW}规则未检测到问题${NC}"
                fi
            fi
        else
            echo -e "${RED}未生成结果文件${NC}"
        fi
    fi
done

echo -e "\n${GREEN}测试完成！${NC}"
echo -e "详细结果保存在 results_*.sarif 文件中" 