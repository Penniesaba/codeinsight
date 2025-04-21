# CodeInsight - 代码安全分析平台

CodeInsight是一个结合CodeQL静态分析和大语言模型能力的代码安全分析平台，帮助开发者自动识别代码中的安全漏洞，并提供专业的修复建议。

## 功能特点

- **自动代码分析**：输入GitHub或Gitee仓库链接，自动拉取并分析代码
- **多语言支持**：支持分析JavaScript、Python、Java、C/C++等多种编程语言
- **智能漏洞检测**：使用CodeQL强大的查询能力识别常见安全漏洞
- **AI增强报告**：结合大语言模型生成更易理解的漏洞描述和修复建议
- **无数据库设计**：使用文件系统缓存，降低部署复杂度
- **美观的可视化界面**：基于Bootstrap的直观操作界面

## 系统架构

本系统主要由以下三个核心组件构成：

1. **CodeQL静态分析引擎**：负责代码扫描和漏洞识别
2. **大语言模型增强层**：提升漏洞描述的可读性并生成修复建议
3. **Web交互界面**：提供友好的用户交互体验

## 安装指南

### 前置条件

- Python 3.8+
- Git
- CodeQL CLI

### 安装步骤

1. 克隆仓库
```bash
git clone https://github.com/yourusername/codeinsight.git
cd codeinsight
```

2. 创建并激活虚拟环境
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

3. 安装依赖
```bash
pip install -r requirements.txt
```

4. 安装CodeQL CLI
   
   请参考[CodeQL CLI官方安装指南](https://github.com/github/codeql-cli-binaries/releases)下载并安装适合您系统的版本，确保`codeql`命令可在终端中使用。

5. 配置API密钥（可选）
   
   如果您希望使用特定的大语言模型API，请在`config.py`中配置相应的API密钥。

## 使用教程

### 启动应用

```bash
python run.py
```

应用将在`http://127.0.0.1:5000`启动，通过浏览器访问即可。

### 分析代码仓库

1. 在首页输入要分析的GitHub或Gitee仓库URL
2. 选择分析语言（如不选择，系统将自动检测）
3. 点击"开始分析"按钮
4. 等待分析完成，系统将自动跳转到结果页面

### 查看分析报告

分析报告页面分为三个主要部分：

1. **总览**：显示检测到的漏洞总数、严重程度分布等统计信息
2. **漏洞列表**：列出所有检测到的漏洞，按严重程度排序
3. **详细信息**：点击具体漏洞可查看详细的漏洞描述、影响分析和修复建议

### 导出报告

在结果页面可以将分析报告导出为PDF或JSON格式，方便分享或存档。

## 疑难解答

如果遇到问题，请检查：

1. CodeQL CLI是否正确安装并添加到系统PATH
2. 网络连接是否正常（拉取代码库需要网络连接）
3. 日志文件`logs/app.log`中的错误信息

## 开发指南

详细的开发文档请参考`docs/developer_guide.md`。

## 许可证

MIT 