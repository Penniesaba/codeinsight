#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Git工具模块
---------
这个模块提供了Git仓库相关的工具函数，如克隆仓库、检查仓库等。
"""

import os
import subprocess
import logging
import re
import tempfile
import shutil
from urllib.parse import urlparse
import json

# 设置日志记录器
logger = logging.getLogger(__name__)

def clone_repository(repo_url, target_dir, protocol='http'):
    """
    克隆Git仓库到指定目录
    
    参数:
        repo_url: 仓库URL，支持GitHub和Gitee
        target_dir: 目标目录
        protocol: 克隆协议，'http'或'ssh'
        
    返回:
        仓库本地路径
    """
    logger.info(f"克隆仓库: {repo_url} 到 {target_dir}, 协议: {protocol}")
    
    # 检查和处理URL
    original_url = repo_url  # 保存原始URL
    original_protocol = protocol
    repo_url = sanitize_repo_url(repo_url, protocol)
    
    logger.debug(f"处理后的URL: {repo_url}")
    
    # 提取仓库名称作为目录名
    repo_name = extract_repo_name(repo_url)
    repo_path = os.path.join(target_dir, repo_name)
    
    # 如果目标目录已存在，确保它是空的
    if os.path.exists(repo_path):
        logger.debug(f"目录已存在: {repo_path}，清空它")
        shutil.rmtree(repo_path)
    
    # 创建父目录
    os.makedirs(target_dir, exist_ok=True)
    
    try:
        # 执行git clone命令
        cmd = ['git', 'clone', '--depth=1', repo_url, repo_path]
        logger.debug(f"执行命令: {' '.join(cmd)}")
        
        # 添加环境变量，确保SSH命令可以正确运行
        env = os.environ.copy()
        env['GIT_SSH_COMMAND'] = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
        
        process = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,  # 5分钟超时
            env=env  # 使用修改后的环境变量
        )
        
        logger.info(f"仓库克隆成功: {repo_path}")
        
        # 验证仓库是否有效
        if not is_valid_repository(repo_path):
            raise ValueError(f"克隆的仓库无效: {repo_path}")
        
        return repo_path
    
    except subprocess.SubprocessError as e:
        error_msg = f"仓库克隆失败: {str(e)}"
        error_output = ""
        if hasattr(e, 'stderr'):
            error_output = e.stderr
            error_msg += f", 错误输出: {error_output}"
        
        logger.error(error_msg)
        
        # 清理部分克隆的目录
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)
        
        # 如果是SSH克隆失败，记录更多信息以帮助调试
        if original_protocol == 'ssh':
            logger.warning("SSH克隆失败，记录相关信息")
            # 尝试获取SSH设置信息（不含敏感信息）
            try:
                ssh_info = {
                    "SSH_AUTH_SOCK": os.environ.get("SSH_AUTH_SOCK", "未设置"),
                    "USER": os.environ.get("USER", "未设置"),
                    "HOME": os.environ.get("HOME", "未设置")
                }
                logger.debug(f"SSH环境变量: {json.dumps(ssh_info)}")
                
                # 测试SSH是否正常工作
                ssh_test_cmd = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no', 
                                '-o', 'UserKnownHostsFile=/dev/null', '-v', 'git@github.com']
                try:
                    ssh_test = subprocess.run(
                        ssh_test_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=10
                    )
                    logger.debug(f"SSH测试输出: {ssh_test.stderr}")
                except Exception as ssh_e:
                    logger.debug(f"SSH测试失败: {str(ssh_e)}")
            except Exception as debug_e:
                logger.debug(f"获取SSH调试信息失败: {str(debug_e)}")
                
            # 尝试使用HTTP协议
            logger.warning("尝试使用HTTP协议克隆")
            try:
                # 如果之前已经转换过URL，先尝试使用原始URL
                http_repo_url = sanitize_repo_url(original_url, 'http')
                logger.debug(f"尝试使用HTTP协议克隆: {http_repo_url}")
                
                cmd = ['git', 'clone', '--depth=1', http_repo_url, repo_path]
                process = subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=300
                )
                
                logger.info(f"使用HTTP协议克隆成功: {repo_path}")
                
                if not is_valid_repository(repo_path):
                    raise ValueError(f"克隆的仓库无效: {repo_path}")
                
                return repo_path
            except subprocess.SubprocessError as http_e:
                http_error_msg = f"使用HTTP协议克隆也失败: {str(http_e)}"
                if hasattr(http_e, 'stderr'):
                    http_error_msg += f", 错误输出: {http_e.stderr}"
                logger.error(http_error_msg)
                # 继续抛出原始SSH错误
        
        raise RuntimeError(error_msg)

def is_valid_repository(repo_path):
    """
    检查本地路径是否为有效的Git仓库
    
    参数:
        repo_path: 仓库路径
        
    返回:
        如果是有效仓库，返回True，否则返回False
    """
    logger.debug(f"检查仓库有效性: {repo_path}")
    
    # 检查.git目录是否存在
    git_dir = os.path.join(repo_path, '.git')
    if not os.path.isdir(git_dir):
        logger.warning(f"不是有效的Git仓库（没有.git目录）: {repo_path}")
        return False
    
    # 检查是否能执行git命令
    try:
        cmd = ['git', '-C', repo_path, 'status']
        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        logger.debug(f"仓库状态: {result.stdout.strip()}")
        return True
    
    except subprocess.SubprocessError as e:
        logger.warning(f"仓库检查失败: {str(e)}")
        return False

def sanitize_repo_url(url, protocol='http'):
    """
    标准化Git仓库URL
    
    参数:
        url: 原始URL
        protocol: 协议类型 'http' 或 'ssh'
        
    返回:
        标准化后的URL
    """
    url = url.strip()
    
    logger.debug(f"标准化仓库URL: {url}, 协议: {protocol}")
    
    # 提取域名、用户和仓库部分
    if url.startswith(('http://', 'https://')):
        # 从HTTP URL提取信息
        match = re.match(r'https?://(?:www\.)?([^/]+)/([^/]+)/([^/.]+)(?:\.git)?', url)
        if match:
            domain, user, repo = match.groups()
        else:
            logger.warning(f"无法解析HTTP URL: {url}")
            return url  # 无法解析，返回原始URL
    elif url.startswith(('git@', 'ssh://')):
        # 处理不同格式的SSH URL
        if url.startswith('git@'):
            # 标准格式 git@github.com:username/repo.git
            match = re.match(r'git@([^:]+):([^/]+)/([^/.]+)(?:\.git)?', url)
            if match:
                domain, user, repo = match.groups()
            else:
                logger.warning(f"无法解析SSH URL (git@): {url}")
                return url
        elif url.startswith('ssh://'):
            # ssh://git@github.com/username/repo.git 或 ssh://git@github.com:22/username/repo.git
            match = re.match(r'ssh://(?:git@)?([^:/]+)(?::\d+)?/([^/]+)/([^/.]+)(?:\.git)?', url)
            if match:
                domain, user, repo = match.groups()
            else:
                logger.warning(f"无法解析SSH URL (ssh://): {url}")
                return url
    else:
        # 尝试解析可能是简写形式的URL (如 username/repo)
        parts = url.split('/')
        if len(parts) == 2 and all(parts):
            # 假设是GitHub
            domain, user, repo = 'github.com', parts[0], parts[1]
            logger.debug(f"解析简写URL: {url} -> domain={domain}, user={user}, repo={repo}")
        else:
            logger.warning(f"无法识别的URL格式: {url}")
            return url  # 无法解析，返回原始URL
    
    # 根据请求的协议生成URL
    if protocol == 'http':
        result = f'https://{domain}/{user}/{repo}.git'
    elif protocol == 'ssh':
        result = f'git@{domain}:{user}/{repo}.git'
    else:
        raise ValueError(f"不支持的协议: {protocol}")
    
    logger.debug(f"URL标准化结果: {url} -> {result}")
    return result

def extract_repo_name(repo_url):
    """
    从仓库URL中提取仓库名称
    
    参数:
        repo_url: 仓库URL
        
    返回:
        仓库名称
    """
    # 处理SSH格式: git@github.com:username/repo.git
    ssh_match = re.match(r'git@[^:]+:([^/]+)/([^/]+)\.git$', repo_url)
    if ssh_match:
        return ssh_match.group(2)
    
    # 解析HTTP URL
    parsed_url = urlparse(repo_url)
    
    # 从路径中获取最后一部分作为仓库名
    path = parsed_url.path.strip('/')
    
    if path.endswith('.git'):
        path = path[:-4]  # 移除.git后缀
    
    repo_name = path.split('/')[-1]
    
    # 如果仓库名为空，生成一个随机名称
    if not repo_name:
        import uuid
        repo_name = f"repo-{uuid.uuid4().hex[:8]}"
        logger.warning(f"无法从URL提取仓库名，使用随机名称: {repo_name}")
    
    logger.debug(f"从URL提取仓库名: {repo_url} -> {repo_name}")
    return repo_name

def get_default_branch(repo_path):
    """
    获取仓库的默认分支
    
    参数:
        repo_path: 仓库路径
        
    返回:
        默认分支名称
    """
    logger.debug(f"获取仓库默认分支: {repo_path}")
    
    try:
        cmd = ['git', '-C', repo_path, 'symbolic-ref', '--short', 'HEAD']
        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        branch = result.stdout.strip()
        logger.debug(f"默认分支: {branch}")
        return branch
    
    except subprocess.SubprocessError as e:
        logger.warning(f"获取默认分支失败: {str(e)}")
        # 返回常见的默认分支名
        return 'main' 