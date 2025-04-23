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
    
    try:
        repo_url = sanitize_repo_url(repo_url, protocol)
        logger.debug(f"处理后的URL: {repo_url}")
    except ValueError as e:
        logger.error(f"URL处理错误: {str(e)}")
        raise
    
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
        
        # 检查是否SSH克隆失败（检查权限错误或公钥错误）
        should_retry_with_http = False
        if original_protocol == 'ssh' and error_output:
            if 'Permission denied' in error_output or 'publickey' in error_output:
                logger.warning("检测到SSH认证失败，将尝试使用HTTP协议")
                should_retry_with_http = True
            else:
                logger.debug(f"SSH克隆失败，但不是由于认证问题: {error_output}")
        
        if should_retry_with_http or original_protocol == 'ssh':
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
                # 使用原始URL生成HTTP URL
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
        
        # 如果HTTP克隆也失败，或者原始协议是HTTP就直接失败
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
    
    # 处理空URL
    if not url:
        logger.error("空URL不能被标准化")
        raise ValueError("仓库URL不能为空")
    
    # 移除URL中的.git后缀（稍后会重新添加）
    url = re.sub(r'\.git$', '', url)
    
    # 提取域名、用户和仓库部分
    domain, user, repo = None, None, None
    
    # 处理HTTP/HTTPS URL
    if url.startswith(('http://', 'https://')):
        # 从HTTP URL提取信息 - 支持常见代码托管平台格式
        match = re.match(r'https?://(?:www\.)?([^/]+)/([^/]+)/([^/]+)(?:/.*)?', url)
        if match:
            domain, user, repo = match.groups()
        else:
            logger.warning(f"无法解析HTTP URL: {url}")
            return url  # 无法解析，返回原始URL
    
    # 处理SSH URL
    elif url.startswith(('git@', 'ssh://')):
        if url.startswith('git@'):
            # 标准格式 git@github.com:username/repo
            match = re.match(r'git@([^:]+):([^/]+)/([^/]+)(?:/.*)?', url)
            if match:
                domain, user, repo = match.groups()
            else:
                logger.warning(f"无法解析SSH URL (git@): {url}")
                return url
        elif url.startswith('ssh://'):
            # 格式 ssh://git@github.com/username/repo 或 ssh://git@github.com:22/username/repo
            match = re.match(r'ssh://(?:git@)?([^:/]+)(?::\d+)?/([^/]+)/([^/]+)(?:/.*)?', url)
            if match:
                domain, user, repo = match.groups()
            else:
                logger.warning(f"无法解析SSH URL (ssh://): {url}")
                return url
    
    # 处理git:// URL
    elif url.startswith('git://'):
        match = re.match(r'git://([^/]+)/([^/]+)/([^/]+)(?:/.*)?', url)
        if match:
            domain, user, repo = match.groups()
        else:
            logger.warning(f"无法解析git:// URL: {url}")
            return url
    
    # 处理简写形式
    else:
        # 尝试解析可能是简写形式的URL (如 username/repo)
        parts = url.split('/')
        if len(parts) >= 2 and all(p.strip() for p in parts[:2]):
            # 假设是GitHub
            user, repo = parts[0], parts[1]
            domain = 'github.com'
            logger.debug(f"解析简写URL: {url} -> domain={domain}, user={user}, repo={repo}")
        else:
            logger.warning(f"无法识别的URL格式: {url}")
            return url  # 无法解析，返回原始URL
    
    # 清理repo部分中的任何额外路径或查询参数
    repo = re.sub(r'[?#].*$', '', repo)
    
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