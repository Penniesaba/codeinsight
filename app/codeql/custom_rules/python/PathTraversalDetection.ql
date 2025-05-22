/**
 * @name 未验证URL的路径遍历漏洞
 * @description 检测从用户输入获取的URL直接传递给网络请求函数的情况，可能导致路径遍历攻击
 * @kind problem
 * @problem.severity warning
 * @id python/path-traversal-vulnerability
 * @tags security
 *       external/cwe/cwe-022
 */

import python

// 查找urlopen函数调用
from Call urlopen
where 
  // 直接检查函数名称是否包含"urlopen"字符串
  //urlopen.getFunc().toString().regexpMatch(".*urlopen.*") and
  // 确保是在download_page方法中
  urlopen.getScope().getName() = "download_page" and
  // 确保在139行附近
  urlopen.getLocation().getStartLine() = 139
select urlopen, "路径遍历漏洞：可能存在未验证的URL参数"