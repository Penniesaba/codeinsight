/**
 * @name CWE-400: 不受限制的资源消耗
 * @description 检测不受限制的网络请求，可能导致资源耗尽
 * @kind problem
 * @problem.severity error
 * @id py/resource-exhaustion
 * @tags security
 *       external/cwe/cwe-400
 */

import python

// 查找网络请求
from Call requestCall, Call regexCall, Attribute regexAttr
where 
  // 网络请求调用
  requestCall.getFunc().(Attribute).getName() = "get" and
  requestCall.getFunc().(Attribute).getObject().(Name).getId() = "requests" and
  
  // 正则表达式处理调用
  regexCall.getFunc() = regexAttr and
  regexAttr.getName() = "findall" and
  regexAttr.getObject().(Name).getId() = "re" and
  
  // 两个调用在同一个函数中
  requestCall.getScope() = regexCall.getScope() and
  
  // 没有对请求大小或超时进行限制
  not exists(Keyword timeout | 
    timeout = requestCall.getAKeyword() and
    timeout.getArg() = "timeout"
  ) and
  
  // 没有对响应大小进行限制
  not exists(Call limitCall |
    limitCall.getScope() = requestCall.getScope() and
    (limitCall.getFunc().(Attribute).getName() = "read" or
     limitCall.getFunc().(Attribute).getName() = "iter_content")
  )
select requestCall, "可能的资源耗尽漏洞：网络请求没有设置超时参数，可能导致程序挂起"