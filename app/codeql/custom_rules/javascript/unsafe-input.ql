/**
 * @name 不安全的用户输入处理
 * @description 检测对用户输入没有进行充分验证的情况
 * @kind problem
 * @problem.severity warning
 * @id javascript/unsafe-input-handling
 */

import javascript

from DataFlow::FunctionNode func
where 
  func.getName() = "escapeDollarNumber" and
  not exists(DataFlow::MethodCallNode regexCall |
    regexCall.getMethodName() = "replace" and
    regexCall.getReceiver().getALocalSource() = func.getParameter(0) and
    regexCall.getArgument(0).toString().matches("%XSS%")
  )
select func, "转义函数只处理了特定的字符模式，没有全面防御XSS攻击"