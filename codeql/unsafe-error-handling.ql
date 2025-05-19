/**
 * @name 不安全的API错误处理
 * @description 检测API错误处理中可能导致信息泄露的问题
 * @kind problem
 * @problem.severity warning
 * @id javascript/unsafe-error-handling
 */

import javascript

from FunctionExpr func, TryStmt tryStmt, CatchClause catchClause
where 
  func.getAChildStmt*() = tryStmt and
  tryStmt.getCatchClause() = catchClause and
  exists(CallExpr consoleLog |
    consoleLog.getCalleeName() = "log" or
    consoleLog.getCalleeName() = "error" and
    catchClause.getAChildStmt*().getAChildExpr*() = consoleLog
  ) and
  not exists(IfStmt ifCheck |
    ifCheck = catchClause.getAChildStmt*() and
    ifCheck.getCondition().toString().matches("%isDevelopment%")
  )
select func, "API错误处理中直接输出错误信息，可能导致敏感信息泄露"