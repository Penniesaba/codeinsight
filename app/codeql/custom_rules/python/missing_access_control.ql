/**
 * @name 缺少访问控制检测
 * @description 检测Web应用程序中可能缺少访问控制的路由处理函数
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.1
 * @precision medium
 * @id py/missing-access-control
 * @tags security
 *       external/cwe/cwe-284
 *       external/cwe/cwe-285
 *       external/cwe/cwe-862
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts

/**
 * 检测可能的敏感操作关键词
 */
predicate isSensitiveOperation(string name) {
  name.matches("%admin%") or
  name.matches("%delete%") or
  name.matches("%remove%") or
  name.matches("%update%") or
  name.matches("%edit%") or
  name.matches("%manage%") or
  name.matches("%config%") or
  name.matches("%profile%") or
  name.matches("%account%") or
  name.matches("%user%")
}

/**
 * 检测常见的认证检查
 */
predicate isAuthenticationCheck(DataFlow::Node node) {
  exists(string name |
    name = node.asExpr().(Call).getFunc().(Name).getId() and
    (
      name = "login_required" or
      name = "require_login" or
      name = "authenticated" or
      name = "requires_auth" or
      name = "check_auth" or
      name = "check_permission" or
      name = "has_permission" or
      name = "is_authenticated" or
      name = "is_admin"
    )
  )
}

/**
 * 标识常见的Web框架路由装饰器
 */
predicate isRouteDecorator(Expr decorator) {
  exists(Name name | 
    name = decorator.(Call).getFunc() and
    (
      name.getId() = "route" or
      name.getId() = "app.route" or
      name.getId() = "path" or
      name.getId() = "get" or
      name.getId() = "post" or
      name.getId() = "put" or
      name.getId() = "delete"
    )
  )
}

/**
 * 识别路由处理函数
 */
class RouteHandler extends Function {
  RouteHandler() {
    exists(Expr decorator |
      decorator = this.getADecorator() and
      isRouteDecorator(decorator)
    )
  }
  
  predicate hasSensitiveName() {
    isSensitiveOperation(this.getName())
  }
  
  predicate hasAuthenticationCheck() {
    exists(Expr decorator |
      decorator = this.getADecorator() and
      isAuthenticationCheck(DataFlow::exprNode(decorator))
    )
    or
    exists(Call call |
      call.getScope() = this and
      isAuthenticationCheck(DataFlow::exprNode(call))
    )
  }
}

from RouteHandler handler
where
  handler.hasSensitiveName() and
  not handler.hasAuthenticationCheck()
select handler,
  "可能缺少访问控制的敏感路由处理函数。在处理用户、管理员或敏感操作相关的路由时，应添加适当的认证和授权检查。" 