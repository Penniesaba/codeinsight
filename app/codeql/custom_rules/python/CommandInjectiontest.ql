/**
 * @name CWE-78 命令注入检测
 * @description 检测从环境获取的数据用于系统命令的情况，增加了合理的限制条件
 * @kind problem
 * @problem.severity error
 * @id py/fixed-operators-command-injection
 * @tags security
 *       external/cwe/cwe-78
 */

import python

// 查找在同一函数中同时出现 os.getcwd() 和 os.system() 的情况
from Function f, Call getcwd, Call system, Expr arg
where 
  // 在同一函数中
  getcwd.getScope() = f and
  system.getScope() = f and
  
  // os.getcwd() 调用
  getcwd.getFunc().(Attribute).getName() = "getcwd" and
  getcwd.getFunc().(Attribute).getObject().(Name).getId() = "os" and
  
  // os.system() 调用
  system.getFunc().(Attribute).getName() = "system" and
  system.getFunc().(Attribute).getObject().(Name).getId() = "os" and
  arg = system.getArg(0) and
  
  // 限制条件：命令参数必须是二元表达式
  arg instanceof BinaryExpr and
  
  // 额外限制：函数中必须有字符串分割操作（split）
  exists(Call splitCall | 
    splitCall.getScope() = f and
    splitCall.getFunc().(Attribute).getName() = "split"
  )
select system, "可能存在命令注入漏洞：在同一函数中使用了环境数据(os.getcwd)和系统命令(os.system)，且命令参数使用了字符串操作"

