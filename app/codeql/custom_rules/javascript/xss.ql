/**
 * @name 跨站脚本攻击（XSS）漏洞检测
 * @description 检测可能导致XSS的代码
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id js/xss
 * @tags security
 *       external/cwe/cwe-079
 */

import javascript
import semmle.javascript.security.dataflow.XSS
import DataFlow::PathGraph

from DOM::XSS::Configuration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "DOM上下文中包含未经过滤的用户输入，可能导致跨站脚本攻击。" 