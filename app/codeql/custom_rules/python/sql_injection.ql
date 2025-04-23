/**
 * @name SQL注入漏洞检测
 * @description 检测可能存在SQL注入漏洞的代码
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.security.dataflow.SqlInjection
import DataFlow::PathGraph

from SqlInjection::Configuration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL查询中包含未净化的用户输入，可能导致SQL注入漏洞。" 