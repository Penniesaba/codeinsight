/**
 * @name Custom pickle.loads deserialization detection
 * @description Detects untrusted socket input passed into pickle.loads()
 * @kind path-problem
 * @id py/custom-unsafe-pickle
 * @tags security
 * @problem.severity warning
 * @precision high
 */

import python
import semmle.python.security.dataflow.UnsafeDeserializationQuery
import DataFlow::PathGraph

class MyConfig extends TaintTracking::Configuration {
  MyConfig() { this = "my-pickle-taint-config" }

  override predicate isSource(DataFlow::Node source) {
    exists(Call recvCall |
      recvCall.getFunc() instanceof Attribute and
      recvCall.getFunc().(Attribute).getAttr() = "recv" and
      source.asExpr() = recvCall
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call call, Attribute attr |
      call.getFunc() = attr and
      attr.getAttr() = "loads" and
      attr.getObject() instanceof Name and  
      attr.getObject().(Name).getId() = "pickle" and 
      sink.asExpr() = call
    )
  }
}

from MyConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), "Untrusted data flows into pickle.loads()", source, sink





