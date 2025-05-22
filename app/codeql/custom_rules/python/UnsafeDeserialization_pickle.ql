/**
 * @name 不安全的pickle反序列化 (CWE-502)
 * @description 检测使用pickle.loads()进行反序列化的情况，这可能导致远程代码执行
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id py/unsafe-pickle-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import python

/**
 * 识别pickle.loads调用
 */
class PickleLoadsCall extends Call {
  PickleLoadsCall() {
    // 检查是否是对pickle.loads的调用
    exists(Name pickle, Attribute loads |
      pickle.getId() = "pickle" and
      loads.getObject() = pickle and
      loads.getName() = "loads" and
      this.getFunc() = loads
    )
  }
}

/**
 * 识别socket.recv调用
 */
class SocketRecvCall extends Call {
  SocketRecvCall() {
    // 检查是否是对socket.recv或类似方法的调用
    exists(Attribute recv |
      recv.getName() = "recv" and
      this.getFunc() = recv
    )
  }
}

/**
 * 检查是否在同一个函数中同时使用了socket.recv和pickle.loads
 */
predicate usesRecvAndPickleLoads(Function f) {
  exists(PickleLoadsCall loads, SocketRecvCall recv |
    loads.getScope() = f and recv.getScope() = f
  )
}

from PickleLoadsCall loads, Function f
where 
  loads.getScope() = f 
select loads, "在函数 '" + f.getName() + "' 中使用了不安全的pickle.loads反序列化，可能导致远程代码执行漏洞。"

// /**
//  * @name Custom pickle.loads deserialization detection
//  * @description Detects untrusted socket input passed into pickle.loads()
//  * @kind path-problem
//  * @id py/custom-unsafe-pickle
//  * @tags security
//  * @problem.severity warning
//  * @precision high
//  */

// import python
// import semmle.python.security.dataflow.UnsafeDeserializationQuery
// import DataFlow::PathGraph

// class MyConfig extends TaintTracking::Configuration {
//   MyConfig() { this = "my-pickle-taint-config" }

//   override predicate isSource(DataFlow::Node source) {
//     exists(Call recvCall |
//       recvCall.getFunc() instanceof Attribute and
//       recvCall.getFunc().(Attribute).getAttr() = "recv" and
//       source.asExpr() = recvCall
//     )
//   }

//   override predicate isSink(DataFlow::Node sink) {
//     exists(Call call, Attribute attr |
//       call.getFunc() = attr and
//       attr.getAttr() = "loads" and
//       attr.getObject() instanceof Name and  
//       attr.getObject().(Name).getId() = "pickle" and 
//       sink.asExpr() = call
//     )
//   }
// }

// from MyConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
// where config.hasFlowPath(source, sink)
// //select sink.getNode(), "Untrusted data flows into pickle.loads()", source, sink
// select sink.getNode(), source, sink, "不安全地使用 pickle.loads 反序列化来自 $@ 的数据", source.getNode(), "网络源"




