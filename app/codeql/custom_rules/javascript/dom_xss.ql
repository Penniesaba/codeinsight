/**
 * @name DOM XSS漏洞检测
 * @description 检测JavaScript代码中可能存在的DOM XSS漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id js/dom-xss
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript
import DataFlow::PathGraph
import semmle.javascript.security.dataflow.DomBasedXss::DomBasedXss

/**
 * 在URL中检测危险的参数名称
 */
predicate isDangerousUrlParamName(string name) {
  name = "q" or
  name = "query" or
  name = "search" or
  name = "id" or
  name = "user" or
  name = "input" or
  name = "text" or
  name = "html" or
  name = "content" or
  name = "data"
}

/**
 * 自定义DOM XSS配置，加强对常见模式的检测
 */
class CustomDomXssConfiguration extends TaintTracking::Configuration {
  CustomDomXssConfiguration() { this = "CustomDomXssConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    // 标准源
    source instanceof DomBasedXss::Source
    or
    // URL参数源
    exists(DataFlow::PropRead read |
      read = source and
      read.getPropertyName() = "value" and
      exists(DataFlow::PropRead parent |
        parent.getPropertyName() = "location" and
        parent.getBase().asExpr().(GlobalVarAccess).getName() = "window"
      )
    )
    or
    // 检测URL搜索参数的访问
    exists(DataFlow::MethodCallNode call |
      call = source and
      call.getMethodName() = "get" and
      call.getReceiver().(DataFlow::NewNode).getCalleeName() = "URLSearchParams" and
      exists(string paramName |
        paramName = call.getArgument(0).getStringValue() and
        isDangerousUrlParamName(paramName)
      )
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // 标准sink
    sink instanceof DomBasedXss::Sink
    or
    // innerHTML或outerHTML属性赋值
    exists(DataFlow::PropWrite write |
      write.getPropertyName() = ["innerHTML", "outerHTML"] and
      write.getRhs() = sink
    )
    or
    // document.write或document.writeln
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = ["write", "writeln"] and
      call.getReceiver().asExpr().(GlobalVarAccess).getName() = "document" and
      call.getArgument(0) = sink
    )
    or
    // jQuery html或append方法
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = ["html", "append", "prepend", "after", "before"] and
      call.getArgument(0) = sink and
      call.getReceiver().getALocalSource() instanceof JQuery::JQueryObject
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // 继承标准污点步骤
    any(DomBasedXss::Configuration c).isAdditionalTaintStep(pred, succ)
    or
    // 字符串模板污点传播
    exists(StringOps::ConcatenationRoot root |
      root.getALeaf() = pred and
      root = succ
    )
    or
    // 正则表达式操作的污点传播
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = ["replace", "replaceAll"] and
      call.getReceiver() = pred and
      call = succ
    )
  }
}

from CustomDomXssConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "可能的DOM XSS漏洞，未经处理的用户输入被用于动态HTML内容。" 