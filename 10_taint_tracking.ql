/**
* @kind path-problem
*/

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph
 
class NetworkByteSwap extends Expr {
    NetworkByteSwap () {
    exists(Macro m, MacroInvocation mi | 
        m.getName().regexpMatch("ntoh[a-z]*") and 
        mi.getMacro() = m and
        mi.getExpr() = this)
  } 
}
 
class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
  }
  override predicate isSink(DataFlow::Node sink) {
    exists(Function f, FunctionCall fc | 
        sink.asExpr() = fc.getArgument(2) and
        fc.getTarget() = f and
        f.getName() = "memcpy")
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"

