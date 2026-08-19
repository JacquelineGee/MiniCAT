/**
 * @name MiniCAT Taint Tracking Query (Original Implementation)
 * @description Original MiniCAT query - tracks all property accesses
 * @kind path-problem
 * @problem.severity warning
 * @id minicat-taint-original
 */

import javascript
import DataFlow
import DataFlow::PathGraph

string selectRoute() {
  result = "%.redirectTo"
  or result = "%.reLaunch"
  or result = "%.navigateTo"
  or result = "%.switchTab"
  or result = "%.navigateBack"
}

private DataFlow::InvokeNode wx_navi() {
  result.getCalleeNode().toString().matches(selectRoute())
}

/**
 * Original MiniCAT configuration - tracks ALL property accesses
 */
class MiniCATOriginal extends TaintTracking::Configuration {
  MiniCATOriginal() { this = "minicat-original" }

  override predicate isSource(DataFlow::Node source) {
    exists(ObjectExpr pa | pa.flow().getALocalSource().(DataFlow::Node) = source)
    or
    exists(DotExpr pe | pe.flow().getALocalSource().(DataFlow::Node) = source)
  }

  override predicate isSink(DataFlow::Node sink) {
    wx_navi().getOptionArgument(0, "url").(DataFlow::Node) = sink
  }
}

from MiniCATOriginal cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential MiniCPRF: data flows from $@ to route API.", source.getNode(), "user input"

