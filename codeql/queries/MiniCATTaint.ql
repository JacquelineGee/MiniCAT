/**
 * @name MiniCAT Taint Tracking Query
 * @description Finds data flows from property access to WeChat route API URL parameters
 * @kind problem
 * @problem.severity warning
 * @id minicat-taint
 */

import javascript
import DataFlow

/**
 * Get location string in format: file|startLine:startCol:endLine:endCol
 */
string get_spec_loc(Location loc) {
  result =
  loc.getFile() + "|" +
  loc.getStartLine() +
  ":" + loc.getStartColumn() +
  ":" + loc.getEndLine() +
  ":" + loc.getEndColumn()
}

/**
 * Route API methods to track
 */
string selectRoute() {
  result = "%.redirectTo"
  or result = "%.reLaunch"
  or result = "%.navigateTo"
  or result = "%.switchTab"
  or result = "%.navigateBack"
}

/**
 * Get WeChat route API invocations
 */
private DataFlow::InvokeNode wx_navi() {
  result.getCalleeNode().toString().matches(selectRoute())
}

/**
 * MiniCAT taint tracking configuration
 * Source: All property accesses (ObjectExpr, DotExpr)
 * Sink: URL parameter of WeChat route APIs
 */
class MiniCAT extends TaintTracking::Configuration {
  MiniCAT() { this = "minicat" }

  override predicate isSource(DataFlow::Node source) {
    exists(ObjectExpr pa | pa.flow().getALocalSource().(DataFlow::Node) = source)
    or
    exists(DotExpr pe | pe.flow().getALocalSource().(DataFlow::Node) = source)
  }

  override predicate isSink(DataFlow::Node sink) {
    wx_navi().getOptionArgument(0, "url").(DataFlow::Node) = sink
  }
}

/**
 * Extract function name from source node (better extraction logic)
 */
string func_name(DataFlow::Node source) {
  if not source.getContainer().getScope().getOuterScope() instanceof FunctionScope
    and source.getContainer().inExternsFile()
  then result = source.getContainer().(Expr).getAPredecessor().toString()
  else
    result =
      source.getContainer().(Expr).getAPredecessor()
      .getContainer().(Expr).getAPredecessor()
      .toString()
}

/**
 * Main query predicate: get function name using Container.getName()
 */
query predicate get_func(
  string sink_loc,
  string source_loc,
  BasicBlock block_name,
  string source_func
) {
  exists(
    MiniCAT pt, DataFlow::Node sink, DataFlow::Node source |
    pt.hasFlow(source, sink)
    and source_loc = get_spec_loc(source.asExpr().getLocation())
    and sink_loc = get_spec_loc(sink.asExpr().getLocation())
    and source_func = source.getContainer().(Function).getName()
    and block_name = source.getBasicBlock()
  )
}

/**
 * Pure query predicate: get function name using custom extraction logic
 * This provides more accurate function names for obfuscated code
 */
query predicate pure_get_func(
  string sink_loc,
  string source_loc,
  BasicBlock block_name,
  string source_func
) {
  exists(
    MiniCAT pt, DataFlow::Node sink, DataFlow::Node source |
    pt.hasFlow(source, sink) |
    source_loc = get_spec_loc(source.asExpr().getLocation())
    and sink_loc = get_spec_loc(sink.asExpr().getLocation())
    and source_func = func_name(source)
    and block_name = source.getBasicBlock()
  )
}
