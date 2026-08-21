/**
 * @name MiniCAT Taint Tracking Query (Paper Implementation)
 * @description 严格按照论文源码实现的污点追踪查询 (Section 4.2)
 *              从属性访问（source）到路由 API（sink）的数据流追踪
 * @kind problem
 * @problem.severity warning
 * @id minicat-taint
 */

import javascript
import DataFlow

/**
 * 获取位置字符串: file|startLine:startCol:endLine:endCol
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
 * Step I: 路由 API 方法
 * 论文: "We focus on three routing APIs: wx.navigateTo, wx.reLaunch, and wx.redirectTo"
 */
string selectRoute() {
  result = "%.redirectTo"
  or result = "%.reLaunch"
  or result = "%.navigateTo"
}

/**
 * 获取微信路由 API 调用
 */
private DataFlow::InvokeNode wx_navi() {
  result.getCalleeNode().toString().matches(selectRoute())
}

/**
 * MiniCAT 污点追踪配置（论文原始实现）
 *
 * 论文源码 wechat_query_reborn.ql:
 * override predicate isSource(DataFlow::Node source) {
 *   exists(ObjectExpr pa| pa.flow().getALocalSource().(DataFlow::Node)=source )
 *   or
 *   exists(DotExpr pe| pe.flow().getALocalSource().(DataFlow::Node)=source)
 * }
 * override predicate isSink(DataFlow::Node sink) {
 *   wx_navi().getOptionArgument(0, "url").(DataFlow::Node) = sink
 * }
 *
 * 数据流方向: Source (属性访问) → Sink (路由 API)
 */
class MiniCAT extends TaintTracking::Configuration {
  MiniCAT() { this = "minicat" }

  /**
   * Source: 所有属性访问（ObjectExpr 和 DotExpr）
   * 这是论文源码的原始实现
   */
  override predicate isSource(DataFlow::Node source) {
    exists(ObjectExpr pa | pa.flow().getALocalSource().(DataFlow::Node) = source)
    or
    exists(DotExpr pe | pe.flow().getALocalSource().(DataFlow::Node) = source)
  }

  /**
   * Sink: 路由 API 的 URL 参数
   */
  override predicate isSink(DataFlow::Node sink) {
    wx_navi().getOptionArgument(0, "url").(DataFlow::Node) = sink
  }
}

/**
 * Extract function name from source node
 * Used to identify event-handling functions (Challenge I from paper)
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
 * Check if function is an event-handling function (EV function)
 * Paper (Algorithm 1): EV function's PR node aligns with module node at AST top level
 */
predicate isEventHandlingFunction(Function f) {
  // Event-handling functions like onLoad, onClick, onShow, etc.
  exists(string name | name = f.getName() |
    name.matches("on%") or  // onLoad, onShow, onHide, etc.
    name.matches("%Handler") or  // clickHandler, submitHandler, etc.
    name.matches("handle%")  // handleClick, handleSubmit, etc.
  )
}

/**
 * Main query predicate: Reverse taint from routing API to property access
 */
query predicate get_func(
  string sink_loc,
  string source_loc,
  string source_func,
  string func_type
) {
  exists(
    MiniCAT pt, DataFlow::Node sink, DataFlow::Node source |
    pt.hasFlow(source, sink)
    and source_loc = get_spec_loc(source.asExpr().getLocation())
    and sink_loc = get_spec_loc(sink.asExpr().getLocation())
    and source_func = source.getContainer().(Function).getName()
    and (
      if isEventHandlingFunction(source.getContainer().(Function))
      then func_type = "EVENT_HANDLER"
      else func_type = "OTHER"
    )
  )
}

/**
 * Alternative query using custom function name extraction
 */
query predicate pure_get_func(
  string sink_loc,
  string source_loc,
  string source_func,
  string func_type
) {
  exists(
    MiniCAT pt, DataFlow::Node sink, DataFlow::Node source |
    pt.hasFlow(source, sink) |
    source_loc = get_spec_loc(source.asExpr().getLocation())
    and sink_loc = get_spec_loc(sink.asExpr().getLocation())
    and source_func = func_name(source)
    and (
      if isEventHandlingFunction(source.getContainer().(Function))
      then func_type = "EVENT_HANDLER"
      else func_type = "OTHER"
    )
  )
}
