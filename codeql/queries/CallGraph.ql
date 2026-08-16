/**
 * CallGraph.ql — 构建函数调用图
 *
 * 目标：
 *   - 提取所有函数定义
 *   - 提取所有函数调用关系
 *   - 为 Event Recovery 提供调用链数据
 *
 * 输出列：
 *   - caller_file: 调用者所在文件
 *   - caller_line: 调用者所在行号
 *   - caller_function: 调用者函数名
 *   - callee_function: 被调用函数名
 *   - callee_file: 被调用函数定义所在文件
 *   - callee_line: 被调用函数定义所在行号
 */

import javascript

/**
 * 获取函数名
 */
string getFunctionName(Function func) {
  // 命名函数
  result = func.getName()
  or
  // 匿名函数但有绑定
  not exists(func.getName()) and
  (
    // 对象方法
    exists(Property prop |
      func = prop.getInit() and
      result = prop.getName()
    )
    or
    // 赋值给变量
    exists(VariableDeclarator vd |
      func = vd.getInit() and
      result = vd.getBindingPattern().(VarDecl).getName()
    )
    or
    // 默认匿名
    not exists(Property prop | func = prop.getInit()) and
    not exists(VariableDeclarator vd | func = vd.getInit()) and
    result = "<anonymous>"
  )
}

/**
 * 获取调用表达式的目标函数名
 */
string getCallTarget(CallExpr call) {
  exists(Expr callee |
    callee = call.getCallee() and
    (
      // 直接函数调用：foo()
      result = callee.(VarAccess).getName()
      or
      // 属性访问调用：obj.method()
      result = callee.(PropAccess).getPropertyName()
      or
      // 动态调用，返回表达式字符串
      not callee instanceof VarAccess and
      not callee instanceof PropAccess and
      result = callee.toString()
    )
  )
}

/**
 * 主查询：提取函数调用关系
 */
from CallExpr call, Function callerFunc, string callerName, string calleeName,
     string callerFile, int callerLine, string calleeFile, int calleeLine
where
  // 调用者函数
  callerFunc = call.getEnclosingFunction() and
  callerName = getFunctionName(callerFunc) and
  callerFile = call.getFile().getRelativePath() and
  callerLine = call.getLocation().getStartLine() and

  // 被调用函数名
  calleeName = getCallTarget(call) and

  // 尝试找到被调用函数的定义
  (
    // 能找到定义
    exists(Function calleeFunc |
      calleeName = getFunctionName(calleeFunc) and
      calleeFile = calleeFunc.getFile().getRelativePath() and
      calleeLine = calleeFunc.getLocation().getStartLine()
    )
    or
    // 找不到定义（外部函数或动态调用）
    not exists(Function calleeFunc | calleeName = getFunctionName(calleeFunc)) and
    calleeFile = "<unknown>" and
    calleeLine = 0
  )
select callerFile, callerLine, callerName, calleeName, calleeFile, calleeLine
