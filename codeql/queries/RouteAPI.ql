/**
 * RouteAPI.ql — 检测微信小程序路由 API 调用
 *
 * 目标：
 *   - 检测 wx.navigateTo()、wx.redirectTo()、wx.reLaunch()、wx.switchTab()、wx.navigateBack()
 *   - 提取调用位置（文件、行号）
 *   - 提取所在函数名
 *   - 提取 url 参数表达式
 *
 * 输出列：
 *   - type: 路由 API 类型（如 "wx.navigateTo"）
 *   - file: 文件路径
 *   - line: 行号
 *   - function: 所在函数名（如果在函数内）
 *   - url_expression: url 参数的源码表达式
 */

import javascript

/**
 * 判断调用表达式是否为微信路由 API
 */
predicate isWxRouteAPI(CallExpr call, string apiName) {
  exists(PropAccess prop |
    // 模式：wx.navigateTo() 或 wx["navigateTo"]()
    call.getCallee() = prop and
    prop.getBase().(VarAccess).getName() = "wx" and
    (
      prop.getPropertyName() = "navigateTo" and apiName = "wx.navigateTo"
      or
      prop.getPropertyName() = "redirectTo" and apiName = "wx.redirectTo"
      or
      prop.getPropertyName() = "reLaunch" and apiName = "wx.reLaunch"
      or
      prop.getPropertyName() = "switchTab" and apiName = "wx.switchTab"
      or
      prop.getPropertyName() = "navigateBack" and apiName = "wx.navigateBack"
    )
  )
}

/**
 * 获取函数名（如果调用在函数内）
 */
string getFunctionName(CallExpr call) {
  exists(Function func |
    call.getContainer() = func and
    (
      // 命名函数：function foo() {}
      result = func.getName()
      or
      // 匿名函数但没有名字
      not exists(func.getName()) and
      (
        // 对象方法：{ handleClick: function() {} }
        exists(Property prop |
          func = prop.getInit() and
          result = prop.getName()
        )
        or
        // 赋值给变量：var handler = function() {}
        exists(VariableDeclarator vd |
          func = vd.getInit() and
          result = vd.getBindingPattern().(VarDecl).getName()
        )
        or
        // 如果以上都不是，返回匿名标记
        not exists(Property prop | func = prop.getInit()) and
        not exists(VariableDeclarator vd | func = vd.getInit()) and
        result = "<anonymous>"
      )
    )
  )
  or
  // 如果不在任何函数内，返回 "<top-level>"
  not exists(Function func | call.getContainer() = func) and
  result = "<top-level>"
}

/**
 * 提取 url 参数表达式
 */
string getUrlExpression(CallExpr call) {
  exists(Expr arg |
    // 第一个参数应该是对象字面量或变量
    arg = call.getArgument(0) and
    (
      // 情况 1: wx.navigateTo({ url: "..." }) - 字符串字面量
      exists(ObjectExpr obj, Property prop, StringLiteral str |
        arg = obj and
        prop = obj.getAProperty() and
        prop.getName() = "url" and
        str = prop.getInit() and
        result = str.getValue()
      )
      or
      // 情况 2: wx.navigateTo({ url: "..." + var }) - 字符串拼接
      exists(ObjectExpr obj, Property prop, AddExpr addExpr, StringLiteral str |
        arg = obj and
        prop = obj.getAProperty() and
        prop.getName() = "url" and
        addExpr = prop.getInit() and
        str = addExpr.getLeftOperand() and
        result = str.getValue() + " + ..."
      )
      or
      // 情况 3: wx.navigateTo({ url: expr }) - 其他表达式（模板字符串、变量等）
      exists(ObjectExpr obj, Property prop, Expr expr |
        arg = obj and
        prop = obj.getAProperty() and
        prop.getName() = "url" and
        expr = prop.getInit() and
        not expr instanceof StringLiteral and
        not expr instanceof AddExpr and
        result = expr.toString()
      )
      or
      // 情况 4: wx.navigateTo(options) - 变量引用，返回变量名
      exists(VarAccess va |
        arg = va and
        result = va.getName()
      )
    )
  )
  or
  // 无参数或无法解析
  not exists(call.getArgument(0)) and
  result = "<no-url>"
}

/**
 * 主查询
 */
from CallExpr call, string apiName, string fileName, int lineNumber, string funcName, string urlExpr
where
  isWxRouteAPI(call, apiName) and
  fileName = call.getFile().getRelativePath() and
  lineNumber = call.getLocation().getStartLine() and
  funcName = getFunctionName(call) and
  urlExpr = getUrlExpression(call)
select apiName, fileName, lineNumber, funcName, urlExpr
