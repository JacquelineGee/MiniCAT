/**
 * WXMLTrigger.ql — WXML 用户触发分析
 *
 * 目标：
 *   - 在转换后的 HTML 文件中，查找 data-handler 属性
 *   - 匹配对应的 JavaScript 函数定义
 *
 * 输出列：
 *   - html_file:  HTML 文件路径
 *   - html_line:  HTML 中的行号
 *   - tag:        HTML 标签名
 *   - event:      事件类型（如 tap）
 *   - handler:    事件处理函数名
 *   - js_file:    对应 JS 函数定义所在文件
 *   - js_line:    对应 JS 函数定义行号
 */

import javascript

/**
 * 获取函数名
 */
string getFunctionName(Function func) {
  result = func.getName()
  or
  not exists(func.getName()) and
  (
    exists(Property prop |
      func = prop.getInit() and
      result = prop.getName()
    )
    or
    exists(VariableDeclarator vd |
      func = vd.getInit() and
      result = vd.getBindingPattern().(VarDecl).getName()
    )
    or
    not exists(Property prop | func = prop.getInit()) and
    not exists(VariableDeclarator vd | func = vd.getInit()) and
    result = "<anonymous>"
  )
}

/**
 * 主查询
 * 使用 HTML::Attribute 类查找 data-handler 属性
 */
from HTML::Attribute handlerAttr, HTML::Attribute eventAttr,
     string handlerName, string eventType,
     string htmlFile, int htmlLine, string tagName,
     Function jsFunc, string jsFile, int jsLine
where
  // 查找 data-handler 属性
  handlerAttr.getName() = "data-handler" and
  handlerName = handlerAttr.getValue() and

  // 找同一元素上的 data-event 属性
  eventAttr.getElement() = handlerAttr.getElement() and
  eventAttr.getName() = "data-event" and
  eventType = eventAttr.getValue() and

  // 位置信息
  htmlFile = handlerAttr.getFile().getRelativePath() and
  htmlLine = handlerAttr.getLocation().getStartLine() and
  tagName = handlerAttr.getElement().getName() and

  // 在 JS 文件中查找对应的函数定义
  jsFunc.getName() = handlerName and
  jsFile = jsFunc.getFile().getRelativePath() and
  jsLine = jsFunc.getLocation().getStartLine() and

  // HTML 与 JS 同属一个页面（路径前缀相同）
  exists(string base |
    base = htmlFile.regexpCapture("^(.*)\\.html$", 1) and
    jsFile.matches(base + "%")
  )

select htmlFile, htmlLine, tagName, eventType, handlerName, jsFile, jsLine
