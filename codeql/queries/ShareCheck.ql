/**
 * ShareCheck.ql
 *
 * 检测页面是否支持分享（是否定义了 onShareAppMessage 函数）
 *
 * 检测策略：
 * 1. 查找页面定义（Page({...})）
 * 2. 检查 Page 配置对象中是否存在 onShareAppMessage 方法
 * 3. 如果存在，提取方法定义和返回的分享配置
 *
 * 分享功能说明：
 * - 如果页面定义了 onShareAppMessage，用户可以通过右上角菜单分享该页面
 * - 分享的页面可以携带参数，形成带参数的分享链接
 * - 攻击者可以构造恶意参数并通过分享传播
 *
 * 输出：
 * - 页面路径
 * - 是否支持分享（shareable）
 * - onShareAppMessage 方法位置
 * - 分享配置（如果有）
 */

import javascript

// 识别页面定义（Page({...})）
class PageDefinition extends CallExpr {
  PageDefinition() {
    this.getCallee().(GlobalVarAccess).getName() = "Page"
  }

  // 获取页面配置对象
  ObjectExpr getConfig() {
    result = this.getArgument(0)
  }

  // 获取页面文件路径
  string getPagePath() {
    result = this.getFile().getRelativePath()
  }
}

// 识别 onShareAppMessage 方法
class ShareFunction extends Function {
  PageDefinition page;

  ShareFunction() {
    exists(Property prop |
      prop = page.getConfig().getAProperty() and
      prop.getInit() = this and
      prop.getName() = "onShareAppMessage"
    )
  }

  PageDefinition getPage() { result = page }

  // 获取分享配置的返回对象
  ObjectExpr getShareConfig() {
    exists(ReturnStmt ret |
      ret.getContainer() = this and
      result = ret.getExpr()
    )
  }
}

// 提取分享配置中的 title 属性
string getShareTitle(ShareFunction func) {
  exists(ObjectExpr config, Property titleProp |
    config = func.getShareConfig() and
    titleProp = config.getAProperty() and
    titleProp.getName() = "title" and
    result = titleProp.getInit().(StringLiteral).getValue()
  )
  or
  not exists(func.getShareConfig()) and result = "<no-config>"
}

// 提取分享配置中的 path 属性
string getSharePath(ShareFunction func) {
  exists(ObjectExpr config, Property pathProp |
    config = func.getShareConfig() and
    pathProp = config.getAProperty() and
    pathProp.getName() = "path" and
    result = pathProp.getInit().(StringLiteral).getValue()
  )
  or
  not exists(ObjectExpr config, Property pathProp |
    config = func.getShareConfig() and
    pathProp = config.getAProperty() and
    pathProp.getName() = "path"
  ) and result = "<default-path>"
}

// 主查询：检测所有页面的分享功能
from PageDefinition page, string shareable, string shareTitle, string sharePath, int line
where
  // 情况 1: 页面定义了 onShareAppMessage
  (
    exists(ShareFunction shareFunc |
      shareFunc.getPage() = page and
      shareable = "true" and
      shareTitle = getShareTitle(shareFunc) and
      sharePath = getSharePath(shareFunc) and
      line = shareFunc.getLocation().getStartLine()
    )
  )
  or
  // 情况 2: 页面未定义 onShareAppMessage（不可分享或使用默认分享）
  (
    not exists(ShareFunction shareFunc | shareFunc.getPage() = page) and
    shareable = "false" and
    shareTitle = "<none>" and
    sharePath = "<none>" and
    line = 0
  )
select page.getPagePath() as pagePath, shareable, shareTitle, sharePath,
       page.getFile().getRelativePath() as filePath, line
