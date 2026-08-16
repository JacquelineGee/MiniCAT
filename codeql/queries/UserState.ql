/**
 * UserState.ql
 *
 * 检测目标页面是否进行用户状态检查（如登录验证、权限检查）
 *
 * 检测策略：
 * 1. 查找页面生命周期函数（onLoad, onShow）中是否调用了用户状态检查函数
 * 2. 识别常见的用户验证模式：
 *    - wx.getStorageSync('token') / wx.getStorageSync('userInfo')
 *    - 检查 app.globalData.userInfo / app.globalData.isLogin
 *    - 调用 checkLogin / getUserInfo 等函数
 *    - 条件判断后调用 wx.navigateTo('/pages/login/login')
 *
 * 输出：
 * - 页面路径
 * - 生命周期函数名
 * - 检查类型（storage, globalData, function）
 * - 检查表达式
 * - 文件位置
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

// 识别生命周期函数
class LifecycleFunction extends Function {
  string lifecycleName;

  LifecycleFunction() {
    exists(PageDefinition page, Property prop |
      prop = page.getConfig().getAProperty() and
      prop.getInit() = this and
      lifecycleName = prop.getName() and
      lifecycleName in ["onLoad", "onShow", "onReady"]
    )
  }

  string getLifecycleName() { result = lifecycleName }

  PageDefinition getPage() {
    exists(Property prop |
      prop = result.getConfig().getAProperty() and
      prop.getInit() = this
    )
  }
}

// 识别用户状态检查：wx.getStorageSync('token') / wx.getStorageSync('userInfo')
class StorageCheck extends MethodCallExpr {
  StorageCheck() {
    exists(string apiName |
      this.getReceiver().(GlobalVarAccess).getName() = "wx" and
      this.getMethodName() = apiName and
      apiName in ["getStorageSync", "getStorage"] and
      exists(StringLiteral arg |
        arg = this.getArgument(0) and
        arg.getValue().regexpMatch(".*(token|user|login|auth|session).*")
      )
    )
  }

  string getStorageKey() {
    result = this.getArgument(0).(StringLiteral).getValue()
  }
}

// 识别全局数据检查：app.globalData.userInfo / getApp().globalData.isLogin
class GlobalDataCheck extends PropAccess {
  GlobalDataCheck() {
    exists(PropAccess globalData |
      globalData.getBase().(CallExpr).getCallee().(GlobalVarAccess).getName() = "getApp" and
      globalData.getPropertyName() = "globalData" and
      this.getBase() = globalData and
      this.getPropertyName().regexpMatch(".*(user|login|auth|token).*")
    )
    or
    exists(PropAccess globalData |
      globalData.getBase().(GlobalVarAccess).getName() = "app" and
      globalData.getPropertyName() = "globalData" and
      this.getBase() = globalData and
      this.getPropertyName().regexpMatch(".*(user|login|auth|token).*")
    )
  }
}

// 识别登录检查函数调用：checkLogin() / getUserInfo() / verifyAuth()
class LoginFunctionCall extends CallExpr {
  LoginFunctionCall() {
    exists(string funcName |
      funcName = this.getCallee().(VarAccess).getName() and
      funcName.regexpMatch(".*(check|verify|get).*(login|user|auth|token).*")
    )
  }

  string getFunctionName() {
    result = this.getCallee().(VarAccess).getName()
  }
}

// 识别登录跳转：wx.navigateTo({ url: '/pages/login/login' })
class LoginRedirect extends MethodCallExpr {
  LoginRedirect() {
    this.getReceiver().(GlobalVarAccess).getName() = "wx" and
    this.getMethodName() in ["navigateTo", "redirectTo", "reLaunch"] and
    exists(ObjectExpr arg, Property urlProp |
      arg = this.getArgument(0) and
      urlProp = arg.getAProperty() and
      urlProp.getName() = "url" and
      urlProp.getInit().(StringLiteral).getValue().regexpMatch(".*/login.*")
    )
  }
}

// 主查询：检测页面是否有用户状态检查
from LifecycleFunction lifecycle, PageDefinition page, string checkType, Expr checkExprNode, int line
where
  page = lifecycle.getPage() and
  (
    // 检查类型 1: Storage 检查
    (
      checkExprNode = lifecycle.getBody().(BlockStmt).getAStmt+().(ExprStmt).getExpr() and
      checkExprNode instanceof StorageCheck and
      checkType = "storage:" + checkExprNode.(StorageCheck).getStorageKey()
    )
    or
    // 检查类型 2: GlobalData 检查
    (
      exists(Expr parent |
        parent = lifecycle.getBody().(BlockStmt).getAStmt+().(ExprStmt).getExpr() and
        checkExprNode = parent.getAChildExpr*() and
        checkExprNode instanceof GlobalDataCheck and
        checkType = "globalData:" + checkExprNode.(GlobalDataCheck).getPropertyName()
      )
    )
    or
    // 检查类型 3: 登录函数调用
    (
      checkExprNode = lifecycle.getBody().(BlockStmt).getAStmt+().(ExprStmt).getExpr() and
      checkExprNode instanceof LoginFunctionCall and
      checkType = "function:" + checkExprNode.(LoginFunctionCall).getFunctionName()
    )
    or
    // 检查类型 4: 登录跳转
    (
      exists(IfStmt ifStmt |
        ifStmt = lifecycle.getBody().(BlockStmt).getAStmt+() and
        checkExprNode = ifStmt.getThen().(BlockStmt).getAStmt().(ExprStmt).getExpr() and
        checkExprNode instanceof LoginRedirect and
        checkType = "redirect:login"
      )
    )
  ) and
  line = checkExprNode.getLocation().getStartLine()
select page.getPagePath() as pagePath, lifecycle.getLifecycleName() as lifecycleName, checkType,
       checkExprNode.toString() as checkExpr, checkExprNode.getFile().getRelativePath() as filePath, line
