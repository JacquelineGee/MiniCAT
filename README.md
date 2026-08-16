# MiniCAT Detector

微信小程序跨页面请求伪造（CPRF）静态检测工具。

## 简介

MiniCAT Detector 是基于论文 *MiniCAT: Cross-Page Request Forgery Detection in WeChat Mini-Programs* 的完整实现，用于自动检测微信小程序中的 CPRF（Cross-Page Request Forgery）漏洞。

CPRF 是一种针对微信小程序的攻击手法：攻击者构造恶意参数并通过分享链接传播，受害者点击后会在未验证身份的情况下执行敏感操作（如下单、转账、修改信息等）。

## 主要特性

- ✅ **完整的 10 步检测流程**：从源码解析到漏洞报告生成
- ✅ **CodeQL 静态分析**：基于抽象语法树和数据流分析
- ✅ **WXML 转换**：支持将 WXML 转换为 HTML 以便分析
- ✅ **事件链恢复**：反向污点分析恢复完整调用链
- ✅ **风险等级评估**：high（CPRF）/ medium / low / info
- ✅ **详细报告生成**：Markdown 格式，包含漏洞详情和修复建议

## 系统要求

- **Python** >= 3.10
- **Node.js** >= 14.0
- **CodeQL CLI** >= 2.15（需在 PATH 中可访问 `codeql` 命令）

## 安装步骤

### 1. 安装 Python 依赖

```bash
pip install -r requirements.txt
```

### 2. 安装 Node.js 依赖（用于 WXML 转换）

```bash
cd transformer
npm install
cd ..
```

### 3. 安装 CodeQL CLI

下载并安装 CodeQL CLI：https://github.com/github/codeql-cli-binaries/releases

确保 `codeql` 命令在 PATH 中可用：

```bash
codeql --version
```

## 使用方法

### 基本用法

```bash
python main.py --source <小程序源码目录> --output <输出目录>
```

### 完整参数

```bash
python main.py \
  --source ../unpacked_test/wx1ebbcac475348f0b \
  --output output_test \
  --config config/config.yaml
```

**参数说明：**

- `--source`：小程序源码根目录（必须包含 app.json）
- `--output`：输出目录（默认 `output/`）
- `--config`：配置文件路径（默认 `config/config.yaml`）

### 示例

```bash
# 检测示例小程序
python main.py --source ../unpacked_test/wx1ebbcac475348f0b --output output_test

# 使用自定义配置
python main.py --source /path/to/miniapp --output results --config my_config.yaml
```

## 输出结果

检测完成后，输出目录将包含以下文件：

### 核心报告

- **`detection_report.md`** - 主检测报告（Markdown 格式）
  - 📊 执行摘要
  - 📈 检测结果统计
  - 🔴 高风险 CPRF 漏洞列表
  - 🟡 中风险漏洞列表
  - 🔍 攻击路径详细示例
  - 💡 修复建议
  - 📝 附录

### 详细数据（JSON 格式）

- `page_index.json` - 页面索引（JS/WXML/HTML 路径）
- `routes.json` - 所有路由 API 调用
- `event_chains.json` - 事件处理函数调用链
- `trigger_chains.json` - 用户触发链（WXML → Event → Route）
- `user_state_checks.json` - 用户状态检查详情
- `share_info.json` - 页面分享功能信息
- `attack_paths.json` - 所有攻击路径
- `vulnerable_attack_paths.json` - 所有漏洞攻击路径
- `cprf_attack_paths.json` - 高风险 CPRF 攻击路径

### 其他文件

- `codeql-db/` - CodeQL 数据库
- `detector.log` - 检测日志

## 报告示例

主报告 `detection_report.md` 包含以下内容：

### 执行摘要

```markdown
本次检测共扫描 **180** 个页面，识别出 **86** 个高风险 CPRF 漏洞和 **492** 个中风险漏洞。

### 关键发现

- 🔴 **高风险 CPRF 漏洞**: 86 个
- 🟡 **中风险漏洞**: 492 个
- 📍 **路由 API 调用**: 206 个
- 🔗 **用户触发链**: 1038 个
```

### 高风险 CPRF 漏洞

```markdown
### 1. pages/upage/upage

- **目标页面**: `pages/upage/upage`
- **路由 API**: `wx.switchTab`
- **触发位置**: `pages/goods/goods.html` 中的 `<search>`
- **风险等级**: 🔴 HIGH (CPRF)

**漏洞描述**: 目标页面缺少用户身份验证且支持分享功能，攻击者可以构造恶意参数并通过分享传播。
```

### 攻击路径详细示例

```markdown
#### 攻击流程

1. 用户在 pages/goods/goods.html 页面中
2. 点击/触发 <search> 元素的 addNum 事件
3. 触发事件处理函数 close_search()
4. 调用链: close_search → onShow → <anonymous>
5. 执行路由 API: wx.switchTab()
6. 跳转到目标页面: pages/upage/upage
7. ⚠️ 目标页面未进行用户身份验证
8. ⚠️ 目标页面支持分享（可通过分享传播）
```

### 修复建议

报告包含详细的修复建议和代码示例。

## 检测流程

MiniCAT Detector 实现了完整的 10 步检测流程：

| 步骤 | 模块 | 功能 | 状态 |
|------|------|------|------|
| Step 1 | app.json 解析 + 页面索引 | 提取所有页面路径，建立 JS/WXML 索引 | ✅ 完成 |
| Step 2 | WXML 转换 | 将 WXML 转换为 HTML（调用 Node.js transformer） | ✅ 完成 |
| Step 3 | CodeQL 数据库创建 | 为小程序源码创建 JavaScript 数据库 | ✅ 完成 |
| Step 4 | RouteAPI 查询 | 检测所有路由 API 调用（wx.navigateTo 等） | ✅ 完成 |
| Step 5 | Event Recovery | 反向污点分析恢复事件调用链 | ✅ 完成 |
| Step 6 | WXML Trigger 查询 | 分析 WXML 中的用户触发器并关联事件链 | ✅ 完成 |
| Step 7 | User State Check | 检测目标页面的用户状态验证 | ✅ 完成 |
| Step 8 | Share Check | 检测目标页面的分享功能 | ✅ 完成 |
| Step 9 | 攻击路径构建 | 构建完整攻击路径并评估风险等级 | ✅ 完成 |
| Step 10 | 报告生成 | 生成 Markdown 格式的检测报告 | ✅ 完成 |

## 风险等级

MiniCAT Detector 将检测到的攻击路径分为 4 个风险等级：

| 风险等级 | 条件 | 说明 |
|----------|------|------|
| 🔴 **HIGH** | 缺少用户验证 + 支持分享 | 典型的 CPRF 漏洞，可通过分享链接传播 |
| 🟡 **MEDIUM** | 缺少用户验证 + 不支持分享 | 虽然无法通过分享传播，但仍可能通过其他方式诱导用户访问 |
| 🟢 **LOW** | 有用户验证 + 支持分享 | 虽然支持分享，但由于有用户验证，攻击者无法在未授权情况下执行敏感操作 |
| ℹ️ **INFO** | 有用户验证 + 不支持分享 | 安全的配置 |

## 目录结构

```
MiniCAT/
├── main.py                          # 主入口
├── requirements.txt                 # Python 依赖
├── README.md                        # 本文档
├── config/
│   └── config.yaml                  # 全局配置
├── preprocessing/                   # 预处理模块
│   ├── app_parser.py                # 解析 app.json
│   ├── page_index.py                # 建立页面索引
│   └── wxml_converter.py            # WXML → HTML 转换
├── codeql/                          # CodeQL 模块
│   ├── database.py                  # 数据库管理
│   ├── run_query.py                 # 查询执行
│   └── queries/                     # CodeQL 查询
│       ├── RouteAPI.ql              # 路由 API 检测
│       ├── CallGraph.ql             # 调用图
│       ├── WXMLTrigger.ql           # WXML 触发器
│       ├── UserState.ql             # 用户状态检查
│       └── ShareCheck.ql            # 分享功能检查
├── analyzer/                        # 分析器模块
│   ├── route_analyzer.py            # 路由分析
│   ├── event_recovery.py            # 事件链恢复
│   ├── trigger_linker.py            # 触发链关联
│   ├── state_checker.py             # 状态检查分析
│   ├── share_checker.py             # 分享功能分析
│   ├── attack_path_builder.py       # 攻击路径构建
│   └── report_generator.py          # 报告生成
├── transformer/                     # WXML 转换器
│   ├── convert.js                   # Node.js 转换脚本
│   └── package.json                 # npm 依赖
└── output/                          # 输出目录（可配置）
    ├── detection_report.md          # 主报告
    ├── *.json                       # 详细数据
    ├── codeql-db/                   # CodeQL 数据库
    └── detector.log                 # 日志
```

## 技术架构

### CodeQL 查询

MiniCAT 使用 5 个 CodeQL 查询来分析小程序源码：

1. **RouteAPI.ql** - 检测所有路由 API 调用（wx.navigateTo, wx.redirectTo, wx.switchTab, wx.reLaunch, wx.navigateBack）
2. **CallGraph.ql** - 构建函数调用图，用于事件链恢复
3. **WXMLTrigger.ql** - 分析 HTML（转换后的 WXML）中的事件绑定
4. **UserState.ql** - 检测用户状态检查（wx.getStorageSync, wx.getStorage, app.globalData）
5. **ShareCheck.ql** - 检测分享功能（onShareAppMessage, onShareTimeline）

### 事件链恢复

使用反向污点分析（Reverse Taint Analysis）从路由 API 调用回溯到：
- 包含该调用的事件处理函数
- 完整的函数调用链
- WXML 中触发该事件的用户交互元素

### 攻击路径构建

整合所有分析结果，构建完整的攻击路径：

```
User → WXML Trigger → Event Handler → Route API → Target Page
                                                        ↓
                                           User State Check? (Step 7)
                                           Shareable? (Step 8)
                                                        ↓
                                              Risk Assessment (Step 9)
```

## 常见问题

### Q: 为什么终端输出显示乱码？

**A:** Windows 终端使用 GBK (cp936) 编码，无法显示表情符号等 Unicode 字符。但这不影响检测结果，所有输出文件（JSON、Markdown、日志）都使用 UTF-8 编码，可以在文本编辑器中正常查看。

### Q: CodeQL 数据库创建失败？

**A:** 确保：
1. CodeQL CLI 已正确安装并在 PATH 中
2. 小程序源码目录包含 app.json
3. 有足够的磁盘空间（数据库通常需要几百 MB）

### Q: WXML 转换失败？

**A:** 确保：
1. Node.js 版本 >= 14.0
2. 已在 transformer 目录运行 `npm install`
3. transformer/convert.js 有执行权限

### Q: 检测报告为空或漏洞数量为 0？

**A:** 可能原因：
1. 小程序已正确实现用户身份验证
2. 页面不支持分享功能
3. 代码混淆导致 CodeQL 分析失败
4. 配置文件中的模式匹配需要调整

### Q: 如何减少误报？

**A:** 可以调整 `config/config.yaml` 中的配置：
- 修改用户状态检查的模式匹配规则
- 排除特定的页面或路由类型
- 调整风险评估规则

## 参考文献

- MiniCAT Paper: *Cross-Page Request Forgery Detection in WeChat Mini-Programs*
- CodeQL Documentation: https://codeql.github.com/docs/
- WeChat Mini-Program Documentation: https://developers.weixin.qq.com/miniprogram/dev/

## 许可证

本项目基于学术研究目的开发，仅供学习和研究使用。

## 联系方式

如有问题或建议，请提交 Issue 或联系项目维护者。

---

**MiniCAT Detector v1.0**
