# MiniCAT Detector

微信小程序跨页面请求伪造（CPRF）静态检测工具。

## 简介

MiniCAT Detector 是基于论文 *MiniCAT: Cross-Page Request Forgery Detection in WeChat Mini-Programs* 的实现，使用 **CodeQL 污点追踪** 自动检测微信小程序中的 CPRF（Cross-Page Request Forgery）漏洞。

CPRF 是一种针对微信小程序的攻击手法：攻击者构造恶意参数并通过分享链接传播，受害者点击后会在未验证身份的情况下执行敏感操作（如下单、转账、修改信息等）。

## 主要特性

- ✅ **污点追踪检测**：使用 CodeQL 追踪数据流从任意属性访问到路由 API
- ✅ **适合混淆代码**：不依赖函数名或事件绑定，适用于混淆后的小程序
- ✅ **可利用性验证**：检查页面是否有 `onShareAppMessage` 方法
- ✅ **自动解包**：支持自动解包 .wxapkg 文件
- ✅ **详细报告生成**：Markdown 格式，包含数据流和漏洞详情

## 系统要求

- **Python** >= 3.10
- **Node.js** >= 14.0
- **CodeQL CLI** >= 2.15（需在 PATH 中可访问 `codeql` 命令）
- **wedecode** - 微信小程序解包工具（需在 PATH 中可访问 `wedecode` 命令）

## 安装步骤

### 1. 安装 Python 依赖

```bash
pip install -r requirements.txt
```

### 2. 安装 wedecode（用于解包 .wxapkg 文件）

```bash
npm install -g wedecode
```

验证安装：

```bash
wedecode --version
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
python main.py --source <小程序源码目录或.wxapkg文件目录> --output <输出目录>
```

**参数说明：**

- `--source`：小程序源码根目录（必须包含 app.json）或包含 .wxapkg 文件的目录
- `--output`：输出目录（默认 `output/`）

### 示例

```bash
# 检测已解包的小程序
python main.py --source unpacked/wx063d504170b0eb1c --output output

# 自动解包并检测（.wxapkg 文件在目录中）
python main.py --source packages/wx063d504170b0eb1c --output output
```

## 输出结果

检测完成后，输出目录将包含以下文件：

### 核心报告

- **`detection_report.md`** - 主检测报告（Markdown 格式）
  - 📊 小程序信息
  - 📈 检测结果统计（数据流总数、可利用漏洞数）
  - 🔴 漏洞列表（文件、函数、Source、Sink）
  - 📊 函数分布和文件分布

### 详细数据（JSON 格式）

- `{app_id}_all_flows.json` - 所有检测到的数据流
- `{app_id}_vulnerabilities.json` - 可利用的漏洞（有 onShareAppMessage）
- `{app_id}_aux.csv` - CodeQL 查询结果（pure_get_func）
- `{app_id}_main.csv` - CodeQL 查询结果（get_func）
- `{app_id}_taint.bqrs` - CodeQL 原始查询结果

### 其他文件

- `{app_id}_db/` - CodeQL 数据库
- `detector.log` - 检测日志

## 报告示例

主报告 `detection_report.md` 包含以下内容：

### 检测结果

```markdown
## 检测结果

- **数据流总数**: 9
- **可利用漏洞**: 2

### 漏洞列表

#### 漏洞 #1

- **文件**: `c.js`
- **函数**: `GYYO`
- **Source**: `c.js|5335:19:5335:19`
- **Sink**: `c.js|5337:18:5337:18`
- **可分享**: ✓

#### 漏洞 #2

- **文件**: `c.js`
- **函数**: `k`
- **Source**: `c.js|8665:26:8665:31`
- **Sink**: `c.js|8665:20:8665:20`
- **可分享**: ✓
```

### 统计信息

```markdown
## 统计信息

### 函数分布

- `GYYO`: 1
- `k`: 1
- `JIO9`: 2
- `S`: 1

### 文件分布

- `c.js`: 4
- `components/showcase/components/navigation-bar/index.js`: 3
```

## 检测原理

MiniCAT 使用 **CodeQL 污点追踪** 检测 CPRF 漏洞，核心步骤：

1. **重命名 WXML → HTML**：将 `.wxml` 文件重命名为 `.html`，帮助 CodeQL 发现关联的 JavaScript 文件
2. **创建 CodeQL 数据库**：为小程序源码创建 JavaScript 分析数据库
3. **污点追踪查询**：追踪数据流从任意属性访问（Source）到路由 API 的 URL 参数（Sink）
4. **可利用性验证**：检查包含数据流的文件是否有 `onShareAppMessage` 方法

### 污点追踪配置

```ql
class MiniCAT extends TaintTracking::Configuration {
  override predicate isSource(DataFlow::Node source) {
    // Source: 任意对象属性访问或点表达式
    exists(ObjectExpr pa | pa.flow().getALocalSource().(DataFlow::Node) = source)
    or
    exists(DotExpr pe | pe.flow().getALocalSource().(DataFlow::Node) = source)
  }

  override predicate isSink(DataFlow::Node sink) {
    // Sink: 路由 API 的 url 参数
    wx_navi().getOptionArgument(0, "url").(DataFlow::Node) = sink
  }
}
```

这种方法的优势：
- **不依赖函数名**：即使函数名被混淆（如 `GYYO`, `k`, `JIO9`），仍能检测数据流
- **不依赖事件绑定**：不需要从 HTML 触发器追踪到处理函数
- **适合混淆代码**：纯 JavaScript 数据流分析，不受混淆影响

## 目录结构

```
MiniCAT/
├── main.py                          # 主入口（集成污点追踪检测）
├── requirements.txt                 # Python 依赖
├── README.md                        # 本文档
├── config/
│   └── config.yaml                  # 全局配置
├── unpacker/                        # 解包模块
│   ├── __init__.py
│   └── wxapkg_unpacker.py           # wxapkg 解包器（调用 wedecode）
├── codeql/                          # CodeQL 模块
│   └── queries/                     # CodeQL 查询
│       ├── MiniCATTaint.ql          # 污点追踪查询（核心）
│       └── qlpack.yml               # CodeQL 包配置
└── output/                          # 输出目录（可配置）
    ├── detection_report.md          # 主报告
    ├── *_all_flows.json             # 所有数据流
    ├── *_vulnerabilities.json       # 可利用漏洞
    ├── *_db/                        # CodeQL 数据库
    └── detector.log                 # 日志
```

## 技术架构

### CodeQL 污点追踪

MiniCAT 使用一个核心 CodeQL 查询 `MiniCATTaint.ql` 来检测数据流：

**Source（污点源）**：
- 对象表达式（`ObjectExpr`）
- 点表达式（`DotExpr`）

**Sink（污点汇）**：
- 路由 API 的 `url` 参数：`wx.navigateTo()`, `wx.redirectTo()`, `wx.reLaunch()`, `wx.switchTab()`, `wx.navigateBack()`

**输出**：
- `pure_get_func`：包含函数名的数据流（更准确）
- `get_func`：不包含函数名的数据流（回退）

### 可利用性验证

检测到数据流后，MiniCAT 会验证该文件是否包含 `onShareAppMessage` 方法：
- ✓ 有分享功能：漏洞可通过分享链接传播（HIGH 风险）
- ✗ 无分享功能：仍是潜在漏洞，但传播途径有限

## 常见问题

### Q: 为什么终端输出显示乱码？

**A:** Windows 终端使用 GBK (cp936) 编码，无法显示表情符号等 Unicode 字符。但这不影响检测结果，所有输出文件（JSON、Markdown、日志）都使用 UTF-8 编码，可以在文本编辑器中正常查看。

### Q: CodeQL 数据库创建失败？

**A:** 确保：
1. CodeQL CLI 已正确安装并在 PATH 中
2. 小程序源码目录包含 app.json
3. 有足够的磁盘空间（数据库通常需要几百 MB）

### Q: 解包失败？

**A:** 确保：
1. wedecode 已正确安装：`npm install -g wedecode`
2. wedecode 版本 >= 0.10.0
3. .wxapkg 文件未损坏
4. 有足够的磁盘空间

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
