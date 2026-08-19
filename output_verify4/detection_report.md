# MiniCAT 检测报告

## 小程序信息

- **AppID**: wx38ccbecb303dcfa2
- **检测时间**: 2026-08-19 19:40:38

## 检测结果

- **数据流总数**: 14
- **MiniCPRF 漏洞数**: 14

## 漏洞页面列表

### 1. `pages/scan/scan`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 2
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

### 2. `pages/ucenter/kpiPlan`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 4
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

### 3. `pages/ucenter/taskList`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 4
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

### 4. `pages/ucenter/taskManage`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 2
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

### 5. `pages/ucenter/taskPlan`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 2
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

