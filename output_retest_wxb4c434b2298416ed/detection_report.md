# MiniCAT 检测报告

## 小程序信息

- **AppID**: wxb4c434b2298416ed
- **检测时间**: 2026-08-20 00:08:40

## 检测结果

- **数据流总数**: 45
- **MiniCPRF 漏洞数**: 45

## 漏洞页面列表

### 1. `pages/account/helpCenter`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 6
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

### 2. `pages/device/device`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 3
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

### 3. `pages/device/gatewayManagement`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 7
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

### 4. `pages/index/index`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 12
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

### 5. `pages/user/userList`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 17
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

