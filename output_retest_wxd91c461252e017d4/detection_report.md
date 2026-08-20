# MiniCAT 检测报告

## 小程序信息

- **AppID**: wxd91c461252e017d4
- **检测时间**: 2026-08-20 00:09:55

## 检测结果

- **数据流总数**: 14
- **MiniCPRF 漏洞数**: 14

## 漏洞页面列表

### 1. `link`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 1
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

### 2. `pages/home/enroll`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 3
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

### 3. `pages/home/enroll-apply`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 3
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

### 4. `pages/home/index`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 3
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

### 5. `pages/tabBar/record`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 4
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

