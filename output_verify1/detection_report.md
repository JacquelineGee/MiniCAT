# MiniCAT 检测报告

## 小程序信息

- **AppID**: wx0c81a5d77dd90191
- **检测时间**: 2026-08-19 15:08:25

## 检测结果

- **数据流总数**: 1
- **MiniCPRF 漏洞数**: 1

## 漏洞页面列表

### 1. `pages/index/user`

- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)
- **数据流数量**: 1
- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)

- **危险参数**: URL 参数

