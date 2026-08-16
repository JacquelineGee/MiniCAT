"""
report_generator.py — 检测报告生成器（Step 10）

功能：
1. 生成 Markdown 格式的检测报告
2. 汇总所有检测结果和统计信息
3. 生成漏洞详情列表
4. 生成可读的攻击路径描述
"""

import logging
import os
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    检测报告生成器
    """

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.report_path = os.path.join(output_dir, "detection_report.md")

    def generate(
        self,
        miniapp_path: str,
        page_count: int,
        routes: List[Dict],
        event_chains: List[Dict],
        trigger_chains: List[Dict],
        state_checks: Dict,
        share_info: Dict,
        attack_paths: List[Dict],
        vulnerable_paths: List[Dict],
        cprf_paths: List[Dict],
        route_stats: Dict,
        state_stats: Dict,
        share_stats: Dict,
        path_stats: Dict,
    ) -> str:
        """
        生成完整的检测报告

        返回:
            报告文件路径
        """
        logger.info("开始生成检测报告...")

        report_lines = []

        # 1. 报告标题和元信息
        report_lines.extend(self._generate_header(miniapp_path))

        # 2. 执行摘要
        report_lines.extend(self._generate_summary(
            page_count, routes, trigger_chains, vulnerable_paths, cprf_paths
        ))

        # 3. 检测结果统计
        report_lines.extend(self._generate_statistics(
            route_stats, state_stats, share_stats, path_stats
        ))

        # 4. 高风险 CPRF 漏洞列表
        report_lines.extend(self._generate_cprf_vulnerabilities(cprf_paths))

        # 5. 中风险漏洞列表
        medium_risk_paths = [
            p for p in vulnerable_paths
            if p["risk_assessment"]["risk_level"] == "medium"
        ]
        report_lines.extend(self._generate_medium_risk_vulnerabilities(medium_risk_paths))

        # 6. 详细攻击路径示例
        report_lines.extend(self._generate_attack_path_examples(cprf_paths[:3]))

        # 7. 修复建议
        report_lines.extend(self._generate_recommendations())

        # 写入报告文件
        report_content = "\n".join(report_lines)
        os.makedirs(os.path.dirname(self.report_path), exist_ok=True)
        with open(self.report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        logger.info("检测报告已生成: %s", self.report_path)
        return self.report_path

    def _generate_header(self, miniapp_path: str) -> List[str]:
        """生成报告标题"""
        return [
            "# MiniCAT Detector 检测报告",
            "",
            f"**小程序路径**: `{miniapp_path}`",
            f"**检测时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**检测器版本**: MiniCAT v1.0",
            "",
            "---",
            "",
        ]

    def _generate_summary(
        self,
        page_count: int,
        routes: List[Dict],
        trigger_chains: List[Dict],
        vulnerable_paths: List[Dict],
        cprf_paths: List[Dict],
    ) -> List[str]:
        """生成执行摘要"""
        return [
            "## 📊 执行摘要",
            "",
            f"本次检测共扫描 **{page_count}** 个页面，识别出 **{len(cprf_paths)}** 个高风险 CPRF 漏洞和 **{len(vulnerable_paths) - len(cprf_paths)}** 个中风险漏洞。",
            "",
            "### 关键发现",
            "",
            f"- 🔴 **高风险 CPRF 漏洞**: {len(cprf_paths)} 个",
            f"- 🟡 **中风险漏洞**: {len(vulnerable_paths) - len(cprf_paths)} 个",
            f"- 📍 **路由 API 调用**: {len(routes)} 个",
            f"- 🔗 **用户触发链**: {len(trigger_chains)} 个",
            "",
            "### 风险说明",
            "",
            "**高风险 CPRF 漏洞**指目标页面既缺少用户身份验证，又支持分享功能。攻击者可以构造恶意参数并通过分享链接传播，受害者点击后会在未验证身份的情况下执行敏感操作。",
            "",
            "**中风险漏洞**指目标页面缺少用户身份验证但不支持分享。虽然无法通过分享传播，但攻击者仍可能通过其他方式（如二维码、URL scheme）诱导用户访问。",
            "",
            "---",
            "",
        ]

    def _generate_statistics(
        self,
        route_stats: Dict,
        state_stats: Dict,
        share_stats: Dict,
        path_stats: Dict,
    ) -> List[str]:
        """生成统计信息"""
        lines = [
            "## 📈 检测结果统计",
            "",
            "### 路由 API 分布",
            "",
        ]

        if route_stats:
            for route_type, count in sorted(route_stats.items()):
                lines.append(f"- `{route_type}`: {count} 次")
            lines.append("")

        lines.extend([
            "### 用户状态检查",
            "",
            f"- 有状态检查的页面: **{state_stats.get('total_pages_with_checks', 0)}** 个",
            f"- 总检查次数: **{state_stats.get('total_checks', 0)}** 次",
            "",
        ])

        if state_stats.get('check_type_distribution'):
            lines.append("检查类型分布:")
            lines.append("")
            for check_type, count in sorted(state_stats['check_type_distribution'].items()):
                lines.append(f"- `{check_type}`: {count} 次")
            lines.append("")

        lines.extend([
            "### 分享功能",
            "",
            f"- 总页面数: **{share_stats.get('total_pages', 0)}** 个",
            f"- 可分享页面: **{share_stats.get('shareable_pages', 0)}** 个",
            f"- 不可分享页面: **{share_stats.get('non_shareable_pages', 0)}** 个",
            f"- 自定义分享配置: **{share_stats.get('custom_share_config', 0)}** 个",
            "",
            "### 攻击路径",
            "",
            f"- 总攻击路径: **{path_stats.get('total_attack_paths', 0)}** 条",
            f"- 漏洞路径: **{path_stats.get('vulnerable_paths', 0)}** 条",
            f"- 高风险 CPRF: **{path_stats.get('high_risk_cprf', 0)}** 条",
            "",
        ])

        if path_stats.get('risk_distribution'):
            lines.append("风险等级分布:")
            lines.append("")
            for risk_level, count in sorted(path_stats['risk_distribution'].items()):
                emoji = {"high": "🔴", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(risk_level, "")
                lines.append(f"- {emoji} `{risk_level}`: {count} 条")
            lines.append("")

        lines.extend([
            "---",
            "",
        ])

        return lines

    def _generate_cprf_vulnerabilities(self, cprf_paths: List[Dict]) -> List[str]:
        """生成高风险 CPRF 漏洞列表"""
        lines = [
            "## 🔴 高风险 CPRF 漏洞",
            "",
            f"共发现 **{len(cprf_paths)}** 个高风险 CPRF 漏洞。以下是漏洞列表：",
            "",
        ]

        if not cprf_paths:
            lines.append("*未发现高风险 CPRF 漏洞*")
            lines.extend(["", "---", ""])
            return lines

        for i, path in enumerate(cprf_paths[:20], 1):  # 最多显示前 20 个
            target_page = path["step4_target_page"]["page_path"]
            route_type = path["step3_route_api"]["api_type"]
            wxml_file = path["step1_user_trigger"]["wxml_file"]
            element = path["step1_user_trigger"]["element"]

            lines.extend([
                f"### {i}. {target_page}",
                "",
                f"- **目标页面**: `{target_page}`",
                f"- **路由 API**: `{route_type}`",
                f"- **触发位置**: `{wxml_file}` 中的 `<{element}>`",
                f"- **风险等级**: 🔴 HIGH (CPRF)",
                "",
                "**漏洞描述**: 目标页面缺少用户身份验证且支持分享功能，攻击者可以构造恶意参数并通过分享传播。",
                "",
            ])

        if len(cprf_paths) > 20:
            lines.append(f"*...还有 {len(cprf_paths) - 20} 个高风险漏洞，详见 `cprf_attack_paths.json`*")
            lines.append("")

        lines.extend([
            "---",
            "",
        ])

        return lines

    def _generate_medium_risk_vulnerabilities(self, medium_risk_paths: List[Dict]) -> List[str]:
        """生成中风险漏洞列表"""
        lines = [
            "## 🟡 中风险漏洞",
            "",
            f"共发现 **{len(medium_risk_paths)}** 个中风险漏洞（缺少用户验证但不支持分享）。",
            "",
        ]

        if not medium_risk_paths:
            lines.append("*未发现中风险漏洞*")
            lines.extend(["", "---", ""])
            return lines

        # 按目标页面分组统计
        target_pages = {}
        for path in medium_risk_paths:
            target = path["step4_target_page"]["page_path"]
            target_pages[target] = target_pages.get(target, 0) + 1

        lines.append("### 受影响的目标页面")
        lines.append("")

        for i, (target, count) in enumerate(sorted(target_pages.items(), key=lambda x: x[1], reverse=True)[:10], 1):
            lines.append(f"{i}. `{target}` - {count} 条攻击路径")

        if len(target_pages) > 10:
            lines.append(f"*...还有 {len(target_pages) - 10} 个页面，详见 `vulnerable_attack_paths.json`*")

        lines.extend([
            "",
            "---",
            "",
        ])

        return lines

    def _generate_attack_path_examples(self, cprf_paths: List[Dict]) -> List[str]:
        """生成详细攻击路径示例"""
        lines = [
            "## 🔍 攻击路径详细示例",
            "",
        ]

        if not cprf_paths:
            lines.append("*无攻击路径示例*")
            lines.extend(["", "---", ""])
            return lines

        for i, path in enumerate(cprf_paths[:3], 1):
            lines.extend([
                f"### 示例 {i}: {path['step4_target_page']['page_path']}",
                "",
                "#### 攻击流程",
                "",
            ])

            flow_lines = path["attack_flow"].split("\n")
            for line in flow_lines:
                lines.append(line)

            lines.extend([
                "",
                "#### 风险评估",
                "",
                f"- **风险等级**: {path['risk_assessment']['risk_level'].upper()}",
                f"- **漏洞类型**: {path['risk_assessment']['vulnerability_type']}",
                f"- **是否可利用**: {'是' if path['risk_assessment']['is_vulnerable'] else '否'}",
                "",
                f"**说明**: {path['risk_assessment']['explanation']}",
                "",
                "---",
                "",
            ])

        return lines

    def _generate_recommendations(self) -> List[str]:
        """生成修复建议"""
        return [
            "## 💡 修复建议",
            "",
            "### 针对高风险 CPRF 漏洞",
            "",
            "1. **添加用户身份验证**",
            "   - 在目标页面的 `onLoad()` 或 `onShow()` 生命周期函数中添加用户登录状态检查",
            "   - 使用 `wx.getStorageSync('token')` 或 `wx.getStorageSync('userInfo')` 检查用户登录信息",
            "   - 如果未登录，跳转到登录页面：`wx.navigateTo({url: '/pages/login/login'})`",
            "",
            "2. **验证请求来源**",
            "   - 检查页面参数的合法性和完整性",
            "   - 对敏感操作添加二次确认（如弹窗确认）",
            "   - 使用时间戳或随机 token 防止重放攻击",
            "",
            "3. **限制分享功能**",
            "   - 如果页面不需要分享功能，移除 `onShareAppMessage()` 函数",
            "   - 如果需要分享，确保分享的页面路径不包含敏感参数",
            "",
            "### 针对中风险漏洞",
            "",
            "1. **添加用户身份验证**（同上）",
            "2. **限制页面访问方式**",
            "   - 检查页面来源，确保只能通过应用内部跳转访问",
            "   - 避免使用 URL scheme 或二维码直接访问敏感页面",
            "",
            "### 代码示例",
            "",
            "```javascript",
            "// 在目标页面的 onLoad 中添加用户验证",
            "Page({",
            "  onLoad: function(options) {",
            "    // 检查用户登录状态",
            "    const userInfo = wx.getStorageSync('userInfo');",
            "    const token = wx.getStorageSync('token');",
            "    ",
            "    if (!userInfo || !token) {",
            "      // 未登录，跳转到登录页面",
            "      wx.showToast({",
            "        title: '请先登录',",
            "        icon: 'none'",
            "      });",
            "      wx.redirectTo({",
            "        url: '/pages/login/login'",
            "      });",
            "      return;",
            "    }",
            "    ",
            "    // 已登录，继续执行页面逻辑",
            "    this.loadData();",
            "  }",
            "});",
            "```",
            "",
            "---",
            "",
            "## 📝 附录",
            "",
            "### 相关文件",
            "",
            "- `attack_paths.json` - 所有攻击路径详细信息",
            "- `vulnerable_attack_paths.json` - 所有漏洞攻击路径",
            "- `cprf_attack_paths.json` - 高风险 CPRF 攻击路径",
            "- `routes.json` - 所有路由 API 调用",
            "- `user_state_checks.json` - 用户状态检查详情",
            "- `share_info.json` - 页面分享功能信息",
            "",
            "### 联系方式",
            "",
            "如有疑问或需要进一步分析，请联系安全团队。",
            "",
            "---",
            "",
            f"*报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
        ]
