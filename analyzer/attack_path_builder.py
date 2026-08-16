"""
attack_path_builder.py — 攻击路径构建器（Step 9）

功能：
1. 整合所有分析结果（路由、事件链、触发链、用户状态检查、分享功能）
2. 构建完整的 CPRF 攻击路径
3. 评估漏洞风险等级
4. 生成结构化的攻击路径报告
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AttackPathBuilder:
    """
    攻击路径构建器
    """

    def __init__(self):
        self.attack_paths: List[Dict] = []

    def build(
        self,
        trigger_chains: List[Dict],
        state_checks: Dict[str, List[Dict]],
        share_info: Dict[str, Dict],
    ) -> List[Dict]:
        """
        构建完整的攻击路径

        参数:
            trigger_chains: 触发链列表（包含 WXML 触发器、事件处理函数、路由信息）
            state_checks: 用户状态检查信息（page_path -> [checks]）
            share_info: 分享功能信息（page_path -> share_info）

        返回:
            攻击路径列表
        """
        logger.info("开始构建攻击路径...")

        for chain in trigger_chains:
            attack_path = self._build_single_path(chain, state_checks, share_info)
            if attack_path:
                self.attack_paths.append(attack_path)

        logger.info("攻击路径构建完成: 共 %d 条路径", len(self.attack_paths))

        return self.attack_paths

    def _build_single_path(
        self,
        chain: Dict,
        state_checks: Dict[str, List[Dict]],
        share_info: Dict[str, Dict],
    ) -> Optional[Dict]:
        """
        构建单条攻击路径

        攻击路径结构：
        User → WXML Trigger → Event Handler → Route API → Target Page
        """
        route_target = chain.get("route_target")
        if not route_target:
            return None

        # 规范化页面路径
        normalized_target = self._normalize_page_path(route_target)

        # 检查用户状态验证
        has_user_check = normalized_target in state_checks
        user_check_details = state_checks.get(normalized_target, [])

        # 检查分享功能
        share_config = share_info.get(normalized_target, {})
        is_shareable = share_config.get("shareable", False)

        # 计算风险等级
        risk_level = self._calculate_risk(has_user_check, is_shareable, chain)

        # 构建攻击路径
        attack_path = {
            # 基本信息
            "path_id": f"path_{chain.get('trigger_id', 'unknown')}",
            "trigger_id": chain.get("trigger_id"),

            # Step 1: 用户交互入口（WXML Trigger）
            "step1_user_trigger": {
                "wxml_file": chain.get("wxml_file"),
                "wxml_line": chain.get("wxml_line"),
                "element": chain.get("wxml_tag"),
                "event_type": chain.get("wxml_event"),
                "description": f"用户在 {chain.get('wxml_file')} 中触发 <{chain.get('wxml_tag')}> 元素的 {chain.get('wxml_event')} 事件"
            },

            # Step 2: 事件处理函数（Event Handler）
            "step2_event_handler": {
                "handler_name": chain.get("handler_name"),
                "handler_file": chain.get("handler_file"),
                "handler_line": chain.get("handler_line"),
                "call_chain": chain.get("call_chain", []),
                "description": f"事件触发 {chain.get('handler_name')}() 函数"
            },

            # Step 3: 路由 API 调用（Route API）
            "step3_route_api": {
                "route_id": chain.get("route_id"),
                "api_type": chain.get("route_type"),
                "route_file": chain.get("route_file"),
                "route_line": chain.get("route_line"),
                "description": f"在 {chain.get('handler_name')}() 中调用 {chain.get('route_type')}()"
            },

            # Step 4: 目标页面（Target Page）
            "step4_target_page": {
                "page_path": route_target,
                "normalized_path": normalized_target,
                "description": f"跳转到目标页面 {route_target}"
            },

            # Step 5: 用户状态检查（User State Check）
            "step5_user_state": {
                "has_check": has_user_check,
                "check_count": len(user_check_details),
                "check_details": user_check_details,
                "description": "目标页面有用户状态检查" if has_user_check else "⚠️ 目标页面缺少用户状态检查"
            },

            # Step 6: 分享功能（Shareability）
            "step6_shareability": {
                "is_shareable": is_shareable,
                "share_title": share_config.get("share_title"),
                "share_path": share_config.get("share_path"),
                "share_file": share_config.get("file"),
                "share_line": share_config.get("line"),
                "description": "⚠️ 目标页面支持分享" if is_shareable else "目标页面不支持分享"
            },

            # 风险评估
            "risk_assessment": {
                "risk_level": risk_level,
                "is_vulnerable": risk_level in ["high", "medium"],
                "vulnerability_type": "CPRF" if risk_level == "high" else None,
                "explanation": self._get_risk_explanation(risk_level, has_user_check, is_shareable)
            },

            # 完整攻击路径描述
            "attack_flow": self._build_attack_flow_description(
                chain, has_user_check, is_shareable
            )
        }

        return attack_path

    def _calculate_risk(self, has_user_check: bool, is_shareable: bool, chain: Dict) -> str:
        """
        计算风险等级

        风险等级：
        - high: 缺少用户验证 + 支持分享（典型 CPRF 漏洞）
        - medium: 缺少用户验证但不支持分享
        - low: 有用户验证但支持分享
        - info: 有用户验证且不支持分享（安全）
        """
        if not has_user_check and is_shareable:
            return "high"
        elif not has_user_check and not is_shareable:
            return "medium"
        elif has_user_check and is_shareable:
            return "low"
        else:
            return "info"

    def _get_risk_explanation(self, risk_level: str, has_user_check: bool, is_shareable: bool) -> str:
        """
        获取风险等级说明
        """
        explanations = {
            "high": "高风险：目标页面缺少用户身份验证且支持分享。攻击者可以构造恶意参数并通过分享链接传播，受害者点击后会在未验证身份的情况下执行敏感操作。这是典型的 CPRF（Cross-Page Request Forgery）漏洞。",
            "medium": "中风险：目标页面缺少用户身份验证但不支持分享。虽然无法通过分享传播，但攻击者仍可能通过其他方式（如二维码、URL scheme）诱导用户访问。",
            "low": "低风险：目标页面有用户身份验证但支持分享。虽然支持分享，但由于有用户验证，攻击者无法在未授权情况下执行敏感操作。",
            "info": "信息：目标页面有用户身份验证且不支持分享。这是安全的配置。"
        }
        return explanations.get(risk_level, "未知风险等级")

    def _build_attack_flow_description(
        self, chain: Dict, has_user_check: bool, is_shareable: bool
    ) -> str:
        """
        构建攻击流程描述
        """
        flow = []

        flow.append(f"1. 用户在 {chain.get('wxml_file')} 页面中")
        flow.append(f"2. 点击/触发 <{chain.get('wxml_tag')}> 元素的 {chain.get('wxml_event')} 事件")
        flow.append(f"3. 触发事件处理函数 {chain.get('handler_name')}()")

        if chain.get("call_chain"):
            call_chain_str = " → ".join(chain.get("call_chain", []))
            flow.append(f"4. 调用链: {call_chain_str}")

        flow.append(f"5. 执行路由 API: {chain.get('route_type')}()")
        flow.append(f"6. 跳转到目标页面: {chain.get('route_target')}")

        if not has_user_check:
            flow.append("7. ⚠️ 目标页面未进行用户身份验证")
        else:
            flow.append("7. ✓ 目标页面进行了用户身份验证")

        if is_shareable:
            flow.append("8. ⚠️ 目标页面支持分享（可通过分享传播）")
        else:
            flow.append("8. ✓ 目标页面不支持分享")

        return "\n".join(flow)

    def _normalize_page_path(self, page_path: str) -> str:
        """
        规范化页面路径
        """
        if page_path.endswith(".js"):
            page_path = page_path[:-3]

        page_path = page_path.lstrip("/")

        if "/" in page_path:
            parts = page_path.split("/")
            if parts[0].startswith("package"):
                page_path = "/".join(parts[1:])

        return page_path

    def get_vulnerable_paths(self) -> List[Dict]:
        """
        获取所有漏洞路径（high + medium 风险）
        """
        return [
            path for path in self.attack_paths
            if path["risk_assessment"]["is_vulnerable"]
        ]

    def get_high_risk_paths(self) -> List[Dict]:
        """
        获取高风险路径（CPRF 漏洞）
        """
        return [
            path for path in self.attack_paths
            if path["risk_assessment"]["risk_level"] == "high"
        ]

    def get_statistics(self) -> Dict:
        """
        获取统计信息
        """
        total_paths = len(self.attack_paths)

        risk_distribution = {}
        for path in self.attack_paths:
            risk_level = path["risk_assessment"]["risk_level"]
            risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1

        vulnerable_count = len(self.get_vulnerable_paths())
        high_risk_count = len(self.get_high_risk_paths())

        return {
            "total_attack_paths": total_paths,
            "vulnerable_paths": vulnerable_count,
            "high_risk_cprf": high_risk_count,
            "risk_distribution": risk_distribution,
        }
