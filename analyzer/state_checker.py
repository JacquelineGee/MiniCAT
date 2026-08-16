"""
state_checker.py — 用户状态检查分析器

功能：
1. 解析 UserState.ql 的查询结果
2. 识别目标页面是否进行了用户状态检查
3. 标记缺少用户验证的页面（潜在 CPRF 漏洞）
"""

import logging
from typing import Dict, List, Set

logger = logging.getLogger(__name__)


class StateChecker:
    """
    用户状态检查分析器
    """

    def __init__(self):
        self.state_checks: Dict[str, List[Dict]] = {}  # page_path -> [checks]

    def analyze(self, user_state_results: List[Dict]) -> Dict[str, List[Dict]]:
        """
        分析 UserState.ql 查询结果，提取用户状态检查信息

        参数:
            user_state_results: CodeQL 查询结果，格式:
                [{"pagePath": "...", "lifecycleName": "...", "checkType": "...",
                  "checkExpr": "...", "filePath": "...", "line": ...}]

        返回:
            字典: page_path -> [检查信息列表]
        """
        logger.info("开始分析用户状态检查...")

        for row in user_state_results:
            page_path = row.get("pagePath")
            lifecycle_name = row.get("lifecycleName")
            check_type = row.get("checkType")
            check_expr = row.get("checkExpr")
            file_path = row.get("filePath")
            line = row.get("line")

            if not page_path:
                continue

            # 规范化页面路径（移除 .js 后缀）
            normalized_page = self._normalize_page_path(page_path)

            check_info = {
                "lifecycle": lifecycle_name,
                "check_type": check_type,
                "check_expr": check_expr,
                "file": file_path,
                "line": line,
            }

            if normalized_page not in self.state_checks:
                self.state_checks[normalized_page] = []

            self.state_checks[normalized_page].append(check_info)

        logger.info(
            "用户状态检查分析完成: %d 个页面有状态检查", len(self.state_checks)
        )

        return self.state_checks

    def check_page_has_user_state(self, page_path: str) -> bool:
        """
        检查指定页面是否进行了用户状态检查

        参数:
            page_path: 页面路径（如 "pages/profile/profile"）

        返回:
            True 如果页面有用户状态检查，否则 False
        """
        normalized_page = self._normalize_page_path(page_path)
        return normalized_page in self.state_checks

    def get_page_checks(self, page_path: str) -> List[Dict]:
        """
        获取指定页面的所有用户状态检查

        参数:
            page_path: 页面路径

        返回:
            检查信息列表
        """
        normalized_page = self._normalize_page_path(page_path)
        return self.state_checks.get(normalized_page, [])

    def get_pages_without_checks(self, all_pages: List[str]) -> List[str]:
        """
        获取所有没有用户状态检查的页面

        参数:
            all_pages: 所有页面路径列表

        返回:
            没有状态检查的页面列表
        """
        pages_without_checks = []

        for page in all_pages:
            normalized_page = self._normalize_page_path(page)
            if normalized_page not in self.state_checks:
                pages_without_checks.append(page)

        return pages_without_checks

    def _normalize_page_path(self, page_path: str) -> str:
        """
        规范化页面路径

        参数:
            page_path: 原始页面路径（可能包含 .js 后缀或包名）

        返回:
            规范化后的页面路径（如 "pages/profile/profile"）
        """
        # 移除 .js 后缀
        if page_path.endswith(".js"):
            page_path = page_path[:-3]

        # 移除前导斜杠
        page_path = page_path.lstrip("/")

        # 移除 packageA/ packageB/ 等前缀（如果存在）
        if "/" in page_path:
            parts = page_path.split("/")
            if parts[0].startswith("package"):
                page_path = "/".join(parts[1:])

        return page_path

    def get_statistics(self) -> Dict:
        """
        获取用户状态检查的统计信息

        返回:
            统计字典
        """
        check_type_count = {}

        for page, checks in self.state_checks.items():
            for check in checks:
                check_type = check["check_type"].split(":")[0]
                check_type_count[check_type] = check_type_count.get(check_type, 0) + 1

        return {
            "total_pages_with_checks": len(self.state_checks),
            "total_checks": sum(len(checks) for checks in self.state_checks.values()),
            "check_type_distribution": check_type_count,
        }
