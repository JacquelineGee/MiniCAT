"""
share_checker.py — 分享功能检查分析器

功能：
1. 解析 ShareCheck.ql 的查询结果
2. 识别哪些页面支持分享（定义了 onShareAppMessage）
3. 提取分享配置信息（title, path）
"""

import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class ShareChecker:
    """
    分享功能检查分析器
    """

    def __init__(self):
        self.share_info: Dict[str, Dict] = {}  # page_path -> share_info

    def analyze(self, share_check_results: List[Dict]) -> Dict[str, Dict]:
        """
        分析 ShareCheck.ql 查询结果，提取分享功能信息

        参数:
            share_check_results: CodeQL 查询结果，格式:
                [{"pagePath": "...", "shareable": "true/false",
                  "shareTitle": "...", "sharePath": "...",
                  "filePath": "...", "line": ...}]

        返回:
            字典: page_path -> {shareable, share_title, share_path, file, line}
        """
        logger.info("开始分析分享功能...")

        for row in share_check_results:
            page_path = row.get("pagePath")
            shareable = row.get("shareable") == "true"
            share_title = row.get("shareTitle")
            share_path = row.get("sharePath")
            file_path = row.get("filePath")
            line = row.get("line")

            if not page_path:
                continue

            # 规范化页面路径（移除 .js 后缀）
            normalized_page = self._normalize_page_path(page_path)

            share_info = {
                "shareable": shareable,
                "share_title": share_title if share_title != "<none>" else None,
                "share_path": share_path if share_path != "<none>" else None,
                "file": file_path,
                "line": line if line > 0 else None,
            }

            self.share_info[normalized_page] = share_info

        logger.info(
            "分享功能分析完成: %d 个页面，其中 %d 个可分享",
            len(self.share_info),
            sum(1 for info in self.share_info.values() if info["shareable"])
        )

        return self.share_info

    def is_page_shareable(self, page_path: str) -> bool:
        """
        检查指定页面是否支持分享

        参数:
            page_path: 页面路径（如 "pages/detail/detail"）

        返回:
            True 如果页面支持分享，否则 False
        """
        normalized_page = self._normalize_page_path(page_path)
        info = self.share_info.get(normalized_page, {})
        return info.get("shareable", False)

    def get_page_share_info(self, page_path: str) -> Dict:
        """
        获取指定页面的分享配置信息

        参数:
            page_path: 页面路径

        返回:
            分享配置信息字典
        """
        normalized_page = self._normalize_page_path(page_path)
        return self.share_info.get(normalized_page, {
            "shareable": False,
            "share_title": None,
            "share_path": None,
            "file": None,
            "line": None,
        })

    def get_shareable_pages(self) -> List[str]:
        """
        获取所有支持分享的页面列表

        返回:
            支持分享的页面路径列表
        """
        return [
            page for page, info in self.share_info.items()
            if info.get("shareable", False)
        ]

    def get_non_shareable_pages(self) -> List[str]:
        """
        获取所有不支持分享的页面列表

        返回:
            不支持分享的页面路径列表
        """
        return [
            page for page, info in self.share_info.items()
            if not info.get("shareable", False)
        ]

    def _normalize_page_path(self, page_path: str) -> str:
        """
        规范化页面路径

        参数:
            page_path: 原始页面路径（可能包含 .js 后缀或包名）

        返回:
            规范化后的页面路径（如 "pages/detail/detail"）
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
        获取分享功能的统计信息

        返回:
            统计字典
        """
        total_pages = len(self.share_info)
        shareable_count = sum(1 for info in self.share_info.values() if info["shareable"])
        non_shareable_count = total_pages - shareable_count

        # 统计有自定义分享配置的页面数量
        custom_config_count = sum(
            1 for info in self.share_info.values()
            if info["shareable"] and (info["share_title"] or info["share_path"])
        )

        return {
            "total_pages": total_pages,
            "shareable_pages": shareable_count,
            "non_shareable_pages": non_shareable_count,
            "custom_share_config": custom_config_count,
        }
