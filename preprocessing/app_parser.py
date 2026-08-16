"""
app_parser.py — 解析微信小程序 app.json，提取页面路径列表。

职责：
  - 读取 app.json
  - 提取 pages 字段（必需）和 subPackages / subpackages 字段（分包）
  - 返回归一化的页面路径列表（统一去掉首尾斜线，格式如 pages/index/index）
"""

import json
import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class AppParser:
    """解析 app.json，提取全量页面路径（含分包）。"""

    def __init__(self, miniapp_root: str):
        """
        :param miniapp_root: 小程序源码根目录，app.json 应位于该目录下。
        """
        self.miniapp_root = os.path.abspath(miniapp_root)
        self.app_json_path = os.path.join(self.miniapp_root, "app.json")
        self._raw: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------------

    def parse(self) -> List[str]:
        """
        读取并解析 app.json。

        :returns: 归一化页面路径列表，如 ["pages/index/index", "pages/device/device"]
        :raises FileNotFoundError: app.json 不存在
        :raises ValueError: app.json 格式错误或缺少 pages 字段
        """
        self._raw = self._load_json()
        pages = self._extract_pages()
        logger.info("共发现 %d 个页面（含分包）", len(pages))
        return pages

    def get_raw(self) -> Dict[str, Any]:
        """返回原始 app.json 内容（parse() 调用后才有效）。"""
        return self._raw

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _load_json(self) -> Dict[str, Any]:
        if not os.path.isfile(self.app_json_path):
            raise FileNotFoundError(f"app.json 不存在: {self.app_json_path}")

        with open(self.app_json_path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"app.json 解析失败: {e}") from e

    def _extract_pages(self) -> List[str]:
        pages: List[str] = []

        # 主包页面（必需字段）
        main_pages = self._raw.get("pages")
        if not isinstance(main_pages, list) or len(main_pages) == 0:
            raise ValueError("app.json 缺少有效的 'pages' 字段")

        for p in main_pages:
            pages.append(self._normalize(p))

        # 分包页面（subPackages 或 subpackages，两种写法均支持）
        sub_packages = self._raw.get("subPackages") or self._raw.get("subpackages") or []
        for pkg in sub_packages:
            root = pkg.get("root", "").strip("/")
            for p in pkg.get("pages", []):
                full_path = f"{root}/{p}" if root else p
                pages.append(self._normalize(full_path))

        # 去重，保持顺序
        seen = set()
        unique: List[str] = []
        for p in pages:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        return unique

    @staticmethod
    def _normalize(path: str) -> str:
        """统一去掉首尾斜线，将反斜线替换为正斜线。"""
        return path.replace("\\", "/").strip("/")


# ------------------------------------------------------------------
# 模块级便捷函数
# ------------------------------------------------------------------

def parse_app_json(miniapp_root: str) -> List[str]:
    """便捷函数：解析 app.json 并返回页面路径列表。"""
    return AppParser(miniapp_root).parse()
