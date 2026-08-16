"""
page_index.py — 根据 app.json 解析出的页面路径，在文件系统中定位对应的
.js / .wxml / .html 文件，建立页面索引。

输出格式（每个页面一条记录）：
{
  "pages/device/deviceDetail": {
    "js":   "D:/...pages/device/deviceDetail.js",    # 绝对路径，文件不存在则 null
    "wxml": "D:/...pages/device/deviceDetail.wxml",
    "html": "D:/...pages/device/deviceDetail.html"   # 转换后生成，初始为 null
  },
  ...
}
"""

import os
import logging
from typing import Dict, Optional

from preprocessing.app_parser import AppParser

logger = logging.getLogger(__name__)


# 页面记录类型别名
PageRecord = Dict[str, Optional[str]]
PageIndex = Dict[str, PageRecord]


class PageIndexBuilder:
    """根据页面路径列表，在文件系统中定位源文件，构建页面索引。"""

    def __init__(self, miniapp_root: str):
        """
        :param miniapp_root: 小程序源码根目录（包含 app.json 的目录）。
        """
        self.miniapp_root = os.path.abspath(miniapp_root)
        self._index: PageIndex = {}

    # ------------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------------

    def build(self, pages: list[str]) -> PageIndex:
        """
        根据页面路径列表构建索引。

        :param pages: 由 AppParser 返回的归一化页面路径列表。
        :returns: PageIndex 字典。
        """
        self._index = {}
        missing_js = []
        missing_wxml = []

        for page_path in pages:
            js_abs = self._resolve(page_path, ".js")
            wxml_abs = self._resolve(page_path, ".wxml")
            # html 由后续 WXML 转换步骤填充，初始为 None
            html_abs = self._resolve(page_path, ".html")

            self._index[page_path] = {
                "js":   js_abs,
                "wxml": wxml_abs,
                "html": html_abs if html_abs else None,
            }

            if js_abs is None:
                missing_js.append(page_path)
                logger.warning("缺少 JS 文件: %s.js", page_path)
            if wxml_abs is None:
                missing_wxml.append(page_path)
                logger.debug("缺少 WXML 文件: %s.wxml（纯逻辑页面？）", page_path)

        logger.info(
            "页面索引构建完成: 共 %d 页, 缺JS %d 个, 缺WXML %d 个",
            len(self._index), len(missing_js), len(missing_wxml),
        )
        return self._index

    def get_index(self) -> PageIndex:
        """返回上次 build() 生成的索引。"""
        return self._index

    def update_html_path(self, page_path: str, html_abs: str) -> None:
        """
        WXML 转换完成后，回填 html 字段。

        :param page_path: 归一化页面路径，如 pages/index/index。
        :param html_abs:  转换生成的 .html 文件绝对路径。
        """
        if page_path in self._index:
            self._index[page_path]["html"] = html_abs
        else:
            logger.warning("update_html_path: 未知页面 %s，跳过", page_path)

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _resolve(self, page_path: str, ext: str) -> Optional[str]:
        """
        拼接绝对路径，文件存在则返回路径，否则返回 None。
        """
        abs_path = os.path.join(self.miniapp_root, page_path + ext)
        abs_path = os.path.normpath(abs_path)
        return abs_path if os.path.isfile(abs_path) else None


# ------------------------------------------------------------------
# 模块级便捷函数
# ------------------------------------------------------------------

def build_page_index(miniapp_root: str) -> PageIndex:
    """
    一步完成 app.json 解析 + 页面索引构建。

    :param miniapp_root: 小程序源码根目录。
    :returns: PageIndex 字典。
    """
    parser = AppParser(miniapp_root)
    pages = parser.parse()
    builder = PageIndexBuilder(miniapp_root)
    return builder.build(pages)
