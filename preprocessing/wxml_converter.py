"""
wxml_converter.py — 调用 Node.js convert.js，将 .wxml 转换为 .html。

职责：
  - 遍历 page_index 中的所有页面
  - 对每个有 .wxml 文件的页面，调用 Node.js convert.js 完成转换
  - 将生成的 .html 文件路径回填到 page_index
"""

import logging
import os
import subprocess
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class WxmlConverter:
    """批量调用 Node.js 脚本完成 WXML → HTML 转换。"""

    def __init__(self, miniapp_root: str, transformer_script: str, node_path: str = "node"):
        """
        :param miniapp_root: 小程序源码根目录。
        :param transformer_script: convert.js 脚本的路径（相对或绝对）。
        :param node_path: Node.js 可执行文件路径（默认 "node"）。
        """
        self.miniapp_root = os.path.abspath(miniapp_root)
        self.transformer_script = os.path.abspath(transformer_script)
        self.node_path = node_path

        if not os.path.isfile(self.transformer_script):
            logger.error("转换脚本不存在: %s", self.transformer_script)
            raise FileNotFoundError(f"转换脚本不存在: {self.transformer_script}")

    # ------------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------------

    def convert_all(self, page_index: Dict[str, dict]) -> Dict[str, dict]:
        """
        批量转换所有页面的 WXML → HTML。

        :param page_index: 由 PageIndexBuilder 生成的页面索引。
        :returns: 更新后的 page_index（html 字段已填充）。
        """
        total = len(page_index)
        converted = 0
        skipped = 0
        failed = 0

        logger.info("开始批量转换 WXML → HTML，共 %d 页", total)

        for page_path, files in page_index.items():
            wxml_abs = files.get("wxml")

            # 跳过无 WXML 的页面
            if not wxml_abs or not os.path.isfile(wxml_abs):
                skipped += 1
                continue

            # 生成 HTML 输出路径（与 WXML 同目录，同名但扩展名为 .html）
            html_abs = os.path.splitext(wxml_abs)[0] + ".html"

            # 调用 Node.js 转换
            success = self._convert_single(wxml_abs, html_abs)

            if success:
                # 回填 HTML 路径到 page_index
                page_index[page_path]["html"] = html_abs
                converted += 1
            else:
                failed += 1
                logger.warning("转换失败: %s", page_path)

        logger.info(
            "WXML 转换完成: 成功 %d, 跳过 %d, 失败 %d",
            converted, skipped, failed,
        )
        return page_index

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _convert_single(self, wxml_path: str, html_path: str) -> bool:
        """
        调用 Node.js convert.js 转换单个 WXML 文件。

        :param wxml_path: 输入 WXML 文件绝对路径。
        :param html_path: 输出 HTML 文件绝对路径。
        :returns: 成功返回 True，失败返回 False。
        """
        try:
            result = subprocess.run(
                [self.node_path, self.transformer_script, wxml_path, html_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=10,
                check=True,
            )
            logger.debug("转换成功: %s", wxml_path)
            return True

        except subprocess.CalledProcessError as e:
            logger.error(
                "转换失败 [%s]: returncode=%d, stderr=%s",
                wxml_path, e.returncode, e.stderr.strip(),
            )
            return False

        except subprocess.TimeoutExpired:
            logger.error("转换超时: %s", wxml_path)
            return False

        except Exception as e:
            logger.error("转换异常 [%s]: %s", wxml_path, e)
            return False
