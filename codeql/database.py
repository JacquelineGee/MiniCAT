"""
database.py — 调用 CodeQL CLI 创建/管理 JavaScript 数据库。

职责：
  - 调用 `codeql database create` 为小程序源码创建 JavaScript 数据库
  - 数据库包含 AST、函数作用域、调用关系、数据流等分析信息
"""

import logging
import os
import shutil
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


class CodeQLDatabase:
    """CodeQL 数据库管理器。"""

    def __init__(self, source_dir: str, db_dir: str, codeql_path: str = "codeql"):
        """
        :param source_dir: 小程序源码根目录（包含转换后的 HTML 文件）。
        :param db_dir: CodeQL 数据库输出目录。
        :param codeql_path: CodeQL CLI 可执行文件路径（默认 "codeql"）。
        """
        self.source_dir = os.path.abspath(source_dir)
        self.db_dir = os.path.abspath(db_dir)
        self.codeql_path = codeql_path

    # ------------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------------

    def create(self, overwrite: bool = False) -> bool:
        """
        创建 CodeQL 数据库。

        :param overwrite: 是否覆盖已存在的数据库（默认 False）。
        :returns: 成功返回 True，失败返回 False。
        """
        # 检查数据库是否已存在
        if os.path.exists(self.db_dir):
            if overwrite:
                logger.info("数据库已存在，删除并重建: %s", self.db_dir)
                shutil.rmtree(self.db_dir)
            else:
                logger.info("数据库已存在，跳过创建: %s", self.db_dir)
                return True

        logger.info("开始创建 CodeQL 数据库: %s", self.db_dir)
        logger.info("源码目录: %s", self.source_dir)

        try:
            # codeql database create <db-dir> --language=javascript --source-root=<source-dir>
            cmd = [
                self.codeql_path,
                "database", "create",
                self.db_dir,
                "--language=javascript",
                f"--source-root={self.source_dir}",
                "--overwrite" if overwrite else "",
            ]
            # 移除空字符串
            cmd = [c for c in cmd if c]

            logger.debug("执行命令: %s", " ".join(cmd))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=600,  # 10 分钟超时
                check=True,
            )

            logger.info("CodeQL 数据库创建成功: %s", self.db_dir)
            logger.debug("stdout: %s", result.stdout.strip())
            return True

        except subprocess.CalledProcessError as e:
            logger.error(
                "CodeQL 数据库创建失败: returncode=%d, stderr=%s",
                e.returncode, e.stderr.strip()
            )
            return False

        except subprocess.TimeoutExpired:
            logger.error("CodeQL 数据库创建超时（10分钟）")
            return False

        except Exception as e:
            logger.error("CodeQL 数据库创建异常: %s", e)
            return False

    def exists(self) -> bool:
        """检查数据库是否已存在。"""
        return os.path.isdir(self.db_dir)

    def get_path(self) -> str:
        """返回数据库路径。"""
        return self.db_dir
