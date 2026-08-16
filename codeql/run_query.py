"""
run_query.py — 执行 CodeQL .ql 查询并解析 BQRS 结果。

职责：
  - 调用 `codeql query run` 执行 .ql 查询文件
  - 调用 `codeql bqrs decode` 解析二进制结果为 JSON
  - 返回结构化的查询结果
"""

import json
import logging
import os
import subprocess
import tempfile
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class QueryRunner:
    """CodeQL 查询执行器。"""

    def __init__(self, db_dir: str, codeql_path: str = "codeql"):
        """
        :param db_dir: CodeQL 数据库目录。
        :param codeql_path: CodeQL CLI 可执行文件路径（默认 "codeql"）。
        """
        self.db_dir = os.path.abspath(db_dir)
        self.codeql_path = codeql_path

        if not os.path.isdir(self.db_dir):
            raise FileNotFoundError(f"CodeQL 数据库不存在: {self.db_dir}")

    # ------------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------------

    def run(self, query_path: str, output_format: str = "json") -> List[Dict[str, Any]]:
        """
        执行 CodeQL 查询并返回结果。

        :param query_path: .ql 查询文件路径（绝对或相对）。
        :param output_format: 输出格式（默认 "json"）。
        :returns: 查询结果列表，每个元素是一个字典（列名 → 值）。
        """
        query_path = os.path.abspath(query_path)

        if not os.path.isfile(query_path):
            logger.error("查询文件不存在: %s", query_path)
            return []

        logger.info("执行 CodeQL 查询: %s", query_path)

        # 临时文件：存储 BQRS 和 JSON 结果
        with tempfile.NamedTemporaryFile(suffix=".bqrs", delete=False) as bqrs_file, \
             tempfile.NamedTemporaryFile(suffix=".json", delete=False) as json_file:

            bqrs_path = bqrs_file.name
            json_path = json_file.name

        try:
            # Step 1: 运行查询，生成 BQRS
            self._run_query(query_path, bqrs_path)

            # Step 2: 解码 BQRS → JSON
            self._decode_bqrs(bqrs_path, json_path)

            # Step 3: 读取 JSON 结果
            results = self._parse_json(json_path)

            logger.info("查询返回 %d 条结果", len(results))
            return results

        finally:
            # 清理临时文件
            for f in [bqrs_path, json_path]:
                if os.path.exists(f):
                    os.remove(f)

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _run_query(self, query_path: str, bqrs_path: str) -> None:
        """
        执行 CodeQL 查询，生成 BQRS 文件。

        命令：codeql query run <query.ql> --database=<db> --output=<bqrs>
        """
        cmd = [
            self.codeql_path,
            "query", "run",
            query_path,
            f"--database={self.db_dir}",
            f"--output={bqrs_path}",
        ]

        logger.debug("执行命令: %s", " ".join(cmd))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=300,
            check=False,
        )

        if result.returncode != 0:
            logger.error("查询执行失败，返回码: %d", result.returncode)
            logger.error("标准输出: %s", result.stdout)
            logger.error("标准错误: %s", result.stderr)
            raise RuntimeError(f"CodeQL 查询失败: {result.stderr}")

        logger.debug("查询执行完成: %s", bqrs_path)

    def _decode_bqrs(self, bqrs_path: str, json_path: str) -> None:
        """
        解码 BQRS → JSON。

        命令：codeql bqrs decode <bqrs> --format=json --output=<json>
        """
        cmd = [
            self.codeql_path,
            "bqrs", "decode",
            bqrs_path,
            "--format=json",
            f"--output={json_path}",
        ]

        logger.debug("执行命令: %s", " ".join(cmd))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=60,
            check=True,
        )

        logger.debug("BQRS 解码完成: %s", json_path)

    def _parse_json(self, json_path: str) -> List[Dict[str, Any]]:
        """
        解析 CodeQL JSON 输出。

        CodeQL JSON 格式：
        {
          "#select": {
            "tuples": [
              [col1_value, col2_value, ...],
              ...
            ],
            "columns": [
              {"name": "col1", "kind": "..."},
              {"name": "col2", "kind": "..."}
            ]
          }
        }

        返回格式：
        [
          {"col1": value1, "col2": value2, ...},
          ...
        ]
        """
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 提取 #select 结果
        select = data.get("#select", {})
        tuples = select.get("tuples", [])
        columns = select.get("columns", [])

        if not columns:
            logger.warning("查询无列定义，返回空结果")
            return []

        column_names = [col.get("name", f"col_{i}") for i, col in enumerate(columns)]

        # 转换为字典列表
        results = []
        for row in tuples:
            if len(row) != len(column_names):
                logger.warning("行列数不匹配，跳过: %s", row)
                continue
            results.append(dict(zip(column_names, row)))

        return results
