"""
route_analyzer.py — 分析 CodeQL RouteAPI 查询结果，提取路由信息。

职责：
  - 解析 RouteAPI.ql 返回的结果
  - 提取路由类型、来源位置、目标页面、参数等信息
  - 为每个路由生成唯一 ID
"""

import logging
import re
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class RouteAnalyzer:
    """路由 API 结果分析器。"""

    def __init__(self):
        self.route_id = 0

    # ------------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------------

    def analyze(self, query_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        分析 RouteAPI.ql 查询结果。

        输入格式（CodeQL 查询返回）：
        {
          "apiName": "wx.redirectTo",
          "fileName": "pages/index/index.js",
          "lineNumber": 42,
          "funcName": "handleClick",
          "urlExpr": "'/pages/detail/detail?id=' + id"
        }

        输出格式：
        {
          "route_id": "route_1",
          "type": "wx.redirectTo",
          "source_file": "pages/index/index.js",
          "source_line": 42,
          "source_function": "handleClick",
          "url_expression": "'/pages/detail/detail?id=' + id",
          "target_page": "pages/detail/detail",  # 提取的目标页面路径
          "has_params": true,  # 是否有参数
          "is_dynamic": true   # URL 是否包含动态拼接
        }

        :param query_results: RouteAPI.ql 查询结果列表。
        :returns: 结构化的路由信息列表。
        """
        routes = []

        for result in query_results:
            route = self._analyze_single(result)
            if route:
                routes.append(route)

        logger.info("路由分析完成: 共 %d 条路由", len(routes))
        return routes

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _analyze_single(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """分析单条路由记录。"""
        self.route_id += 1

        api_name = result.get("apiName", "")
        file_name = result.get("fileName", "")
        line_number = result.get("lineNumber", 0)
        func_name = result.get("funcName", "")
        url_expr = result.get("urlExpr", "")

        # 提取目标页面路径和参数
        target_page, has_params, is_dynamic = self._extract_target_page(url_expr)

        return {
            "route_id": f"route_{self.route_id}",
            "type": api_name,
            "source_file": file_name,
            "source_line": line_number,
            "source_function": func_name,
            "url_expression": url_expr,
            "target_page": target_page,
            "has_params": has_params,
            "is_dynamic": is_dynamic,
        }

    def _extract_target_page(self, url_expr: str) -> tuple[Optional[str], bool, bool]:
        """
        从 URL 表达式中提取目标页面路径。

        :returns: (target_page, has_params, is_dynamic)
        """
        if not url_expr or url_expr in ("<no-url>", "<anonymous>"):
            return None, False, False

        # 检查是否为简单变量引用（单个标识符）
        # 例如：options, urlVar, e, t
        if re.match(r'^[a-zA-Z_]\w*$', url_expr):
            # 单个变量名，无法静态提取
            return None, False, True

        # 检查是否包含函数调用（排除已经在 URL 中的查询参数）
        if "(" in url_expr and "?" not in url_expr:
            return None, False, True

        # 情况 1: 纯字符串（CodeQL 的 StringLiteral.getValue() 返回的不带引号的值）
        # 匹配：/pages/xxx/xxx 或 ../pages/xxx 或 pages/xxx
        if re.match(r'^[./a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)*(?:\?.*)?$', url_expr):
            # 分离路径和参数
            if "?" in url_expr:
                path, params = url_expr.split("?", 1)
                return path.strip("/"), True, False
            else:
                return url_expr.strip("/"), False, False

        # 情况 2: 带引号的字符串字面量（来自 toString() 的结果）
        match = re.search(r'["\']([/a-zA-Z0-9_\-\.]+(?:/[a-zA-Z0-9_\-\.]+)*(?:\?[^"\']*)?)', url_expr)
        if match:
            url = match.group(1)
            # 分离路径和参数
            if "?" in url:
                path, params = url.split("?", 1)
                return path.strip("/"), True, False
            else:
                return url.strip("/"), False, False

        # 情况 3: 包含拼接的动态 URL，如 "/pages/xxx" + id 或 `${base}/xxx`
        if "+" in url_expr or "${" in url_expr:
            # 尝试提取静态前缀部分
            match = re.search(r'["\']?([/a-zA-Z0-9_\-\.]+(?:/[a-zA-Z0-9_\-\.]+)*)', url_expr)
            if match:
                path = match.group(1).strip("/")
                # 去掉参数部分（如果有）
                if "?" in path:
                    path = path.split("?")[0]
                return path, True, True

        # 无法提取
        return None, False, True
