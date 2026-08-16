"""
event_recovery.py — Reverse Taint 恢复事件触发链。

职责：
  - 从路由 API 调用点（sink）反向追踪到事件函数（source）
  - 构建调用链路径
  - 识别用户可触发的事件函数
"""

import logging
from typing import List, Dict, Any, Set, Optional

logger = logging.getLogger(__name__)


class EventRecovery:
    """事件链恢复分析器。"""

    def __init__(self):
        self.call_graph: Dict[str, List[Dict[str, Any]]] = {}  # callee -> [caller]

    # ------------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------------

    def recover(self, route_results: List[Dict[str, Any]], call_graph_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        从路由 API 反向追踪事件函数。

        :param route_results: 路由分析结果（来自 route_analyzer）。
        :param call_graph_results: 调用图查询结果（来自 CallGraph.ql）。
        :returns: 恢复的事件链列表。
        """
        logger.info("开始事件链恢复...")

        # 构建反向调用图（被调用者 -> 调用者列表）
        self._build_reverse_call_graph(call_graph_results)

        event_chains = []

        for route in route_results:
            route_id = route.get("route_id")
            source_func = route.get("source_function")
            source_file = route.get("source_file")

            # 从路由所在函数开始反向追踪
            chain = self._trace_back(source_func, source_file, max_depth=5)

            event_chains.append({
                "route_id": route_id,
                "route_function": source_func,
                "route_file": source_file,
                "call_chain": chain,
                "entry_function": chain[0] if chain else source_func,  # 调用链的起点
            })

        logger.info("事件链恢复完成: 共 %d 条", len(event_chains))
        return event_chains

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _build_reverse_call_graph(self, call_graph_results: List[Dict[str, Any]]) -> None:
        """
        构建反向调用图：被调用者 -> [调用者列表]

        输入格式（CallGraph.ql）：
        {
          "callerFile": "pages/index/index.js",
          "callerLine": 10,
          "callerName": "handleClick",
          "calleeName": "doRequest",
          "calleeFile": "utils/api.js",
          "calleeLine": 5
        }
        """
        self.call_graph = {}

        for record in call_graph_results:
            caller_func = record.get("callerName")  # 修正：使用 callerName
            caller_file = record.get("callerFile")
            caller_line = record.get("callerLine")

            callee_func = record.get("calleeName")  # 修正：使用 calleeName

            # 跳过无效记录
            if not caller_func or not callee_func:
                continue

            # 构建 callee -> callers 映射
            if callee_func not in self.call_graph:
                self.call_graph[callee_func] = []

            self.call_graph[callee_func].append({
                "function": caller_func,
                "file": caller_file,
                "line": caller_line,
            })

        logger.info("反向调用图已构建: %d 个被调用函数", len(self.call_graph))

    def _trace_back(self, start_func: str, start_file: str, max_depth: int = 5) -> List[str]:
        """
        从起始函数反向追踪调用链。

        :param start_func: 起始函数名（如路由 API 所在函数）。
        :param start_file: 起始文件路径。
        :param max_depth: 最大追踪深度。
        :returns: 调用链列表（从入口函数到起始函数）。
        """
        # BFS 反向追踪
        visited: Set[str] = set()
        queue: List[tuple[str, List[str]]] = [(start_func, [start_func])]
        longest_chain = [start_func]

        while queue and len(queue) < 1000:  # 防止无限循环
            current_func, chain = queue.pop(0)

            if current_func in visited:
                continue
            visited.add(current_func)

            # 记录最长链
            if len(chain) > len(longest_chain):
                longest_chain = chain

            # 达到最大深度
            if len(chain) >= max_depth:
                continue

            # 查找调用当前函数的函数
            callers = self.call_graph.get(current_func, [])

            for caller in callers:
                caller_func = caller["function"]

                # 避免循环
                if caller_func in chain:
                    continue

                # 继续追踪
                new_chain = [caller_func] + chain
                queue.append((caller_func, new_chain))

        # 返回最长链（反转后，入口 -> 出口）
        return longest_chain[::-1]
