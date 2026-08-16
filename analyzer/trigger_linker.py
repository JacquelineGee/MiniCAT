"""
trigger_linker.py — 将 WXML 触发器与事件链、路由关联。

职责：
  - 将 WXMLTrigger 查询结果与事件链匹配
  - 识别用户可直接触发的路由路径
  - 生成完整的用户触发链：WXML 事件 → 函数调用链 → 路由 API
"""

import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class TriggerLinker:
    """WXML 触发器关联分析器。"""

    def __init__(self):
        pass

    # ------------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------------

    def link(self,
             wxml_triggers: List[Dict[str, Any]],
             event_chains: List[Dict[str, Any]],
             routes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        将 WXML 触发器、事件链、路由关联起来。

        :param wxml_triggers: WXMLTrigger.ql 查询结果。
        :param event_chains: EventRecovery 返回的事件链。
        :param routes: RouteAnalyzer 返回的路由信息。
        :returns: 完整的触发链列表。
        """
        logger.info("开始关联 WXML 触发器、事件链和路由...")

        # 构建索引：函数名 -> 事件链
        chain_index = self._build_chain_index(event_chains)

        # 构建索引：route_id -> route
        route_index = {r["route_id"]: r for r in routes}

        trigger_chains = []

        for trigger in wxml_triggers:
            handler_name = trigger.get("handlerName")
            html_file = trigger.get("htmlFile")
            js_file = trigger.get("jsFile")

            # 查找对应的事件链
            matching_chains = self._find_matching_chains(handler_name, js_file, chain_index)

            for chain in matching_chains:
                route_id = chain.get("route_id")
                route_info = route_index.get(route_id)

                trigger_chains.append({
                    "trigger_id": f"trigger_{len(trigger_chains) + 1}",
                    "wxml_file": html_file,
                    "wxml_line": trigger.get("htmlLine"),
                    "wxml_tag": trigger.get("tagName"),
                    "wxml_event": trigger.get("eventType"),
                    "handler_name": handler_name,
                    "handler_file": js_file,
                    "handler_line": trigger.get("jsLine"),
                    "call_chain": chain.get("call_chain", []),
                    "route_id": route_id,
                    "route_type": route_info.get("type") if route_info else None,
                    "route_target": route_info.get("target_page") if route_info else None,
                    "route_file": route_info.get("source_file") if route_info else None,
                    "route_line": route_info.get("source_line") if route_info else None,
                })

        logger.info("触发链关联完成: 共 %d 条", len(trigger_chains))
        return trigger_chains

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _build_chain_index(self, event_chains: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        构建索引：入口函数名 -> [事件链列表]

        事件链的入口函数是 call_chain 的第一个元素。
        """
        index = {}

        for chain in event_chains:
            call_chain = chain.get("call_chain", [])
            if not call_chain:
                continue

            # 入口函数（调用链起点）
            entry_func = call_chain[0]

            if entry_func not in index:
                index[entry_func] = []

            index[entry_func].append(chain)

        logger.debug("事件链索引已构建: %d 个入口函数", len(index))
        return index

    def _find_matching_chains(self,
                              handler_name: str,
                              handler_file: str,
                              chain_index: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        查找与 WXML handler 匹配的事件链。

        匹配规则：
          1. handler_name 在事件链的 call_chain 中（任意位置）
          2. 优先匹配同文件的事件链
        """
        matching_chains = []

        # 1. 查找以 handler_name 为入口的事件链
        if handler_name in chain_index:
            matching_chains.extend(chain_index[handler_name])

        # 2. 查找 handler_name 在调用链中间或末尾的事件链
        for entry_func, chains in chain_index.items():
            for chain in chains:
                call_chain = chain.get("call_chain", [])
                if handler_name in call_chain and chain not in matching_chains:
                    # 检查文件是否匹配（同一页面）
                    route_file = chain.get("route_file", "")
                    if self._same_page(handler_file, route_file):
                        matching_chains.append(chain)

        return matching_chains

    def _same_page(self, file1: str, file2: str) -> bool:
        """
        判断两个文件是否属于同一个页面。

        例如：
          pages/index/index.html
          pages/index/index.js
        应该匹配。
        """
        if not file1 or not file2:
            return False

        # 提取页面路径前缀（去掉扩展名）
        def get_page_prefix(path: str) -> str:
            # pages/index/index.js -> pages/index/index
            if "." in path:
                return path.rsplit(".", 1)[0]
            return path

        return get_page_prefix(file1) == get_page_prefix(file2)
