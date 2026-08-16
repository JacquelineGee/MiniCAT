"""
main.py — MiniCAT Detector 主入口。

用法:
    python main.py --source <小程序源码目录> [--output <输出目录>] [--config <配置文件>]
"""

import argparse
import json
import logging
import os
import sys

import yaml

from preprocessing.app_parser import AppParser
from preprocessing.page_index import PageIndexBuilder
from preprocessing.wxml_converter import WxmlConverter
from codeql.database import CodeQLDatabase
from codeql.run_query import QueryRunner
from analyzer.route_analyzer import RouteAnalyzer
from analyzer.event_recovery import EventRecovery
from analyzer.trigger_linker import TriggerLinker
from analyzer.state_checker import StateChecker
from analyzer.share_checker import ShareChecker
from analyzer.attack_path_builder import AttackPathBuilder
from analyzer.report_generator import ReportGenerator


def setup_logging(level: str, log_file: str) -> None:
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
    )


def load_config(config_path: str) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def save_json(data: dict | list, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="MiniCAT Detector — 微信小程序 CPRF 静态检测器")
    parser.add_argument("--source", required=True, help="小程序源码根目录（含 app.json）")
    parser.add_argument("--output", default="output", help="输出目录（默认 output/）")
    parser.add_argument("--config", default="config/config.yaml", help="配置文件路径")
    args = parser.parse_args()

    cfg = load_config(args.config)

    log_cfg = cfg.get("logging", {})
    log_file = os.path.join(args.output, "detector.log")
    setup_logging(log_cfg.get("level", "INFO"), log_file)

    logger = logging.getLogger("main")
    logger.info("=== MiniCAT Detector 启动 ===")
    logger.info("源码目录: %s", os.path.abspath(args.source))

    # ------------------------------------------------------------------ #
    # Step 1: app.json 解析                                                #
    # ------------------------------------------------------------------ #
    logger.info("[Step 1] 解析 app.json ...")
    app_parser = AppParser(args.source)
    pages = app_parser.parse()
    logger.info("发现页面: %d 个", len(pages))

    # ------------------------------------------------------------------ #
    # Step 1: 页面索引构建                                                 #
    # ------------------------------------------------------------------ #
    logger.info("[Step 1] 构建页面索引 ...")
    builder = PageIndexBuilder(args.source)
    page_index = builder.build(pages)

    index_output = os.path.join(args.output, "page_index.json")
    save_json(page_index, index_output)
    logger.info("页面索引已保存: %s", index_output)

    # ------------------------------------------------------------------ #
    # Step 2: WXML 转换                                                  #
    # ------------------------------------------------------------------ #
    logger.info("[Step 2] 转换 WXML → HTML ...")
    transformer_cfg = cfg.get("transformer", {})
    converter = WxmlConverter(
        miniapp_root=args.source,
        transformer_script=transformer_cfg.get("script_path", "transformer/convert.js"),
        node_path=transformer_cfg.get("node_path", "node"),
    )
    page_index = converter.convert_all(page_index)

    # 保存更新后的 page_index（包含 HTML 路径）
    save_json(page_index, index_output)
    logger.info("页面索引已更新（含 HTML）: %s", index_output)

    # ------------------------------------------------------------------ #
    # Step 3: 创建 CodeQL 数据库                                          #
    # ------------------------------------------------------------------ #
    logger.info("[Step 3] 创建 CodeQL 数据库 ...")
    codeql_cfg = cfg.get("codeql", {})
    db_dir = os.path.join(args.output, codeql_cfg.get("database_dir", "codeql-db"))

    codeql_db = CodeQLDatabase(
        source_dir=args.source,
        db_dir=db_dir,
        codeql_path=codeql_cfg.get("cli_path", "codeql"),
    )

    db_created = codeql_db.create(overwrite=False)
    if not db_created:
        logger.error("CodeQL 数据库创建失败，终止")
        sys.exit(1)

    logger.info("CodeQL 数据库路径: %s", db_dir)

    # ------------------------------------------------------------------ #
    # Step 4: 执行 RouteAPI 查询                                          #
    # ------------------------------------------------------------------ #
    logger.info("[Step 4] 执行 RouteAPI 查询 ...")
    query_runner = QueryRunner(db_dir, codeql_cfg.get("cli_path", "codeql"))
    route_query_path = os.path.join("codeql", "queries", "RouteAPI.ql")

    route_results = query_runner.run(route_query_path)
    logger.info("RouteAPI 查询返回 %d 条结果", len(route_results))

    # 分析路由结果
    route_analyzer = RouteAnalyzer()
    routes = route_analyzer.analyze(route_results)

    # 保存路由分析结果
    routes_output = os.path.join(args.output, "routes.json")
    save_json(routes, routes_output)
    logger.info("路由分析结果已保存: %s", routes_output)

    # ------------------------------------------------------------------ #
    # Step 5: Event Recovery (反向污点分析)                               #
    # ------------------------------------------------------------------ #
    logger.info("[Step 5] 执行 CallGraph 查询并恢复事件链 ...")
    call_graph_query_path = os.path.join("codeql", "queries", "CallGraph.ql")

    call_graph_results = query_runner.run(call_graph_query_path)
    logger.info("CallGraph 查询返回 %d 条结果", len(call_graph_results))

    # 恢复事件链
    event_recovery = EventRecovery()
    event_chains = event_recovery.recover(routes, call_graph_results)

    # 保存事件链结果
    events_output = os.path.join(args.output, "event_chains.json")
    save_json(event_chains, events_output)
    logger.info("事件链已保存: %s", events_output)

    # ------------------------------------------------------------------ #
    # Step 6: WXML 触发器分析 + 关联                                      #
    # ------------------------------------------------------------------ #
    logger.info("[Step 6] 执行 WXMLTrigger 查询并关联触发链 ...")
    wxml_query_path = os.path.join("codeql", "queries", "WXMLTrigger.ql")

    wxml_triggers = query_runner.run(wxml_query_path)
    logger.info("WXMLTrigger 查询返回 %d 条结果", len(wxml_triggers))

    # 关联 WXML 触发器、事件链、路由
    trigger_linker = TriggerLinker()
    trigger_chains = trigger_linker.link(wxml_triggers, event_chains, routes)

    # 保存触发链
    triggers_output = os.path.join(args.output, "trigger_chains.json")
    save_json(trigger_chains, triggers_output)
    logger.info("触发链已保存: %s", triggers_output)

    # ------------------------------------------------------------------ #
    # Step 7: 用户状态检查分析                                            #
    # ------------------------------------------------------------------ #
    logger.info("[Step 7] 执行 UserState 查询并分析用户状态检查 ...")
    user_state_query_path = os.path.join("codeql", "queries", "UserState.ql")

    user_state_results = query_runner.run(user_state_query_path)
    logger.info("UserState 查询返回 %d 条结果", len(user_state_results))

    # 分析用户状态检查
    state_checker = StateChecker()
    state_checks = state_checker.analyze(user_state_results)

    # 保存状态检查结果
    state_output = os.path.join(args.output, "user_state_checks.json")
    save_json(state_checks, state_output)
    logger.info("用户状态检查已保存: %s", state_output)

    # 标记触发链中缺少用户验证的路由
    vulnerable_chains = []
    for chain in trigger_chains:
        route_target = chain.get("route_target")
        if route_target and not state_checker.check_page_has_user_state(route_target):
            vulnerable_chain = chain.copy()
            vulnerable_chain["missing_user_check"] = True
            vulnerable_chains.append(vulnerable_chain)

    logger.info("发现 %d 条触发链的目标页面缺少用户状态检查", len(vulnerable_chains))

    # 保存潜在漏洞触发链
    vulnerable_output = os.path.join(args.output, "vulnerable_chains.json")
    save_json(vulnerable_chains, vulnerable_output)
    logger.info("潜在漏洞触发链已保存: %s", vulnerable_output)

    # 输出统计信息
    stats = state_checker.get_statistics()
    logger.info("用户状态检查统计: %s", stats)

    # ------------------------------------------------------------------ #
    # Step 8: 分享功能检查分析                                            #
    # ------------------------------------------------------------------ #
    logger.info("[Step 8] 执行 ShareCheck 查询并分析分享功能 ...")
    share_check_query_path = os.path.join("codeql", "queries", "ShareCheck.ql")

    share_check_results = query_runner.run(share_check_query_path)
    logger.info("ShareCheck 查询返回 %d 条结果", len(share_check_results))

    # 分析分享功能
    share_checker = ShareChecker()
    share_info = share_checker.analyze(share_check_results)

    # 保存分享功能分析结果
    share_output = os.path.join(args.output, "share_info.json")
    save_json(share_info, share_output)
    logger.info("分享功能分析已保存: %s", share_output)

    # 增强漏洞链分析：同时标记目标页面是否可分享
    cprf_vulnerable_chains = []
    for chain in vulnerable_chains:
        route_target = chain.get("route_target")
        if route_target:
            is_shareable = share_checker.is_page_shareable(route_target)
            share_config = share_checker.get_page_share_info(route_target)

            # 如果目标页面既缺少用户验证，又支持分享，则为高风险 CPRF 漏洞
            if is_shareable:
                cprf_chain = chain.copy()
                cprf_chain["target_shareable"] = True
                cprf_chain["share_title"] = share_config.get("share_title")
                cprf_chain["share_path"] = share_config.get("share_path")
                cprf_chain["cprf_risk"] = "high"  # 高风险：可分享 + 无用户验证
                cprf_vulnerable_chains.append(cprf_chain)

    logger.info(
        "发现 %d 条高风险 CPRF 触发链（目标页面可分享且缺少用户验证）",
        len(cprf_vulnerable_chains)
    )

    # 保存高风险 CPRF 漏洞链
    cprf_output = os.path.join(args.output, "cprf_vulnerable_chains.json")
    save_json(cprf_vulnerable_chains, cprf_output)
    logger.info("高风险 CPRF 漏洞链已保存: %s", cprf_output)

    # 输出分享功能统计信息
    share_stats = share_checker.get_statistics()
    logger.info("分享功能统计: %s", share_stats)

    # ------------------------------------------------------------------ #
    # Step 9: 攻击路径构建                                               #
    # ------------------------------------------------------------------ #
    logger.info("[Step 9] 构建完整攻击路径 ...")

    # 构建攻击路径
    path_builder = AttackPathBuilder()
    attack_paths = path_builder.build(trigger_chains, state_checks, share_info)

    # 保存所有攻击路径
    attack_paths_output = os.path.join(args.output, "attack_paths.json")
    save_json(attack_paths, attack_paths_output)
    logger.info("攻击路径已保存: %s", attack_paths_output)

    # 保存漏洞路径（high + medium 风险）
    vulnerable_paths = path_builder.get_vulnerable_paths()
    vulnerable_paths_output = os.path.join(args.output, "vulnerable_attack_paths.json")
    save_json(vulnerable_paths, vulnerable_paths_output)
    logger.info("漏洞攻击路径已保存: %s", vulnerable_paths_output)

    # 保存高风险 CPRF 路径
    cprf_paths = path_builder.get_high_risk_paths()
    cprf_paths_output = os.path.join(args.output, "cprf_attack_paths.json")
    save_json(cprf_paths, cprf_paths_output)
    logger.info("CPRF 攻击路径已保存: %s", cprf_paths_output)

    # 输出攻击路径统计信息
    path_stats = path_builder.get_statistics()
    logger.info("攻击路径统计: %s", path_stats)

    # 计算路由类型统计
    route_types = {}
    for r in routes:
        rtype = r.get('type', 'unknown')
        route_types[rtype] = route_types.get(rtype, 0) + 1

    # ------------------------------------------------------------------ #
    # Step 10: 生成检测报告                                              #
    # ------------------------------------------------------------------ #
    logger.info("[Step 10] 生成检测报告 ...")

    # 生成 Markdown 检测报告
    report_generator = ReportGenerator(args.output)
    report_path = report_generator.generate(
        miniapp_path=args.source,
        page_count=len(pages),
        routes=routes,
        event_chains=event_chains,
        trigger_chains=trigger_chains,
        state_checks=state_checks,
        share_info=share_info,
        attack_paths=attack_paths,
        vulnerable_paths=vulnerable_paths,
        cprf_paths=cprf_paths,
        route_stats=route_types,
        state_stats=stats,
        share_stats=share_stats,
        path_stats=path_stats,
    )

    logger.info("检测报告已生成: %s", report_path)

    # ------------------------------------------------------------------ #
    # 所有步骤完成                                                       #
    # ------------------------------------------------------------------ #
    logger.info("=== Step 1-10 全部完成 ===")

    print(f"\n{'='*60}")
    print(f"{'MiniCAT Detector 检测完成':^60}")
    print(f"{'='*60}")
    print(f"\n输出文件:")
    print(f"  - 页面索引: {index_output}")
    print(f"  - CodeQL 数据库: {db_dir}")
    print(f"  - 路由分析: {routes_output}")
    print(f"  - 事件链: {events_output}")
    print(f"  - 触发链: {triggers_output}")
    print(f"  - 用户状态检查: {state_output}")
    print(f"  - 分享功能: {share_output}")
    print(f"  - 攻击路径: {attack_paths_output}")
    print(f"  - 漏洞路径: {vulnerable_paths_output}")
    print(f"  - CPRF 路径: {cprf_paths_output}")
    print(f"  - [报告] 检测报告: {report_path}")

    html_count = sum(1 for v in page_index.values() if v.get('html'))
    print(f"\n检测统计:")
    print(f"  - 发现 {len(pages)} 个页面，HTML 已转换 {html_count} 个")
    print(f"  - 发现 {len(routes)} 条路由 API 调用")
    print(f"  - 恢复 {len(event_chains)} 条事件链")
    print(f"  - 识别 {len(trigger_chains)} 条用户触发链")
    print(f"  - 构建 {len(attack_paths)} 条完整攻击路径")
    print(f"  - 发现 {len(state_checks)} 个页面有用户状态检查")

    print(f"\n漏洞发现:")
    print(f"  - [HIGH] 高风险 CPRF 漏洞: {len(cprf_paths)} 条")
    print(f"  - [MEDIUM] 中风险漏洞: {len(vulnerable_paths) - len(cprf_paths)} 条")
    print(f"  - [总计] 总漏洞路径: {len(vulnerable_paths)} 条")

    print(f"\n路由类型分布:")
    for rtype, count in sorted(route_types.items()):
        print(f"  - {rtype}: {count}")

    if stats:
        print(f"\n用户状态检查统计:")
        print(f"  - 有状态检查的页面: {stats['total_pages_with_checks']}")
        print(f"  - 总检查次数: {stats['total_checks']}")
        if stats.get('check_type_distribution'):
            print(f"  - 检查类型分布:")
            for check_type, count in sorted(stats['check_type_distribution'].items()):
                print(f"    * {check_type}: {count}")

    if share_stats:
        print(f"\n分享功能统计:")
        print(f"  - 总页面数: {share_stats['total_pages']}")
        print(f"  - 可分享页面: {share_stats['shareable_pages']}")
        print(f"  - 不可分享页面: {share_stats['non_shareable_pages']}")
        print(f"  - 自定义分享配置: {share_stats['custom_share_config']}")

    if path_stats:
        print(f"\n攻击路径统计:")
        print(f"  - 总攻击路径: {path_stats['total_attack_paths']}")
        print(f"  - 漏洞路径: {path_stats['vulnerable_paths']}")
        print(f"  - 高风险 CPRF: {path_stats['high_risk_cprf']}")
        if path_stats.get('risk_distribution'):
            print(f"  - 风险分布:")
            for risk_level, count in sorted(path_stats['risk_distribution'].items()):
                print(f"    * {risk_level}: {count}")

    print(f"\n{'='*60}")
    print(f"检测完成! 详细报告请查看: {report_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
