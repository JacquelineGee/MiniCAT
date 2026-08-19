"""
main.py - MiniCAT 主检测入口

使用 CodeQL 污点追踪检测微信小程序 CPRF 漏洞
"""

import os
import sys
import logging
import argparse
import subprocess
import csv
import json
from pathlib import Path
from typing import Dict, List, Tuple

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('detector.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class MiniCATDetector:
    """MiniCAT 污点追踪检测器"""

    def __init__(self, source_dir: str, output_dir: str, quiet: bool = False):
        self.source_dir = os.path.abspath(source_dir)
        self.output_dir = os.path.abspath(output_dir)
        self.db_path = None
        self.app_id = os.path.basename(self.source_dir)
        self.quiet = quiet  # 静默模式，不输出格式化摘要

        # unpacked 目录（在当前工作目录下）
        self.unpacked_base = os.path.join(os.getcwd(), 'unpacked')
        os.makedirs(self.unpacked_base, exist_ok=True)

        # 创建输出目录
        os.makedirs(self.output_dir, exist_ok=True)

        # CodeQL 查询文件路径
        self.query_path = os.path.join(
            os.path.dirname(__file__),
            'codeql', 'queries', 'MiniCATTaint.ql'
        )

    def check_unpacked(self) -> Tuple[bool, str]:
        """
        检查源码是否已解包

        返回: (是否已解包, 源码目录路径)
        """
        # Step 1: 优先检查 unpacked/wx_id/ 是否已存在
        unpacked_target = os.path.join(self.unpacked_base, self.app_id)
        if os.path.exists(unpacked_target) and os.path.exists(os.path.join(unpacked_target, 'app.json')):
            logger.info(f"在 unpacked/ 目录中找到已解包源码: {unpacked_target}")
            self.source_dir = unpacked_target
            return True, unpacked_target

        # Step 2: 如果 source_dir 本身包含 app.json，说明已解包
        app_json = os.path.join(self.source_dir, 'app.json')
        if os.path.exists(app_json):
            logger.info(f"检测到已解包的小程序: {self.source_dir}")
            return True, self.source_dir

        # Step 3: 检查是否有 .wxapkg 文件
        wxapkg_files = list(Path(self.source_dir).rglob('*.wxapkg'))
        if wxapkg_files:
            logger.info(f"检测到 {len(wxapkg_files)} 个 .wxapkg 文件，开始解包...")
            unpacked_dir = self._unpack_wxapkg(wxapkg_files[0])
            if unpacked_dir and os.path.exists(os.path.join(unpacked_dir, 'app.json')):
                self.source_dir = unpacked_dir
                return True, unpacked_dir
            else:
                logger.error("解包失败")
                return False, ""

        logger.error(f"未找到 app.json 或 .wxapkg 文件: {self.source_dir}")
        return False, ""

    def _unpack_wxapkg(self, wxapkg_path: Path) -> str:
        """
        解包 .wxapkg 文件到 unpacked/wx_id/ 目录

        返回: 解包后的目录路径
        """
        try:
            import shutil

            # 目标解包目录: unpacked/wx_id/
            unpacked_target = os.path.join(self.unpacked_base, self.app_id)

            # 如果目标目录已存在，先删除
            if os.path.exists(unpacked_target):
                shutil.rmtree(unpacked_target)

            # 使用 wedecode 解包到临时目录
            temp_output = os.path.join(os.path.dirname(str(wxapkg_path)), '_temp_unpack')
            if os.path.exists(temp_output):
                shutil.rmtree(temp_output)
            os.makedirs(temp_output, exist_ok=True)

            # wedecode 命令格式: wedecode <wxapkg> --out <dir> --clear
            cmd = f'wedecode "{str(wxapkg_path)}" --out "{temp_output}" --clear'

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                shell=True,
                encoding='utf-8',
                errors='ignore'
            )

            if result.returncode == 0:
                # 查找包含 app.json 的目录
                unpacked_dir = self._find_app_json_dir(temp_output)
                if unpacked_dir:
                    # 移动到 unpacked/wx_id/
                    shutil.move(unpacked_dir, unpacked_target)

                    # 清理临时目录
                    if os.path.exists(temp_output):
                        shutil.rmtree(temp_output)

                    logger.info(f"解包成功: {unpacked_target}")
                    return unpacked_target

            logger.error(f"解包失败: {result.stderr}")
            return ""
        except Exception as e:
            logger.error(f"解包异常: {e}")
            return ""

    def _find_app_json_dir(self, root_dir: str) -> str:
        """在解包目录中查找包含 app.json 的目录"""
        # 检查根目录
        if os.path.exists(os.path.join(root_dir, "app.json")):
            return root_dir

        # 检查子目录（最多2层）
        for item in os.listdir(root_dir):
            item_path = os.path.join(root_dir, item)
            if os.path.isdir(item_path):
                if os.path.exists(os.path.join(item_path, "app.json")):
                    return item_path

                # 递归查找
                for subitem in os.listdir(item_path):
                    subitem_path = os.path.join(item_path, subitem)
                    if os.path.isdir(subitem_path):
                        if os.path.exists(os.path.join(subitem_path, "app.json")):
                            return subitem_path

        return ""

    def rename_wxml_to_html(self) -> int:
        """将所有 .wxml 文件重命名为 .html，返回转换数量"""
        logger.info("重命名 .wxml 文件为 .html...")
        count = 0
        for root, dirs, files in os.walk(self.source_dir):
            for file in files:
                if file.endswith('.wxml'):
                    wxml_path = os.path.join(root, file)
                    html_path = wxml_path.replace('.wxml', '.html')
                    if not os.path.exists(html_path):
                        os.rename(wxml_path, html_path)
                        count += 1
        logger.info(f"重命名了 {count} 个 .wxml 文件")
        return count

    def create_codeql_database(self):
        """创建 CodeQL 数据库"""
        import shutil
        self.db_path = os.path.join(self.output_dir, f"{self.app_id}_db")

        if os.path.exists(self.db_path):
            # 验证数据库是否有效
            logger.info(f"CodeQL 数据库已存在: {self.db_path}")
            verify_cmd = ['codeql', 'database', 'upgrade', self.db_path]
            try:
                result = subprocess.run(
                    verify_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    logger.info("数据库验证通过")
                    return True
                else:
                    logger.warning(f"数据库无效，将重新创建: {result.stderr}")
                    shutil.rmtree(self.db_path)
            except Exception as e:
                logger.warning(f"数据库验证失败，将重新创建: {e}")
                shutil.rmtree(self.db_path)

        logger.info("创建 CodeQL 数据库...")
        cmd = [
            'codeql', 'database', 'create',
            self.db_path,
            '--language=javascript',
            '--threads=4'
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=self.source_dir,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.returncode == 0:
                logger.info("CodeQL 数据库创建成功")
                return True
            else:
                logger.error(f"CodeQL 数据库创建失败: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"创建 CodeQL 数据库时出错: {e}")
            return False

    def run_taint_query(self):
        """运行污点追踪查询"""
        logger.info("运行污点追踪查询...")

        if not os.path.exists(self.query_path):
            logger.error(f"查询文件不存在: {self.query_path}")
            return False

        bqrs_path = os.path.join(self.output_dir, f"{self.app_id}_taint.bqrs")

        cmd = [
            'codeql', 'query', 'run',
            '--database', self.db_path,
            '--output', bqrs_path,
            self.query_path
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if result.returncode == 0:
                logger.info("污点追踪查询完成")
                return bqrs_path
            else:
                logger.error(f"查询失败: {result.stderr}")
                return None
        except Exception as e:
            logger.error(f"运行查询时出错: {e}")
            return None

    def decode_bqrs(self, bqrs_path: str, csv_path: str, predicate: str):
        """解码 BQRS 文件为 CSV"""
        logger.info(f"解码 {predicate} 结果...")

        cmd = [
            'codeql', 'bqrs', 'decode',
            '--format=csv',
            f'--result-set={predicate}',
            '--output', csv_path,
            bqrs_path
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                logger.info(f"解码成功: {csv_path}")
                return True
            else:
                logger.error(f"解码失败: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"解码时出错: {e}")
            return False

    def check_share_method(self, file_path: str) -> bool:
        """检查文件是否包含 onShareAppMessage 方法"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                return b'onShareAppMessage' in content
        except Exception as e:
            logger.debug(f"读取文件失败 {file_path}: {e}")
            return False

    def has_any_share_method(self) -> bool:
        """检查整个小程序是否有任何页面包含 onShareAppMessage 方法"""
        try:
            # 优先检查 pages 目录（大部分分享功能在这里）
            pages_dir = os.path.join(self.source_dir, 'pages')
            if os.path.exists(pages_dir):
                for root, dirs, files in os.walk(pages_dir):
                    for file in files:
                        if file.endswith('.js'):
                            file_path = os.path.join(root, file)
                            if self.check_share_method(file_path):
                                logger.info(f"发现分享功能: {file_path}")
                                return True

            # 如果 pages 目录没找到，再搜索整个小程序
            for root, dirs, files in os.walk(self.source_dir):
                # 跳过 node_modules 和其他不相关目录
                dirs[:] = [d for d in dirs if d not in ['node_modules', 'miniprogram_npm', '__MACOSX']]

                for file in files:
                    if file.endswith('.js'):
                        file_path = os.path.join(root, file)
                        if self.check_share_method(file_path):
                            logger.info(f"发现分享功能: {file_path}")
                            return True
            return False
        except Exception as e:
            logger.error(f"检查分享功能时出错: {e}")
            return False

    def process_results(self, csv_path: str) -> Tuple[List[Dict], List[Dict]]:
        """
        处理查询结果

        返回: (所有数据流, 可利用的漏洞)
        """
        logger.info("处理查询结果...")

        all_flows = []
        vulnerabilities = []

        # 先检查整个小程序是否有任何页面有分享功能
        has_share = self.has_any_share_method()

        if has_share:
            logger.info("检测到小程序有分享功能，所有数据流都是可利用的")
        else:
            logger.info("小程序没有分享功能，数据流无法通过分享链接利用")

        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    sink_loc = row.get('sink_loc', '')
                    source_loc = row.get('source_loc', '')
                    source_func = row.get('source_func', '')
                    block_name = row.get('block_name', '')

                    # 从 sink_loc 提取文件路径
                    if '|' in sink_loc:
                        csv_file_path = sink_loc.split('|')[0]

                        flow_data = {
                            'file': csv_file_path,
                            'sink': sink_loc,
                            'source': source_loc,
                            'function': source_func,
                            'block': block_name
                        }

                        all_flows.append(flow_data)

                        # 如果小程序有任何页面有分享功能，则所有数据流都是可利用的
                        if has_share:
                            flow_data['has_share'] = True
                            vulnerabilities.append(flow_data)
                            logger.debug(f"发现可利用数据流: {os.path.basename(csv_file_path)} (函数: {source_func})")

        except Exception as e:
            logger.error(f"处理结果时出错: {e}")

        if vulnerabilities:
            logger.info(f"发现 {len(vulnerabilities)} 个可利用漏洞")

        return all_flows, vulnerabilities

    def generate_report(self, all_flows: List[Dict], vulnerabilities: List[Dict]):
        """生成检测报告"""
        logger.info("生成检测报告...")

        report_path = os.path.join(self.output_dir, 'detection_report.md')

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"# MiniCAT 检测报告\n\n")
            f.write(f"## 小程序信息\n\n")
            f.write(f"- **AppID**: {self.app_id}\n")
            f.write(f"- **检测时间**: {self._get_timestamp()}\n\n")

            f.write(f"## 检测结果\n\n")
            f.write(f"- **数据流总数**: {len(all_flows)}\n")
            f.write(f"- **MiniCPRF 漏洞数**: {len(vulnerabilities)}\n\n")

            if vulnerabilities:
                f.write(f"## 漏洞页面列表\n\n")

                # 按页面分组
                page_vulns = {}
                for vuln in vulnerabilities:
                    # 提取页面路径：从完整路径中提取 pages/xxx/yyy
                    file_path = vuln['file']
                    if 'pages/' in file_path or 'Pages/' in file_path:
                        # 提取 pages/xxx/yyy 部分
                        parts = file_path.replace('\\', '/').split('/')
                        try:
                            pages_idx = parts.index('pages') if 'pages' in parts else parts.index('Pages')
                            # pages/xxx/yyy.js -> pages/xxx/yyy
                            page_path = '/'.join(parts[pages_idx:pages_idx+3]).replace('.js', '')
                        except (ValueError, IndexError):
                            page_path = os.path.basename(file_path).replace('.js', '')
                    else:
                        page_path = os.path.basename(file_path).replace('.js', '')

                    if page_path not in page_vulns:
                        page_vulns[page_path] = []
                    page_vulns[page_path].append(vuln)

                # 输出每个页面的漏洞
                for idx, (page_path, vulns) in enumerate(page_vulns.items(), 1):
                    f.write(f"### {idx}. `{page_path}`\n\n")
                    f.write(f"- **漏洞类型**: MiniCPRF (Cross-Page Request Forgery)\n")
                    f.write(f"- **数据流数量**: {len(vulns)}\n")
                    f.write(f"- **触发方式**: 页面加载时自动触发 (`onLoad` 函数接收 URL 参数)\n\n")

                    # 显示使用的 URL 参数（从 source 中提取）
                    params = set()
                    for vuln in vulns:
                        source = vuln.get('source', '')
                        # 简单提取，实际可能需要更复杂的解析
                        if 'onLoad' in vuln.get('function', ''):
                            params.add('URL 参数')

                    if params:
                        f.write(f"- **危险参数**: {', '.join(params)}\n\n")

            else:
                f.write(f"未发现 MiniCPRF 漏洞。\n\n")

        logger.info(f"检测报告已生成: {report_path}")

    def _get_timestamp(self):
        """获取当前时间戳"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def count_pages(self) -> int:
        """统计页面数量（.js 文件）"""
        count = 0
        for root, dirs, files in os.walk(self.source_dir):
            for f in files:
                if f.endswith('.js'):
                    count += 1
        return count

    def count_share_pages(self) -> Tuple[int, int]:
        """统计可分享页面数，返回 (可分享数, 总页面数)"""
        total = 0
        shareable = 0
        for root, dirs, files in os.walk(self.source_dir):
            for f in files:
                if f.endswith('.js'):
                    total += 1
                    file_path = os.path.join(root, f)
                    if self.check_share_method(file_path):
                        shareable += 1
        return shareable, total

    def detect(self):
        """执行完整检测流程"""
        logger.info("="*60)
        logger.info(f"MiniCAT 检测器启动")
        logger.info("="*60)

        # Step 0: 检查是否需要解包
        is_unpacked, unpacked_dir = self.check_unpacked()
        if not is_unpacked:
            logger.error("检测终止：源码未解包")
            return False

        logger.info(f"检测目标: {self.app_id}")
        logger.info(f"源码目录: {self.source_dir}")

        # Step 1: 重命名 wxml 为 html
        html_count = self.rename_wxml_to_html()

        # Step 2: 创建 CodeQL 数据库
        if not self.create_codeql_database():
            return False

        # Step 3: 运行污点追踪查询
        bqrs_path = self.run_taint_query()
        if not bqrs_path:
            return False

        # Step 4: 解码结果 (两个谓词: pure_get_func 和 get_func)
        aux_csv = os.path.join(self.output_dir, f"{self.app_id}_aux.csv")
        main_csv = os.path.join(self.output_dir, f"{self.app_id}_main.csv")

        if not self.decode_bqrs(bqrs_path, aux_csv, 'pure_get_func'):
            return False
        if not self.decode_bqrs(bqrs_path, main_csv, 'get_func'):
            return False

        # Step 5: 处理结果 (使用 aux_csv,因为它的函数名更准确)
        all_flows, vulnerabilities = self.process_results(aux_csv)

        # 保存 JSON 结果
        flows_file = os.path.join(self.output_dir, f"{self.app_id}_all_flows.json")
        with open(flows_file, 'w', encoding='utf-8') as f:
            json.dump(all_flows, f, indent=2, ensure_ascii=False)

        vuln_file = os.path.join(self.output_dir, f"{self.app_id}_vulnerabilities.json")
        with open(vuln_file, 'w', encoding='utf-8') as f:
            json.dump(vulnerabilities, f, indent=2, ensure_ascii=False)

        # Step 6: 生成报告
        self.generate_report(all_flows, vulnerabilities)

        # Step 7: 统计分享功能
        shareable, total_pages = self.count_share_pages()

        # 函数分布
        func_dist = {}
        for flow in all_flows:
            func = flow['function']
            func_dist[func] = func_dist.get(func, 0) + 1

        # 文件分布
        file_dist = {}
        for flow in all_flows:
            fname = os.path.basename(flow['file'])
            file_dist[fname] = file_dist.get(fname, 0) + 1

        # 打印格式化结果（非静默模式）
        if not self.quiet:
            self._print_summary(
                html_count=html_count,
                all_flows=all_flows,
                vulnerabilities=vulnerabilities,
                total_pages=total_pages,
                shareable=shareable,
                func_dist=func_dist,
                file_dist=file_dist
            )

        return True

    def _print_summary(self, html_count, all_flows, vulnerabilities,
                       total_pages, shareable, func_dist, file_dist):
        """打印格式化的检测结果摘要"""
        sep = "=" * 60
        report_path = os.path.join(self.output_dir, 'detection_report.md')
        aux_csv = os.path.join(self.output_dir, f"{self.app_id}_aux.csv")
        main_csv = os.path.join(self.output_dir, f"{self.app_id}_main.csv")
        flows_file = os.path.join(self.output_dir, f"{self.app_id}_all_flows.json")
        vuln_file = os.path.join(self.output_dir, f"{self.app_id}_vulnerabilities.json")
        bqrs_file = os.path.join(self.output_dir, f"{self.app_id}_taint.bqrs")

        print(f"\n{sep}")
        print(f"{'MiniCAT Detector 检测完成':^60}")
        print(f"{sep}\n")

        print("输出文件:")
        print(f"  - CodeQL 数据库: {self.db_path}")
        print(f"  - 污点查询结果(BQRS): {bqrs_file}")
        print(f"  - 数据流(pure_get_func): {aux_csv}")
        print(f"  - 数据流(get_func): {main_csv}")
        print(f"  - 所有数据流(JSON): {flows_file}")
        print(f"  - 漏洞列表(JSON): {vuln_file}")
        print(f"  - [报告] 检测报告: {report_path}")

        print(f"\n检测统计:")
        print(f"  - 检测目标: {self.app_id}")
        print(f"  - 总页面数(JS文件): {total_pages}")
        print(f"  - HTML 已转换: {html_count} 个")
        print(f"  - 污点数据流: {len(all_flows)} 条")
        print(f"  - 可利用漏洞(有onShareAppMessage): {len(vulnerabilities)} 条")

        print(f"\n漏洞发现:")
        print(f"  - [HIGH] 可利用 CPRF 漏洞(可分享): {len(vulnerabilities)} 条")
        print(f"  - [总计] 总数据流: {len(all_flows)} 条")

        if vulnerabilities:
            print(f"\n漏洞详情:")
            for idx, vuln in enumerate(vulnerabilities, 1):
                print(f"  #{idx} 文件: {os.path.basename(vuln['file'])}, "
                      f"函数: {vuln['function']}")

        print(f"\n函数分布:")
        for func, count in sorted(func_dist.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {func}: {count}")

        print(f"\n文件分布:")
        for fname, count in sorted(file_dist.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {fname}: {count}")

        print(f"\n分享功能统计:")
        print(f"  - 总页面数: {total_pages}")
        print(f"  - 可分享页面: {shareable}")
        print(f"  - 不可分享页面: {total_pages - shareable}")

        print(f"\n{sep}")


def main():
    parser = argparse.ArgumentParser(description='MiniCAT - 微信小程序 CPRF 检测工具')
    parser.add_argument('--source', required=True, help='小程序源码目录或包含 .wxapkg 文件的目录')
    parser.add_argument('--output', default='output', help='输出目录 (默认: output)')

    args = parser.parse_args()

    detector = MiniCATDetector(args.source, args.output)
    success = detector.detect()

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
