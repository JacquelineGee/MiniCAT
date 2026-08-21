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

os.makedirs('logs', exist_ok=True)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/detector.log', encoding='utf-8'),
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
        """
        将所有 .wxml 文件重命名为 .html（论文 Section 4.2 Challenge II）

        论文: "As the syntax of WXML is similar to HTML, we can use a public tool
               to convert WXML files to HTML files while maintaining the raw WXML
               tags and attributes."

        返回转换数量
        """
        count = 0
        for root, dirs, files in os.walk(self.source_dir):
            for file in files:
                if file.endswith('.wxml'):
                    wxml_path = os.path.join(root, file)
                    html_path = wxml_path.replace('.wxml', '.html')
                    if not os.path.exists(html_path):
                        os.rename(wxml_path, html_path)
                        count += 1
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

    def check_user_state(self, page_file: str) -> Dict[str, bool]:
        """
        Step III: 检查用户状态实现（按照论文 Section 4.2）

        论文: "Our static analysis focuses on detecting two types of API calls
               in the onLoad page load functions"

        返回: {
            'has_check_session': bool,  # 是否检查 session 过期
            'has_get_storage': bool     # 是否读取本地存储
        }
        """
        result = {
            'has_check_session': False,
            'has_get_storage': False,
            'has_proper_check': False
        }

        try:
            with open(page_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # 检查是否有 wx.checkSession
                if 'wx.checkSession' in content or 'checkSession' in content:
                    result['has_check_session'] = True

                # 检查是否有 wx.getStorage 或 wx.getStorageSync
                if 'wx.getStorage' in content or 'getStorage' in content:
                    result['has_get_storage'] = True

                # 如果两者都有，说明有完整的用户状态检查
                result['has_proper_check'] = result['has_check_session'] and result['has_get_storage']

        except Exception as e:
            logger.debug(f"检查用户状态失败 {page_file}: {e}")

        return result

    def process_results(self, csv_path: str) -> Tuple[List[Dict], List[Dict]]:
        """
        处理逆向污点追踪结果（按照论文 Section 4.2）

        返回: (所有数据流, 可利用的漏洞)
        """
        logger.info("处理逆向污点追踪结果...")

        all_flows = []
        vulnerabilities = []

        # Step IV: 检查整个小程序是否有分享功能
        has_share = self.has_any_share_method()

        if has_share:
            pass
        else:
            pass

        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    sink_loc = row.get('sink_loc', '')
                    source_loc = row.get('source_loc', '')
                    source_func = row.get('source_func', '')
                    func_type = row.get('func_type', 'OTHER')

                    # 从 sink_loc 提取文件路径和位置信息
                    if '|' in sink_loc:
                        file_path = sink_loc.split('|')[0]
                        sink_position = sink_loc.split('|')[1] if len(sink_loc.split('|')) > 1 else ''
                    else:
                        file_path = sink_loc
                        sink_position = ''

                    # 从 source_loc 提取位置信息
                    if '|' in source_loc:
                        source_position = source_loc.split('|')[1] if len(source_loc.split('|')) > 1 else ''
                    else:
                        source_position = ''

                    flow_data = {
                        'file': file_path,
                        'sink': sink_loc,
                        'sink_position': sink_position,
                        'source': source_loc,
                        'source_position': source_position,
                        'function': source_func,
                        'func_type': func_type,
                        'is_event_handler': func_type == 'EVENT_HANDLER'
                    }

                    # Step III: 检查用户状态
                    user_state = self.check_user_state(file_path)
                    flow_data['user_state'] = user_state

                    # Step IV: 检查可分享性
                    flow_data['has_share'] = has_share

                    all_flows.append(flow_data)

                    # 判断是否为漏洞：有分享功能 = 可利用
                    if has_share:
                        vulnerabilities.append(flow_data)
                        logger.debug(f"发现漏洞: {os.path.basename(file_path)} - {source_func}")

        except Exception as e:
            logger.error(f"处理结果时出错: {e}")

        logger.info(f"检测到 {len(all_flows)} 条数据流，其中 {len(vulnerabilities)} 个可利用漏洞")

        return all_flows, vulnerabilities

    def generate_report(self, all_flows: List[Dict], vulnerabilities: List[Dict]):
        """生成检测报告（按照论文格式）"""
        report_path = os.path.join(self.output_dir, 'detection_report.md')

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"# MiniCAT 检测报告\n\n")
            f.write(f"## 小程序信息\n\n")
            f.write(f"AppID: {self.app_id}\n\n")
            f.write(f"检测时间: {self._get_timestamp()}\n\n")
            f.write(f"分析方法: 逆向污点分析\n\n")

            f.write(f"## 检测结果\n\n")
            f.write(f"数据流总数: {len(all_flows)}\n\n")
            f.write(f"MiniCPRF 漏洞数: {len(vulnerabilities)}\n\n")

            if vulnerabilities:
                f.write(f"## 漏洞详情\n\n")

                # 按页面分组
                page_vulns = {}
                for vuln in vulnerabilities:
                    file_path = vuln['file']
                    # 提取页面路径
                    if 'pages/' in file_path or 'Pages/' in file_path:
                        parts = file_path.replace('\\', '/').split('/')
                        try:
                            pages_idx = parts.index('pages') if 'pages' in parts else parts.index('Pages')
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
                    f.write(f"### {idx}. {page_path}\n\n")
                    f.write(f"漏洞类型: MiniCPRF\n\n")
                    f.write(f"数据流数量: {len(vulns)}\n\n")

                    # 显示受影响的文件
                    affected_file = os.path.basename(vulns[0]['file'])
                    f.write(f"受影响文件: {affected_file}\n\n")

                    # 显示事件处理函数
                    event_handlers = set([v['function'] for v in vulns if v.get('is_event_handler')])
                    if event_handlers:
                        f.write(f"事件处理函数: {', '.join(event_handlers)}\n\n")

                    # 显示用户状态检查情况
                    user_state = vulns[0].get('user_state', {})
                    if user_state.get('has_proper_check'):
                        f.write(f"用户状态检查: 有完整检查\n\n")
                    else:
                        f.write(f"用户状态检查: 不完整或缺失\n\n")

                    f.write(f"可分享性: 可分享\n\n")

                    # 详细数据流信息
                    f.write(f"#### 数据流详情\n\n")
                    for flow_idx, vuln in enumerate(vulns, 1):
                        f.write(f"数据流 {flow_idx}:\n\n")

                        # 污点源位置
                        source_pos = vuln.get('source_position', '')
                        if source_pos:
                            line_info = source_pos.split(':')[0] if ':' in source_pos else source_pos
                            f.write(f"- 污点源: 第 {line_info} 行, 函数 {vuln['function']}\n")
                        else:
                            f.write(f"- 污点源: 函数 {vuln['function']}\n")

                        # 污点终点（路由API）
                        sink_pos = vuln.get('sink_position', '')
                        if sink_pos:
                            line_info = sink_pos.split(':')[0] if ':' in sink_pos else sink_pos
                            f.write(f"- 路由API调用: 第 {line_info} 行\n")

                        # 检查对应的HTML文件
                        html_file = vuln['file'].replace('.js', '.html')
                        if os.path.exists(html_file):
                            f.write(f"- 对应组件: {os.path.basename(html_file)}\n")

                        f.write(f"\n")

            else:
                f.write(f"未发现 MiniCPRF 漏洞。\n\n")

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
        """执行完整检测流程（严格按照论文 Section 4.2）"""
        if not self.quiet:
            print(f"正在检测: {self.app_id}")

        # 检查是否需要解包
        is_unpacked, unpacked_dir = self.check_unpacked()
        if not is_unpacked:
            logger.error("检测终止：源码未解包")
            return False

        # 重命名 wxml 为 html（论文 Challenge II）
        html_count = self.rename_wxml_to_html()

        # 创建 CodeQL 数据库
        if not self.create_codeql_database():
            return False

        # 运行污点追踪查询
        bqrs_path = self.run_taint_query()
        if not bqrs_path:
            return False

        # 解码结果 (两个谓词: pure_get_func 和 get_func)
        aux_csv = os.path.join(self.output_dir, f"{self.app_id}_aux.csv")
        main_csv = os.path.join(self.output_dir, f"{self.app_id}_main.csv")

        if not self.decode_bqrs(bqrs_path, aux_csv, 'pure_get_func'):
            return False
        if not self.decode_bqrs(bqrs_path, main_csv, 'get_func'):
            return False

        # 优先使用 aux_csv，如果为空则使用 main_csv
        csv_to_use = aux_csv
        try:
            with open(aux_csv, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                if len(lines) <= 1:  # 只有标题行或为空
                    logger.warning("pure_get_func 结果为空，使用 get_func 结果")
                    csv_to_use = main_csv
        except Exception as e:
            logger.warning(f"读取 aux_csv 失败: {e}，使用 main_csv")
            csv_to_use = main_csv

        # Step III & IV: 处理结果（包含用户状态检查和可分享性检查）
        all_flows, vulnerabilities = self.process_results(csv_to_use)

        # 保存 JSON 结果
        flows_file = os.path.join(self.output_dir, f"{self.app_id}_all_flows.json")
        with open(flows_file, 'w', encoding='utf-8') as f:
            json.dump(all_flows, f, indent=2, ensure_ascii=False)

        vuln_file = os.path.join(self.output_dir, f"{self.app_id}_vulnerabilities.json")
        with open(vuln_file, 'w', encoding='utf-8') as f:
            json.dump(vulnerabilities, f, indent=2, ensure_ascii=False)

        # 生成报告
        self.generate_report(all_flows, vulnerabilities)

        # 统计分享功能
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
        report_path = os.path.join(self.output_dir, 'detection_report.md')

        print(f"\n检测完成: {self.app_id}")
        print(f"数据流: {len(all_flows)} 条")
        print(f"漏洞: {len(vulnerabilities)} 个")
        print(f"报告: {report_path}\n")


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
