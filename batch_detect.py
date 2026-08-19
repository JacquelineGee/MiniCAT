"""
batch_detect.py - 批量检测微信小程序 CPRF 漏洞

使用 MiniCAT 污点追踪方法批量检测多个小程序
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import List, Dict
from main import MiniCATDetector

# 配置日志 - 只记录到文件，不输出到终端
logging.basicConfig(
    level=logging.WARNING,  # 终端只显示警告和错误
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('batch_detector.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)


class BatchDetector:
    """批量检测器"""

    def __init__(self, source_root: str, output_root: str):
        self.source_root = os.path.abspath(source_root)
        self.output_root = os.path.abspath(output_root)
        os.makedirs(self.output_root, exist_ok=True)

    def find_miniapps(self) -> List[str]:
        """
        查找所有小程序目录

        返回: 小程序目录列表
        """
        miniapps = []

        # 查找所有包含 app.json 或 .wxapkg 的目录
        for root, dirs, files in os.walk(self.source_root):
            # 包含 app.json 的目录（已解包）
            if 'app.json' in files:
                miniapps.append(root)
            # 包含 .wxapkg 文件的目录（未解包）
            elif any(f.endswith('.wxapkg') for f in files):
                miniapps.append(root)

        print(f"找到 {len(miniapps)} 个小程序")
        return miniapps

    def detect_all(self):
        """批量检测所有小程序"""
        miniapps = self.find_miniapps()

        if not miniapps:
            print("未找到任何小程序")
            return

        results = {
            'total': len(miniapps),
            'success': 0,
            'failed': 0,
            'vulnerabilities': 0,
            'details': []
        }

        print(f"\n开始批量检测...")
        print("=" * 60)

        for idx, miniapp_dir in enumerate(miniapps, 1):
            app_id = os.path.basename(miniapp_dir)

            # 简洁的进度显示
            print(f"[{idx}/{len(miniapps)}] {app_id} ... ", end='', flush=True)

            output_dir = os.path.join(self.output_root, app_id)

            try:
                detector = MiniCATDetector(miniapp_dir, output_dir, quiet=True)
                success = detector.detect()

                if success:
                    results['success'] += 1

                    # 读取漏洞结果
                    vuln_file = os.path.join(output_dir, f"{app_id}_vulnerabilities.json")
                    if os.path.exists(vuln_file):
                        with open(vuln_file, 'r', encoding='utf-8') as f:
                            vulns = json.load(f)
                            vuln_count = len(vulns)
                            results['vulnerabilities'] += vuln_count

                            results['details'].append({
                                'app_id': app_id,
                                'status': 'success',
                                'vulnerabilities': vuln_count
                            })

                            # 终端显示结果
                            if vuln_count > 0:
                                print(f"✓ 发现 {vuln_count} 个漏洞")
                            else:
                                print(f"✓ 无漏洞")
                    else:
                        results['details'].append({
                            'app_id': app_id,
                            'status': 'success',
                            'vulnerabilities': 0
                        })
                        print(f"✓ 无漏洞")
                else:
                    results['failed'] += 1
                    results['details'].append({
                        'app_id': app_id,
                        'status': 'failed',
                        'vulnerabilities': 0
                    })
                    print(f"✗ 检测失败")

            except Exception as e:
                logger.error(f"检测异常 [{app_id}]: {e}")
                results['failed'] += 1
                results['details'].append({
                    'app_id': app_id,
                    'status': 'error',
                    'error': str(e),
                    'vulnerabilities': 0
                })
                print(f"✗ 异常")

        # 保存批量结果
        self._save_summary(results)

    def _save_summary(self, results: Dict):
        """保存汇总结果"""
        summary_file = os.path.join(self.output_root, 'batch_summary.json')

        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        # 生成 Markdown 报告
        report_file = os.path.join(self.output_root, 'batch_report.md')

        # 统计有漏洞的小程序
        vuln_apps = [d for d in results['details'] if d.get('vulnerabilities', 0) > 0]
        vuln_apps_sorted = sorted(vuln_apps, key=lambda x: x['vulnerabilities'], reverse=True)

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# MiniCAT 批量检测报告\n\n")

            f.write("## 检测汇总\n\n")
            f.write(f"- **扫描小程序总数**: {results['total']}\n")
            f.write(f"- **检测成功**: {results['success']}\n")
            f.write(f"- **检测失败**: {results['failed']}\n")
            f.write(f"- **发现 CPRF 漏洞的小程序数**: {len(vuln_apps)}\n")
            f.write(f"- **漏洞总数**: {results['vulnerabilities']}\n\n")

            # 有漏洞的小程序列表（表格）
            if vuln_apps_sorted:
                f.write(f"## 存在 CPRF 漏洞的小程序 ({len(vuln_apps_sorted)})\n\n")
                f.write("| # | 小程序 ID | 漏洞数量 | 详细报告 |\n")
                f.write("|---|-----------|----------|----------|\n")
                for idx, app in enumerate(vuln_apps_sorted, 1):
                    report_path = f"{app['app_id']}/detection_report.md"
                    f.write(f"| {idx} | `{app['app_id']}` | {app['vulnerabilities']} | [查看报告]({report_path}) |\n")
                f.write("\n")

            # 无漏洞的小程序统计
            safe_apps = [d for d in results['details'] if d.get('vulnerabilities', 0) == 0 and d['status'] == 'success']
            if safe_apps:
                f.write(f"## 无漏洞的小程序 ({len(safe_apps)})\n\n")
                f.write(f"共 {len(safe_apps)} 个小程序未发现 CPRF 漏洞。\n\n")

            # 失败的小程序
            failed_apps = [d for d in results['details'] if d['status'] in ['failed', 'error']]
            if failed_apps:
                f.write(f"## 检测失败的小程序 ({len(failed_apps)})\n\n")
                f.write("| # | 小程序 ID | 错误信息 |\n")
                f.write("|---|-----------|----------|\n")
                for idx, app in enumerate(failed_apps, 1):
                    error_msg = app.get('error', '未知错误')
                    f.write(f"| {idx} | `{app['app_id']}` | {error_msg} |\n")
                f.write("\n")

        # 终端显示汇总
        print("=" * 60)
        print(f"\n批量检测完成！\n")
        print(f"扫描小程序总数: {results['total']}")
        print(f"检测成功: {results['success']}")
        print(f"检测失败: {results['failed']}")
        print(f"发现 CPRF 漏洞的小程序: {len(vuln_apps)} 个")
        print(f"漏洞总数: {results['vulnerabilities']} 个")
        print(f"\n详细报告: {report_file}")
        print(f"汇总数据: {summary_file}\n")


def main():
    if len(sys.argv) < 2:
        print("用法: python batch_detect.py <小程序根目录> [输出目录]")
        print("示例: python batch_detect.py ./unpacked ./batch_output")
        sys.exit(1)

    source_root = sys.argv[1]
    output_root = sys.argv[2] if len(sys.argv) > 2 else 'batch_output'

    detector = BatchDetector(source_root, output_root)
    detector.detect_all()


if __name__ == '__main__':
    main()
