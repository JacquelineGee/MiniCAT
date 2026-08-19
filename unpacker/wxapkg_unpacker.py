"""
wxapkg_unpacker.py — wxapkg 解包器

功能:
1. 检查源码目录是否已解包（是否存在 app.json）
2. 如果未解包，查找 .wxapkg 文件
3. 调用 wedecode 工具解包
4. 验证解包是否成功
"""

import logging
import os
import subprocess
import shutil
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class WxapkgUnpacker:
    """
    小程序解包器
    """

    def __init__(self, wedecode_cmd: str = "wedecode"):
        """
        初始化解包器

        参数:
            wedecode_cmd: wedecode 命令路径（默认从 PATH 中查找）
        """
        self.wedecode_cmd = wedecode_cmd

    def check_unpacked(self, source_dir: str) -> bool:
        """
        检查目录是否已解包（是否包含 app.json）

        参数:
            source_dir: 源码目录

        返回:
            bool: 是否已解包
        """
        app_json_path = os.path.join(source_dir, "app.json")
        return os.path.exists(app_json_path)

    def find_wxapkg(self, source_dir: str) -> Optional[str]:
        """
        在目录中查找 .wxapkg 文件

        参数:
            source_dir: 源码目录

        返回:
            str: wxapkg 文件路径，如果未找到则返回 None
        """
        if not os.path.exists(source_dir):
            return None

        # 查找所有 .wxapkg 文件
        wxapkg_files = []
        for file in os.listdir(source_dir):
            if file.endswith('.wxapkg'):
                wxapkg_files.append(os.path.join(source_dir, file))

        if not wxapkg_files:
            logger.warning("未找到 .wxapkg 文件: %s", source_dir)
            return None

        if len(wxapkg_files) > 1:
            logger.warning("找到多个 .wxapkg 文件，使用第一个: %s", wxapkg_files[0])

        return wxapkg_files[0]

    def check_wedecode_available(self) -> bool:
        """
        检查 wedecode 命令是否可用

        返回:
            bool: wedecode 是否可用
        """
        try:
            # 尝试使用 shell=True 来找到 wedecode（特别是在 Windows 上）
            result = subprocess.run(
                f"{self.wedecode_cmd} --version",
                capture_output=True,
                text=True,
                timeout=5,
                shell=True
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.error("wedecode 不可用: %s", e)
            return False

    def unpack(self, wxapkg_path: str, output_dir: str) -> bool:
        """
        使用 wedecode 解包 wxapkg 文件

        参数:
            wxapkg_path: wxapkg 文件路径
            output_dir: 输出目录

        返回:
            bool: 解包是否成功
        """
        if not os.path.exists(wxapkg_path):
            logger.error("wxapkg 文件不存在: %s", wxapkg_path)
            return False

        try:
            # 创建临时解包目录
            temp_output = os.path.join(os.path.dirname(output_dir), "_temp_unpack")
            os.makedirs(temp_output, exist_ok=True)

            # 执行 wedecode 命令
            # wedecode <wxapkg_path> --out <output_dir>
            cmd = f'{self.wedecode_cmd} "{wxapkg_path}" --out "{temp_output}" --clear'

            logger.info("执行解包命令: %s", cmd)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2分钟超时
                shell=True,  # 使用 shell=True 来找到 wedecode
                encoding='utf-8',  # 使用 UTF-8 编码
                errors='ignore'  # 忽略无法解码的字符
            )

            if result.returncode != 0:
                logger.error("wedecode 解包失败: %s", result.stderr)
                return False

            # wedecode 可能将文件解包到子目录中，查找 app.json
            unpacked_dir = self._find_app_json_dir(temp_output)

            if not unpacked_dir:
                logger.error("解包后未找到 app.json")
                return False

            # 移动解包后的文件到目标目录
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            shutil.move(unpacked_dir, output_dir)

            # 清理临时目录
            if os.path.exists(temp_output):
                shutil.rmtree(temp_output)

            logger.info("解包成功: %s", output_dir)
            return True

        except subprocess.TimeoutExpired:
            logger.error("解包超时（>2分钟）")
            return False
        except Exception as e:
            logger.error("解包失败: %s", e)
            return False

    def _find_app_json_dir(self, root_dir: str) -> Optional[str]:
        """
        在解包目录中查找包含 app.json 的目录

        参数:
            root_dir: 根目录

        返回:
            str: 包含 app.json 的目录路径
        """
        # 检查根目录
        if os.path.exists(os.path.join(root_dir, "app.json")):
            return root_dir

        # 检查子目录（wedecode 可能创建子目录）
        for item in os.listdir(root_dir):
            item_path = os.path.join(root_dir, item)
            if os.path.isdir(item_path):
                if os.path.exists(os.path.join(item_path, "app.json")):
                    return item_path

                # 递归查找（最多2层）
                for subitem in os.listdir(item_path):
                    subitem_path = os.path.join(item_path, subitem)
                    if os.path.isdir(subitem_path):
                        if os.path.exists(os.path.join(subitem_path, "app.json")):
                            return subitem_path

        return None

    def process(self, source_dir: str, force_unpack: bool = False, unpack_base_dir: str = None) -> Tuple[bool, str]:
        """
        处理源码目录：检查是否已解包，如果未解包则自动解包

        参数:
            source_dir: 源码目录（可能是 wxapkg 文件所在目录，也可能是已解包的目录）
            force_unpack: 是否强制重新解包
            unpack_base_dir: 解包基础目录，默认为当前工作目录下的 unpacked/

        返回:
            (success, unpacked_dir): 成功标志和解包后的目录路径
        """
        # 设置解包基础目录
        if unpack_base_dir is None:
            unpack_base_dir = os.path.join(os.getcwd(), "unpacked")

        # 提取小程序 ID（目录名）
        miniapp_id = os.path.basename(os.path.abspath(source_dir))

        # 解包目标目录：unpacked/wx?????/
        unpacked_target = os.path.join(unpack_base_dir, miniapp_id)

        # Step 1: 优先检查 unpacked/ 目录中是否已有解包记录
        if not force_unpack and os.path.exists(unpacked_target) and self.check_unpacked(unpacked_target):
            logger.info("在 unpacked/ 目录中找到已解包源码: %s", unpacked_target)
            return True, unpacked_target

        # Step 2: 检查当前源码目录是否已解包（如果不是 unpacked/ 目录下）
        if not force_unpack and self.check_unpacked(source_dir):
            logger.info("源码已解包: %s", source_dir)
            return True, source_dir

        # Step 3: 查找 wxapkg 文件
        logger.info("源码未解包，正在查找 .wxapkg 文件...")
        wxapkg_path = self.find_wxapkg(source_dir)

        if not wxapkg_path:
            logger.error("未找到 .wxapkg 文件，无法解包")
            return False, source_dir

        logger.info("找到 wxapkg 文件: %s", wxapkg_path)

        # Step 4: 检查 wedecode 是否可用
        if not self.check_wedecode_available():
            logger.error("wedecode 工具不可用，请先安装: npm install -g wedecode")
            return False, source_dir

        # Step 5: 解包到 unpacked/wx?????/ 目录
        logger.info("正在解包到: %s", unpacked_target)

        if self.unpack(wxapkg_path, unpacked_target):
            logger.info("解包成功: %s", unpacked_target)
            return True, unpacked_target
        else:
            logger.error("解包失败")
            return False, source_dir
