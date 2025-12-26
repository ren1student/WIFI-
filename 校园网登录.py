#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
校园网自动登录工具 - v2.3.0
"""

import requests
import re
import sys
import winreg
import configparser
import os
import socket
import json
import threading
import time
import base64
import hashlib
import platform
import subprocess
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional, Tuple, Dict, Any
from datetime import datetime
import shutil
import pythoncom
try:
    import win32com.shell.shell as shell
    WIN32COM_SHELL_AVAILABLE = True
except ImportError:
    WIN32COM_SHELL_AVAILABLE = False
    shell = None

try:
    import win32event
    import win32api
    import win32con
    import win32gui
    from winerror import ERROR_ALREADY_EXISTS
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False

MUTEX_NAME = "CampusNetLogin_SingleInstance_Mutex_123456"
mutex_handle = None

def check_single_instance():
    """检测是否已有实例运行，返回：(是否为新实例, 错误信息)"""
    global mutex_handle
    
    if not PYWIN32_AVAILABLE:
        return True, "单实例检测失败：缺少pywin32"
    
    try:
        mutex_handle = win32event.CreateMutex(None, True, MUTEX_NAME)
        last_error = win32api.GetLastError()
        if last_error == ERROR_ALREADY_EXISTS:
            try:
                def enum_windows_callback(hwnd, extra):
                    window_title = win32gui.GetWindowText(hwnd)
                    if window_title and "校园网自动登录" in window_title:
                        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                        win32gui.SetForegroundWindow(hwnd)
                        return False
                    return True
                win32gui.EnumWindows(enum_windows_callback, None)
            except:
                pass
            
            win32api.CloseHandle(mutex_handle)
            mutex_handle = None
            return False, "已有校园网登录实例在运行，已激活原有窗口"
        return True, ""
    except Exception as e:
        return True, f"单实例检测失败：{str(e)}"

# 执行单实例检测
is_new_instance, msg = check_single_instance()
if not is_new_instance:
    # 完全静默退出，不输出任何信息到控制台
    sys.exit(0)

# 初始化日志系统，将在函数定义后调用

# PyQt5 全局变量（用于懒加载）
QThread = None
pyqtSignal = None
QApplication = None
QMainWindow = None
QWidget = None
QVBoxLayout = None
QHBoxLayout = None
QLabel = None
QLineEdit = None
QPushButton = None
QCheckBox = None
QMessageBox = None
QDesktopWidget = None
QGroupBox = None
QProgressBar = None
Qt = None
QIcon = None
QFont = None

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

# 初始化日志
logger = None

def init_logger():
    """初始化日志系统"""
    global logger
    if getattr(sys, 'frozen', False):
        exe_real_path = os.path.realpath(sys.executable)
        app_dir = os.path.dirname(exe_real_path)
    else:
        app_dir = os.path.dirname(os.path.abspath(__file__))
    
    log_dir = os.path.join(app_dir, "logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_path = os.path.join(log_dir, "campus_net.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(funcName)s - %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8", mode="a"),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)
    return logger

# 立即初始化日志
logger = init_logger()

# 常量定义
TIMEOUT = 10
CONFIG_FILE = 'login_config.ini'
VERSION = "2.3.1"

# 认证服务器
AUTH_SERVERS = [
    {"host": "172.30.255.42", "port": 801, "name": "主服务器"},
    {"host": "172.30.255.43", "port": 801, "name": "备用服务器1"},
    {"host": "172.30.255.44", "port": 801, "name": "备用服务器2"},
]

AUTH_URL_PATH = "/eportal/portal/login"
CHECK_INTERVAL = 3600
DEFAULT_IP = "172.17.14.69"

TARGET_WIFI_SSID = "SZU_CTC&CMCC"

# 密码加密
try:
    from cryptography.fernet import Fernet
    ENCRYPTION_ENABLED = True
except ImportError:
    ENCRYPTION_ENABLED = False

def get_wifi_interface_info() -> dict:
    """获取WiFi接口状态信息"""
    interface_info = {
        'connected': False,
        'ssid': None,
        'bssid': None,
        'signal': 0,
        'channel': 0,
        'authentication': None,
        'available': True,  # WiFi接口通常总是可用的，除非硬件故障
        'rssi': 0
    }
    
    try:
        # 获取WiFi接口状态
        kwargs = {
            'capture_output': True,
            'text': True,
            'encoding': 'gbk',
            'errors': 'ignore',
            'timeout': 10
        }
        if platform.system() == 'Windows':
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'interfaces'],
            **kwargs
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # 解析SSID（确保不是BSSID）
                if 'SSID' in line and ':' in line and 'BSSID' not in line and not line.startswith('    AP BSSID'):
                    ssid = line.split(':', 1)[1].strip()
                    if ssid and ssid != interface_info.get('ssid'):
                        interface_info['ssid'] = ssid
                
                # 解析BSSID
                elif 'BSSID' in line and ':' in line:
                    bssid = line.split(':', 1)[1].strip()
                    if bssid:
                        interface_info['bssid'] = bssid
                
                # 解析RSSI（更可靠的连接指标）
                elif 'Rssi' in line and ':' in line:
                    try:
                        rssi_str = line.split(':', 1)[1].strip()
                        rssi = int(rssi_str)
                        interface_info['rssi'] = rssi
                        # RSSI为负数，有值表示有信号和连接
                        if rssi < 0:
                            interface_info['connected'] = True
                    except:
                        pass
                
                # 解析连接状态（补充检测）
                elif any(keyword in line for keyword in ['状态', 'state', 'State']):
                    status = line.split(':', 1)[1].strip() if ':' in line else line
                    if any(connected_word in status for connected_word in 
                          ['已连接', 'connected', '已关联', 'associated']):
                        interface_info['connected'] = True
                
                # 解析信号强度
                elif '%' in line and ('信号' in line or 'Signal' in line or 'RSSI' not in line):
                    try:
                        signal_str = line.split('%')[0].split()[-1]
                        interface_info['signal'] = int(signal_str)
                    except:
                        pass
                
                # 解析信道
                elif '信道' in line or 'Channel' in line:
                    try:
                        channel_str = line.split(':')[1].strip()
                        interface_info['channel'] = int(channel_str)
                    except:
                        pass
                
                # 解析认证方式
                elif '认证' in line or 'Authentication' in line:
                    auth = line.split(':', 1)[1].strip() if ':' in line else line
                    interface_info['authentication'] = auth
    
    except Exception as e:
        logger.error(f"获取WiFi接口信息失败: {e}")
        # 即使失败，也认为WiFi接口可用（只是状态未知）
        pass
    
    return interface_info

def get_ethernet_interface_info() -> dict:
    """获取有线接口状态信息"""
    interface_info = {
        'connected': False,  # 物理连接状态
        'interface_name': None,
        'description': None,
        'available': True  # 有线接口通常总是可用的，除非硬件故障
    }
    
    try:
        # 获取所有网络接口状态
        # 直接使用二进制模式然后手动解码，避免编码问题
        kwargs = {
            'stdout': subprocess.PIPE,
            'stderr': subprocess.PIPE,
            'timeout': 10
        }
        if platform.system() == 'Windows':
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        
        result_bin = subprocess.run(
            ['netsh', 'interface', 'show', 'interface'],
            **kwargs
        )
        
        # 尝试多种编码方式解码
        stdout_bytes = result_bin.stdout
        decoded_output = None
        
        # 尝试几种可能的编码
        encodings = ['utf-8', 'gbk', 'gb2312', 'cp936']
        for encoding in encodings:
            try:
                decoded_output = stdout_bytes.decode(encoding)
                logger.debug(f"成功使用 {encoding} 编码解码netsh输出")
                break
            except UnicodeDecodeError:
                continue
        
        # 如果所有编码都失败，使用错误忽略模式
        if decoded_output is None:
            decoded_output = stdout_bytes.decode('utf-8', errors='ignore')
            logger.warning("使用错误忽略模式解码netsh输出")
        
        if result_bin.returncode == 0:
            logger.info("成功执行netsh interface show interface命令")
            logger.info(f"netsh输出: {repr(decoded_output)}")
            lines = decoded_output.split('\n')
            
            for line in lines:
                line = line.strip()
                logger.debug(f"接口行: {repr(line)}")
                # 检查是否是有线网络接口，需要同时匹配以太网相关关键词
                # 排除WLAN接口
                if line and 'wlan' not in line.lower() and 'wireless' not in line.lower():
                    logger.debug(f"处理非WLAN行: {line}")
                    # 检查是否包含以太网相关关键词 - 也检查乱码版本
                    has_ethernet = (any(indicator in line.lower() for indicator in ['以太网', 'ethernet', '本地连接', 'lan', '有线', 'eth']) 
                                   or '以太网' in line 
                                   or 'Ethernet' in line
                                   # 检查可能的乱码版本
                                   or '浠ュお缃' in line  # "以太网"的常见乱码
                                   or '浠ユ太缃' in line)
                    
                    if has_ethernet:
                        logger.info(f"找到包含以太网关键词的行: {line}")
                        # 解析接口信息
                        # 格式通常是: 管理员状态 状态 类型 接口名称
                        parts = line.split()
                        if len(parts) >= 4:
                            admin_state = parts[0]  # 管理员状态
                            connection_state = parts[1]  # 状态
                            interface_type = parts[2]  # 类型
                            interface_name = parts[3]  # 接口名称
                            
                            interface_info['interface_name'] = interface_name
                            interface_info['description'] = f"{interface_type} - {interface_name}"
                            
                            # 检查连接状态 - 这只是物理连接状态，不代表网络认证
                            if '已连接' in connection_state or 'connected' in connection_state.lower() or '宸茶繛鎺' in connection_state:
                                interface_info['connected'] = True
                                logger.info(f"检测到有线接口物理连接: {interface_name} - 但需要认证才能访问网络")
                        else:
                            logger.info(f"行parts不足4个: {parts}")
                        # 不再break，继续查找所有可能的以太网接口
    
    except Exception as e:
        logger.error(f"获取有线接口信息失败: {e}")
        # 即使失败，也认为有线接口可用（只是状态未知）
        pass
    
    return interface_info

def is_target_wifi_available() -> bool:
    """检查目标WiFi是否在系统配置文件中可用"""
    try:
        # 检查WiFi配置文件中是否有目标WiFi
        kwargs = {
            'capture_output': True,
            'text': True,
            'encoding': 'gbk',
            'errors': 'ignore',
            'timeout': 10
        }
        if platform.system() == 'Windows':
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'profiles'],
            **kwargs
        )
        
        if result.returncode == 0:
            # 检查配置文件列表中是否包含目标WiFi
            return TARGET_WIFI_SSID in result.stdout
    
    except Exception:
        pass
    
    return True  # 默认认为可用，避免阻断连接

def connect_to_target_wifi() -> bool:
    """基于WiFi接口状态进行连接（更稳定的识别逻辑）"""
    logger.info("开始执行WiFi连接...")
    try:
        # 1. 获取当前WiFi接口状态
        interface_info = get_wifi_interface_info()
        logger.info(f"当前WiFi接口状态: available={interface_info['available']}, connected={interface_info['connected']}, ssid={interface_info.get('ssid', 'N/A')}, signal={interface_info.get('signal', 'N/A')}")
        
        # 2. 如果WiFi接口不可用，返回False
        if not interface_info['available']:
            logger.warning("WiFi接口不可用")
            return False
        
        # 3. 检查是否已连接到目标WiFi
        if (interface_info['connected'] and 
            interface_info['ssid'] == TARGET_WIFI_SSID and
            (interface_info['signal'] > 0 or interface_info['rssi'] < 0)):
            logger.info(f"已连接到目标WiFi: {TARGET_WIFI_SSID} (RSSI: {interface_info['rssi']}, 信号: {interface_info['signal']}%)")
            return True
        
        # 4. 检查目标WiFi是否在配置文件中可用
        if not is_target_wifi_available():
            logger.warning(f"目标WiFi {TARGET_WIFI_SSID} 不在系统配置文件中")
            return False
        
        # 5. 执行连接命令（优化超时）
        logger.info(f"尝试连接到目标WiFi: {TARGET_WIFI_SSID}")
        # 设置更短的超时，避免阻塞
        kwargs = {
            'capture_output': True,
            'text': True,
            'encoding': 'gbk',
            'errors': 'ignore',
            'timeout': 8  # 从15秒缩短到8秒
        }
        if platform.system() == 'Windows':
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        
        connect_result = subprocess.run(
            ['netsh', 'wlan', 'connect', f'name="{TARGET_WIFI_SSID}"'],
            **kwargs
        )
        
        logger.info(f"WiFi连接命令执行结果: {connect_result.returncode}")
        
        # 优化等待逻辑：根据返回码动态等待
        if connect_result.returncode == 0:
            logger.info("WiFi连接命令执行成功，等待2秒...")
            time.sleep(2)  # 成功则短等待
        else:
            logger.info("WiFi连接命令执行失败，等待1秒...")
            time.sleep(1)  # 失败则更短等待
        
        # 7. 再次获取接口状态验证连接
        interface_info_after = get_wifi_interface_info()
        logger.info(f"连接后WiFi接口状态: connected={interface_info_after['connected']}, ssid={interface_info_after.get('ssid', 'N/A')}, signal={interface_info_after.get('signal', 'N/A')}")
        
        success = (interface_info_after['connected'] and 
                  interface_info_after['ssid'] == TARGET_WIFI_SSID and
                  (interface_info_after['signal'] > 0 or interface_info_after['rssi'] < 0))
        
        if success:
            logger.info(f"WiFi连接成功: {TARGET_WIFI_SSID} (信号: {interface_info_after['signal']}%)")
        else:
            logger.warning(f"WiFi连接失败或未连接到目标WiFi")
        
        return success
        
    except Exception as e:
        logger.error(f"WiFi连接过程异常: {e}", exc_info=True)
        return False

def is_network_connected_standalone(test_host: str = "www.baidu.com", port: int = 80) -> bool:
    """检查外网是否连接（独立版本，用于connect_ethernet_interface函数）"""
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(3)
        sock = socket.create_connection((test_host, port))
        sock.close()
        return True
    except (OSError, socket.timeout, socket.gaierror):
        return False
    finally:
        socket.setdefaulttimeout(old_timeout)

def connect_ethernet_interface() -> bool:
    """启用有线网络接口"""
    logger.info("开始执行有线网络连接...")
    try:
        # 获取当前有线接口状态
        ethernet_info = get_ethernet_interface_info()
        logger.info(f"当前有线接口状态: available={ethernet_info['available']}, connected={ethernet_info['connected']}, description={ethernet_info.get('description', 'N/A')}")
        
        # 如果有线接口已经连接，检查是否能访问网络
        if ethernet_info['connected']:
            logger.info(f"有线网络物理连接已建立: {ethernet_info.get('description', 'Unknown')}")
            # 重要：物理连接不等于认证通过，还需要检查是否能访问网络
            # 在校园网环境中，物理连接只是表示网线插好了，不代表可以上网
            if is_network_connected_standalone():
                logger.info("有线网络认证通过，可访问网络")
                return True
            else:
                logger.info("有线网络物理连接已建立，但未通过认证，需要进行校园网认证")
                # 物理连接已建立但认证未通过，返回True让主登录逻辑处理认证
                # 这是校园网的典型场景：插上网线后需要认证才能上网
                return True
        
        # 获取所有接口信息，找到未连接的以太网接口
        kwargs = {
            'capture_output': True,
            'text': True,
            'encoding': 'gbk',
            'errors': 'ignore',
            'timeout': 10
        }
        if platform.system() == 'Windows':
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        
        result = subprocess.run(
            ['netsh', 'interface', 'show', 'interface'],
            **kwargs
        )
        
        if result.returncode == 0:
            logger.info("成功执行netsh interface show interface命令")
            lines = result.stdout.split('\n')
            for line in lines:
                line = line.strip()
                logger.debug(f"接口行: {line}")  # 添加调试信息
                # 查找未连接的以太网接口
                if '已断开' in line or 'disconnected' in line.lower():
                    if any(ethernet_indicator in line.lower() for ethernet_indicator in 
                          ['以太网', 'ethernet', '本地连接', 'lan', '有线', 'eth']) or '以太网' in line or 'Ethernet' in line:
                        # 提取接口名称 - 改进提取逻辑
                        parts = line.split()
                        if len(parts) >= 1:
                            # 通常接口名称在行的最后
                            interface_name = parts[-1]
                            logger.info(f"找到未连接的有线网络接口: {interface_name}")
                            logger.info(f"尝试启用有线网络接口: {interface_name}")
                            
                            # 启用接口
                            enable_result = subprocess.run(
                                ['netsh', 'interface', 'set', 'interface', f'name="{interface_name}"', 'admin=enabled'],
                                **kwargs
                            )
                            
                            if enable_result.returncode == 0:
                                logger.info(f"成功发送启用接口命令，等待3秒...")
                                time.sleep(3)  # 等待接口启用
                                # 再次检查连接状态
                                new_ethernet_info = get_ethernet_interface_info()
                                logger.info(f"启用后有线接口状态: connected={new_ethernet_info['connected']}, description={new_ethernet_info.get('description', 'N/A')}")
                                if new_ethernet_info['connected']:
                                    logger.info(f"有线网络连接成功: {new_ethernet_info.get('description', 'Unknown')}")
                                    # 检查是否能够访问网络
                                    if is_network_connected_standalone():
                                        logger.info("有线网络认证通过，可访问网络")
                                        return True
                                    else:
                                        logger.info("有线网络接口已启用，但未通过认证，需要进行校园网认证")
                                        # 尝试校园网认证
                                        # 返回True，让主登录逻辑处理认证
                                        return True
                                else:
                                    logger.info("接口启用后仍未连接，尝试获取IP地址...")
                                    # 尝试获取IP地址
                                    ipconfig_result = subprocess.run(['ipconfig', '/renew'], **kwargs)
                                    logger.info(f"ipconfig /renew 命令执行结果: {ipconfig_result.returncode}")
                                    time.sleep(3)
                                    # 最后检查一次
                                    final_ethernet_info = get_ethernet_interface_info()
                                    logger.info(f"最终有线接口状态: connected={final_ethernet_info['connected']}")
                                    if final_ethernet_info['connected']:
                                        # 检查是否能够访问网络
                                        if is_network_connected_standalone():
                                            logger.info("有线网络认证通过，可访问网络")
                                            return True
                                        else:
                                            logger.info("有线网络接口已启用，但未通过认证，需要进行校园网认证")
                                            # 返回True，让主登录逻辑处理认证
                                            return True
                                    return final_ethernet_info['connected']
                            else:
                                logger.warning(f"启用有线网络接口失败: {interface_name}，返回码: {enable_result.returncode}")
        else:
            logger.warning(f"netsh命令执行失败，返回码: {result.returncode}")
        
        logger.info("未能找到或启用有线网络接口")
        return False
        
    except Exception as e:
        logger.error(f"有线网络连接过程异常: {e}", exc_info=True)
        return False

class StartupFolderManager:
    """启动文件夹管理器 - 用于设置开机自启"""
    
    def __init__(self):
        # 获取用户启动文件夹路径
        self.startup_folder = os.path.expanduser(r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
        self.shortcut_name = "校园网自动登录.lnk"
        self.shortcut_path = os.path.join(self.startup_folder, self.shortcut_name)
    
    def is_startup_enabled(self) -> bool:
        """检查是否已在启动文件夹中"""
        return os.path.exists(self.shortcut_path)
    
    def create_startup_shortcut(self) -> bool:
        """创建启动文件夹快捷方式"""
        if not WIN32COM_SHELL_AVAILABLE or shell is None:
            # 如果win32com.shell不可用，直接跳到备用方案
            raise ImportError("win32com.shell not available")
            
        try:
            # 获取程序路径
            if getattr(sys, 'frozen', False):
                # 程序已被打包为exe
                exe_path = sys.executable
            else:
                # 从源代码运行
                exe_path = os.path.abspath(__file__)
            
            # 创建快捷方式
            
            # 创建快捷方式对象
            shortcut = pythoncom.CoCreateInstance(
                shell.CLSID_ShellLink,
                None,
                pythoncom.CLSCTX_INPROC_SERVER,
                shell.IID_IShellLink
            )
            
            # 设置快捷方式目标
            shortcut.SetPath(exe_path)
            # 设置参数为静默模式
            shortcut.SetArguments("--silent")
            # 设置工作目录
            shortcut.SetWorkingDirectory(os.path.dirname(exe_path))
            # 设置图标（使用程序本身）
            shortcut.SetIconLocation(exe_path, 0)
            
            # 保存快捷方式
            persist_file = shortcut.QueryInterface(pythoncom.IID_IPersistFile)
            persist_file.Save(self.shortcut_path, 0)
            
            logger.info(f"启动文件夹快捷方式创建成功: {self.shortcut_path}")
            return True
            
        except ImportError:
            # 如果没有win32com，则尝试使用其他方法
            logger.warning("win32com不可用，尝试其他方式创建快捷方式")
            try:
                # 使用批处理文件作为替代方案
                batch_content = f'@echo off\ncd /d "{os.path.dirname(exe_path)}"\n"{exe_path}" --silent\n'
                batch_path = self.shortcut_path.replace('.lnk', '.bat')
                
                with open(batch_path, 'w', encoding='utf-8') as f:
                    f.write(batch_content)
                
                # 记录批处理文件路径而不是快捷方式路径
                self.shortcut_path = batch_path
                logger.info(f"批处理启动文件创建成功: {batch_path}")
                return True
            except Exception as e:
                logger.error(f"创建启动文件失败: {str(e)}")
                return False
        except Exception as e:
            logger.error(f"创建启动快捷方式失败: {str(e)}")
            return False
    
    def remove_startup_shortcut(self) -> bool:
        """移除启动文件夹快捷方式"""
        try:
            if os.path.exists(self.shortcut_path):
                os.remove(self.shortcut_path)
                logger.info(f"启动文件夹快捷方式已移除: {self.shortcut_path}")
                return True
            else:
                logger.info("启动文件夹快捷方式不存在")
                return True  # 不存在也算成功
        except Exception as e:
            logger.error(f"移除启动文件夹快捷方式失败: {str(e)}")
            return False


# 统一使用StartupFolderManager，不再需要TaskSchedulerManager


class CampusNetLogin:
    """校园网登录核心类"""
    
    def __init__(self, app_instance=None):
        self.username: str = ""
        self.password: str = ""
        self.auto_startup: bool = True  # 默认直接开启开机自启
        self.running: bool = True
        self.app = app_instance  # 接受外部传入的QApplication实例
        self.window = None
        self.pystray_icon = None
        self.session = None
        self.encryption_key = None
        
        # ========== 延迟创建TraySignal实例，避免在主线程外创建 ==========
        self.tray_signal = None
        if app_instance:
            self._init_tray_signal(app_instance)
        
        # IP缓存
        self._cached_ip = None
        self._cached_ip_time = 0
        self._ip_cache_duration = 300  # 5分钟
        
        # 统计信息
        self.login_count = 0
        self.last_login_time = None
        self.total_logins = 0
        
        # ========== 新增：触发冷却时间控制 ==========
        self.trigger_cooldown = 10  # 触发冷却时间（秒），可根据需要调整
        self.last_trigger_time = 0  # 最后一次触发时间戳（初始化为0）
        
        # 启动文件夹管理器（更稳定、兼容性更好的方案）
        self.startup_manager = StartupFolderManager()
        
        # 初始化
        self._init_encryption()
        self._init_session()
        self.load_config()
    
    def _init_tray_signal(self, app_instance):
        """初始化托盘信号（确保在主线程中创建）"""
        if self.tray_signal is None:
            # 导入PyQt5相关模块
            global QObject, pyqtSignal
            from PyQt5.QtCore import QObject, pyqtSignal
            
            class TraySignal(QObject):
                restore_window_signal = pyqtSignal()  # 窗口恢复信号
            
            self.tray_signal = TraySignal()
            # 强制信号槽在主线程执行（关键修复）
            self.tray_signal.moveToThread(app_instance.thread())
            self.tray_signal.restore_window_signal.connect(self._restore_window_in_main_thread)

    def _init_encryption(self) -> None:
        """初始化加密功能"""
        try:
            if ENCRYPTION_ENABLED:
                machine_info = f"{platform.node()}-{platform.system()}-{platform.machine()}"
                hash_obj = hashlib.sha256(machine_info.encode())
                key_base = hash_obj.digest()[:32]
                self.encryption_key = base64.urlsafe_b64encode(key_base)
            else:
                self.encryption_key = None
        except Exception:
            self.encryption_key = None

    def _init_session(self) -> None:
        """初始化HTTP会话"""
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Connection": "keep-alive"
        })
        self.session.verify = False
        self.session.timeout = TIMEOUT

    def encrypt_password(self, password: str) -> str:
        """加密密码"""
        if not ENCRYPTION_ENABLED or not password or not self.encryption_key:
            return password
        
        try:
            f = Fernet(self.encryption_key)
            return f.encrypt(password.encode()).decode()
        except Exception:
            return password

    def decrypt_password(self, encrypted_pwd: str) -> str:
        """解密密码"""
        if not ENCRYPTION_ENABLED or not encrypted_pwd or not self.encryption_key:
            return encrypted_pwd
        
        try:
            f = Fernet(self.encryption_key)
            return f.decrypt(encrypted_pwd.encode()).decode()
        except Exception:
            return encrypted_pwd

    def get_config_path(self) -> str:
        """获取配置文件路径（单文件EXE也指向自身所在目录）"""
        # ========== 关键修改：区分单文件打包的临时目录和实际EXE目录 ==========
        if getattr(sys, 'frozen', False):
            # 单文件打包模式：
            # sys.executable 是临时目录的exe，sys._MEIPASS 是临时解压目录
            # 我们需要获取「实际的EXE文件路径」（而非临时目录）
            exe_real_path = os.path.realpath(sys.executable)  # 获取EXE真实路径
            app_root = os.path.dirname(exe_real_path)  # EXE所在的根目录（比如D:\校园网\）
        else:
            # 开发模式：脚本所在目录
            app_root = os.path.dirname(os.path.abspath(__file__))
        
        # 配置文件生成在EXE根目录
        return os.path.join(app_root, CONFIG_FILE)

    def load_config(self) -> None:
        """加载配置文件"""
        config = configparser.ConfigParser()
        config_path = self.get_config_path()
        
        if os.path.exists(config_path):
            try:
                config.read(config_path, encoding='utf-8')
                
                if 'Login' in config:
                    self.username = config.get('Login', 'username', fallback='')
                    encrypted_pwd = config.get('Login', 'password', fallback='')
                    # 确保密码解密可靠，失败时返回原始值而非空
                    try:
                        self.password = self.decrypt_password(encrypted_pwd)
                    except Exception:
                        self.password = encrypted_pwd
                
                if 'System' in config:
                    # 从配置文件中读取设置，但实际状态以启动文件夹为准
                    config_auto_startup = config.getboolean('System', 'auto_startup', fallback=False)
                    # 检查实际的启动文件夹状态
                    actual_auto_startup = self.startup_manager.is_startup_enabled()
                    # 如果配置和实际状态不一致，以实际状态为准
                    if config_auto_startup != actual_auto_startup:
                        logger.info(f"开机自启配置与实际状态不一致，配置: {config_auto_startup}, 实际: {actual_auto_startup}")
                        # 修复：如果配置为开启但实际不存在，创建启动快捷方式
                        if config_auto_startup and not actual_auto_startup:
                            logger.info("配置中开机自启为True，但启动文件夹中不存在，立即创建快捷方式")
                            self.set_startup(True)
                            actual_auto_startup = True
                    self.auto_startup = actual_auto_startup
                    self.login_count = config.getint('System', 'login_count', fallback=0)
                    self.total_logins = config.getint('System', 'total_logins', fallback=0)
                
                if 'Stats' in config:
                    last_time = config.get('Stats', 'last_login_time', fallback='')
                    if last_time:
                        self.last_login_time = last_time
                
            except Exception as e:
                logger.error(f"加载配置失败: {e}", exc_info=True)
                self.username = ""
                self.password = ""
                self.auto_startup = True  # 修复：默认开启开机自启
        else:
            # 配置文件不存在时，主动初始化空配置（避免后续逻辑异常）
            self.username = ""
            self.password = ""
            self.auto_startup = True  # 修复：默认开启开机自启
            self.save_config()  # 创建默认配置文件

    def save_config(self) -> bool:
        """保存配置文件（增强容错）"""
        config = configparser.ConfigParser()
        
        config['Login'] = {
            'username': self.username,
            'password': self.encrypt_password(self.password)
        }
        
        config['System'] = {
            'auto_startup': self.auto_startup,
            'version': VERSION,
            'login_count': self.login_count,
            'total_logins': self.total_logins
        }
        
        if self.last_login_time:
            config['Stats'] = {
                'last_login_time': self.last_login_time
            }
        
        try:
            config_path = self.get_config_path()
            # 先写入临时文件，避免覆盖原有配置
            temp_path = f"{config_path}.tmp"
            with open(temp_path, 'w', encoding='utf-8') as configfile:
                config.write(configfile)
            # 原子替换
            os.replace(temp_path, config_path)
            return True
        except PermissionError:
            # 降级：保存到用户目录
            try:
                user_dir = os.path.expanduser("~")
                fallback_path = os.path.join(user_dir, CONFIG_FILE)
                with open(fallback_path, 'w', encoding='utf-8') as f:
                    config.write(f)
                return True
            except Exception as e:
                logger.error(f"配置文件保存失败（降级也失败）: {e}")
                return False
        except Exception as e:
            logger.error(f"配置文件保存失败: {e}")
            return False

    def is_authentication_server_reachable(self, server: Dict[str, Any]) -> bool:
        """检查认证服务器是否可达"""
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(3)
            sock = socket.create_connection((server["host"], server["port"]))
            sock.close()
            return True
        except (OSError, socket.timeout, socket.gaierror):
            return False
        finally:
            socket.setdefaulttimeout(old_timeout)

    def is_network_connected(self, test_host: str = "www.baidu.com", port: int = 80) -> bool:
        """检查外网是否连接"""
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(3)
            sock = socket.create_connection((test_host, port))
            sock.close()
            return True
        except (OSError, socket.timeout, socket.gaierror):
            return False
        finally:
            socket.setdefaulttimeout(old_timeout)

    def is_network_connected_http(self, test_url: str = "http://www.baidu.com", timeout: int = 5) -> bool:
        """通过HTTP请求检查外网是否连接（更严格的检测）"""
        try:
            response = self.session.get(test_url, timeout=timeout)
            # 检查是否返回了有效的HTTP响应（200-399）
            return 200 <= response.status_code < 400
        except:
            return False

    def get_available_server(self) -> Optional[Dict[str, Any]]:
        """获取可用的认证服务器"""
        for server in AUTH_SERVERS:
            if self.is_authentication_server_reachable(server):
                return server
        return None

    def get_local_ip(self) -> Optional[str]:
        """获取本地IP地址（带缓存）"""
        if (self._cached_ip and self._cached_ip_time and 
            time.time() - self._cached_ip_time < self._ip_cache_duration):
            return self._cached_ip
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            self._cached_ip = local_ip
            self._cached_ip_time = time.time()
            return local_ip
            
        except Exception:
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                self._cached_ip = local_ip
                self._cached_ip_time = time.time()
                return local_ip
            except socket.error:
                return None

    def extract_ip_from_response(self, text: str) -> str:
        """从响应文本中提取IP地址"""
        try:
            pattern = re.compile(r"v46ip='(?P<ip>\d+\.\d+\.\d+\.\d+)'", re.S)
            match = pattern.search(text)
            if match:
                return match.group("ip")
            return DEFAULT_IP
        except Exception:
            return DEFAULT_IP

    def build_login_url(self, server: Dict[str, Any], username: str, password: str, ip: str) -> str:
        """构建登录URL"""
        base_url = f"http://{server['host']}:{server['port']}{AUTH_URL_PATH}"
        params = {
            "callback": "dr1003",
            "login_method": "1",
            "user_account": f",0,{username}",
            "user_password": password,
            "wlan_user_ip": ip,
            "wlan_user_ipv6": "",
            "wlan_user_mac": "000000000000",
            "wlan_ac_ip": "",
            "wlan_ac_name": "",
            "jsVersion": "4.1.3",
            "terminal_type": "1",
            "lang": "zh-cn",
            "v": "6230"
        }
        
        param_str = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{base_url}?{param_str}"

    def login(self, username: str, password: str, ip: Optional[str] = None) -> Tuple[bool, str]:
        """执行登录操作 - 高速优化版本（支持有线和无线网络）"""
        # ========== 新增：登录时同步更新触发时间 ==========
        self.last_trigger_time = time.time()
        
        # 重置会话状态
        self._init_session()
        
        if not username or not password:
            return False, "用户名或密码不能为空"
        
        # 1. 快速预检查：并行获取关键信息，减少串行等待
        wifi_info = get_wifi_interface_info()
        ethernet_info = get_ethernet_interface_info()
        network_ready = self.is_network_connected()  # 检查是否可以访问外网
        
        # 添加调试日志
        logger.info(f"WiFi状态 - 可用: {wifi_info['available']}, 已连接: {wifi_info['connected']}, SSID: {wifi_info.get('ssid', 'N/A')}")
        logger.info(f"有线网络状态 - 可用: {ethernet_info['available']}, 已连接: {ethernet_info['connected']}, 描述: {ethernet_info.get('description', 'N/A')}")
        logger.info(f"网络连接状态: {network_ready}")
        
        # 检测到有线物理连接时，强制执行一次认证（无论当前网络状态如何）
        if ethernet_info['connected']:
            logger.info("检测到有线物理连接，强制执行认证")
            # 连接物理接口
            result = connect_ethernet_interface()
            if result:
                logger.info("有线网络物理连接完成")
                
                # 无论当前网络状态如何，都执行HTTP认证以确保有线网络被认证
                # 这样即使WiFi已连接，有线网络也会被认证
                logger.info("执行有线网络HTTP认证")
                
                # 获取IP地址用于认证
                if not ip:
                    ip = self.get_local_ip()
                    if not ip:
                        return False, "无法获取本地IP地址"
                
                server = self._get_available_server_fast()
                if not server:
                    return False, "认证服务器不可达"
                
                try:
                    server_ip = self._get_server_ip_optimized(server)
                    login_url = self.build_login_url(server, username, password, server_ip)
                    login_response = self.session.get(login_url, timeout=TIMEOUT)
                    login_response.raise_for_status()
                    
                    result = self._parse_login_response_fast(login_response, username, password)
                    logger.info("有线网络认证请求已发送")
                    return result
                except requests.exceptions.Timeout:
                    return False, "请求超时"
                except requests.exceptions.ConnectionError:
                    return False, "服务器连接失败"
                except Exception as e:
                    if self.is_network_connected_http():
                        logger.info("有线网络认证成功")
                        return True, "有线网络认证成功"
                    else:
                        return False, f"登录异常：{str(e)}"
            else:
                logger.error("有线网络连接失败")
        
        # 2. 智能网络连接：检测并连接有线或无线网络
        # 注意：ethernet_info['connected'] 表示物理连接状态（网线是否插好）
        #      network_ready 表示网络认证状态（是否能访问外网）
        wifi_connected_target = (wifi_info['connected'] and 
                            wifi_info['ssid'] == "SZU_CTC&CMCC")
        ethernet_connected = ethernet_info['connected']  # 这是物理连接状态
        
        # 根据当前连接状态决定连接策略
        if not wifi_connected_target and not ethernet_connected:
            # 都未连接，尝试连接有线和/或无线网络
            logger.info("WiFi和有线网络都未连接，开始并行连接...")
            connections_to_attempt = []
            
            if ethernet_info['available']:
                logger.info("有线网络接口可用，添加到连接列表")
                connections_to_attempt.append(connect_ethernet_interface)
            else:
                logger.info("有线网络接口不可用")
            
            if wifi_info['available']:
                logger.info("WiFi接口可用，添加到连接列表")
                connections_to_attempt.append(connect_to_target_wifi)
            else:
                logger.info("WiFi接口不可用")
            
            # 同时尝试连接
            threads = []
            for conn_func in connections_to_attempt:
                logger.info(f"启动连接线程: {conn_func.__name__}")
                thread = threading.Thread(target=conn_func, daemon=True)
                thread.start()
                threads.append(thread)
            
            # 等待连接完成
            for thread in threads:
                thread.join(timeout=3)  # 最多等待3秒
        elif not wifi_connected_target:
            # 只有WiFi未连接，连接WiFi
            logger.info("仅WiFi未连接，连接WiFi")
            connect_to_target_wifi()
        elif not ethernet_connected:
            # 只有有线网络未连接，连接有线网络
            # 注意：物理连接不等于认证通过，connect_ethernet_interface会处理认证
            logger.info("仅有线网络未连接，连接有线网络")
            connect_ethernet_interface()
        
        # 3. 如果网络已连接，快速验证并返回（避免重复登录）
        if network_ready:
            # 使用更严格的HTTP检查来确认是否真的可以访问外网
            if self.is_network_connected_http():
                return True, "网络已连接，账号已在线"
            else:
                logger.info("网络物理连接存在，但HTTP访问失败，需要进行认证")
        
        # 4. 并行准备：IP获取和服务器选择同时进行
        if not ip:
            ip = self.get_local_ip()
            if not ip:
                return False, "无法获取本地IP地址"
        
        # 5. 快速服务器选择：优先主服务器，减少探测时间
        server = self._get_available_server_fast()
        if not server:
            return False, "认证服务器不可达"
        
        try:
            # 6. 优化的服务器IP获取
            server_ip = self._get_server_ip_optimized(server)
            
            # 7. 执行登录请求
            login_url = self.build_login_url(server, username, password, server_ip)
            login_response = self.session.get(login_url, timeout=TIMEOUT)
            login_response.raise_for_status()
            
            # 8. 快速响应解析
            return self._parse_login_response_fast(login_response, username, password)
                
        except requests.exceptions.Timeout:
            return False, "请求超时"
        except requests.exceptions.ConnectionError:
            return False, "服务器连接失败"
        except Exception as e:
            # 快速兜底：网络已连接就认为成功
            # 使用更严格的HTTP检查来确认网络状态
            if self.is_network_connected_http():
                return True, "网络已连接"
            else:
                return False, f"登录异常：{str(e)}"

    def _get_available_server_fast(self) -> Optional[Dict[str, Any]]:
        """快速服务器选择：优先主服务器"""
        # 直接尝试主服务器，减少探测次数
        primary_server = AUTH_SERVERS[0]
        if self.is_authentication_server_reachable(primary_server):
            return primary_server
        
        # 主服务器不可达才尝试备用服务器
        for server in AUTH_SERVERS[1:]:
            if self.is_authentication_server_reachable(server):
                return server
        return None

    def _get_server_ip_optimized(self, server: Dict[str, Any]) -> str:
        """优化的服务器IP获取"""
        try:
            response = self.session.get(f"http://{server['host']}", timeout=3)
            response.raise_for_status()
            return self.extract_ip_from_response(response.text)
        except:
            return DEFAULT_IP

    def _parse_login_response_fast(self, login_response, username: str, password: str) -> Tuple[bool, str]:
        """快速登录响应解析"""
        response_text = login_response.content.decode('utf-8', errors='ignore').strip()
        
        if response_text.startswith("dr1003(") and response_text.endswith(");"):
            json_str = response_text[7:-2]
            try:
                response_json = json.loads(json_str)
                result = response_json.get("result")
                msg = response_json.get("msg", "未知错误")
                
                # 快速成功判断
                success_indicators = ["已在线", "在线", "成功", "登录成功", "已经在线"]
                if (any(indicator in msg for indicator in success_indicators) or result == 1):
                    self.username = username
                    self.password = password
                    self.last_login_time = time.strftime("%Y-%m-%d %H:%M:%S")
                    if result == 1:
                        self.login_count += 1
                        self.total_logins += 1
                    self.save_config()
                    return True, f"账号状态：{msg}"
                
                # 快速失败判断
                fail_indicators = ["密码错误", "账号不存在", "认证失败", "拒绝", "error", "failed"]
                if any(indicator in msg.lower() for indicator in fail_indicators):
                    return False, f"登录失败：{msg}"
                
                return False, f"登录响应：{msg}"
                    
            except json.JSONDecodeError:
                return True, "登录成功（响应解析异常）"
        else:
            return True, "登录成功（响应格式异常）"

    def is_startup_enabled(self) -> bool:
        """检查启动文件夹中是否已存在快捷方式"""
        try:
            return self.startup_manager.is_startup_enabled()
        except Exception:
            return False
    
    def sync_startup_state(self, new_state: bool = None):
        """同步开机自启状态到GUI和托盘"""
        if new_state is not None:
            self.auto_startup = new_state
        
        # 同步到GUI界面
        if self.window and hasattr(self.window, 'startup_check'):
            self.window.startup_check.setChecked(self.auto_startup)
        
        # 同步到托盘菜单
        if self.pystray_icon:
            self.pystray_icon.update_menu()
    
    def set_startup(self, enable: bool) -> bool:
        """设置自启（使用启动文件夹方式）"""
        self.auto_startup = enable
        
        if enable:
            result = self.startup_manager.create_startup_shortcut()
        else:
            result = self.startup_manager.remove_startup_shortcut()
        
        self.save_config()
        # 同步状态到GUI和托盘
        self.sync_startup_state()
        return result

    def auto_login(self) -> bool:
        """自动登录（添加触发冷却限制）"""
        # ========== 新增：触发冷却检查 ==========
        current_time = time.time()
        if current_time - self.last_trigger_time < self.trigger_cooldown:
            logger.info(f"触发冷却中，{int(self.trigger_cooldown - (current_time - self.last_trigger_time))}秒后可再次执行")
            return True  # 视为成功，避免重复触发
        
        # 更新最后触发时间
        self.last_trigger_time = current_time
        
        # （原有登录逻辑保持不变）
        if not self.username or not self.password:
            return False
        
        # 开机自启模式：仅在网络未连接时才连接WiFi（减少耗时）
        if not self.is_network_connected_http():
            # 异步连接WiFi，不阻塞登录
            threading.Thread(target=connect_to_target_wifi, daemon=True).start()
        
        # 快速登录：直接用缓存IP + 主服务器，跳过服务器探测
        server = AUTH_SERVERS[0]  # 优先主服务器，不探测
        ip = self._cached_ip or DEFAULT_IP  # 用缓存IP或默认IP，不获取新IP
        if server and not self.is_network_connected_http():
            success, msg = self.login(self.username, self.password, ip)
            logger.info(f"开机自启登录结果: {success}, {msg}")
            return success
        return True

    def _restore_window_in_main_thread(self):
        """【必须在主线程执行】恢复窗口的槽函数"""
        try:
            if self.window:
                self.window.show()
                self.window.raise_()
                self.window.activateWindow()
            else:
                # 兜底：避免重复创建 QApplication
                app_instance = QApplication.instance()
                if not app_instance:
                    self.app = QApplication(sys.argv)
                    self.app.setQuitOnLastWindowClosed(False)
                else:
                    self.app = app_instance
                self.create_login_window()
        except Exception as e:
            logger.error(f"恢复窗口失败: {e}", exc_info=True)
            # 终极兜底：重新创建窗口实例
            try:
                self.window = EnhancedMainWindow(self)
                self.window.show()
            except Exception as e2:
                logger.error(f"重新创建窗口失败: {e2}", exc_info=True)
                # 弹窗提示（仅在主线程）
                if QApplication.instance():
                    QMessageBox.warning(None, "提示", "窗口恢复失败，请重启程序")
    
    def create_login_window(self) -> None:
        """创建登录窗口（懒加载PyQt5）"""
        # 确保TraySignal已初始化
        if self.tray_signal is None and self.app:
            self._init_tray_signal(self.app)
        
        # 懒加载PyQt5模块
        global QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit
        global QPushButton, QCheckBox, QMessageBox, QDesktopWidget, QGroupBox, QProgressBar
        global Qt, QIcon, QFont, QThread, pyqtSignal, QObject
        
        from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                    QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                                    QCheckBox, QMessageBox, QDesktopWidget, QGroupBox,
                                    QProgressBar)
        from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
        from PyQt5.QtGui import QIcon, QFont
        
        # 更新全局变量
        globals()['QApplication'] = QApplication
        globals()['QMainWindow'] = QMainWindow
        globals()['QWidget'] = QWidget
        globals()['QVBoxLayout'] = QVBoxLayout
        globals()['QHBoxLayout'] = QHBoxLayout
        globals()['QLabel'] = QLabel
        globals()['QLineEdit'] = QLineEdit
        globals()['QPushButton'] = QPushButton
        globals()['QCheckBox'] = QCheckBox
        globals()['QMessageBox'] = QMessageBox
        globals()['QDesktopWidget'] = QDesktopWidget
        globals()['QGroupBox'] = QGroupBox
        globals()['QProgressBar'] = QProgressBar
        globals()['Qt'] = Qt
        globals()['QIcon'] = QIcon
        globals()['QFont'] = QFont
        globals()['QThread'] = QThread
        globals()['pyqtSignal'] = pyqtSignal
        globals()['QObject'] = QObject
        
        # 确保只使用已有的QApplication实例
        if not self.app:
            raise RuntimeError("QApplication instance not found. It should be created in the main thread.")
        
        if self.window:
            self.window.close()
        
        # 直接使用全局的 EnhancedMainWindow 类
        self.window = EnhancedMainWindow(self)
        self.window.show()
        
        try:
            self.app.setWindowIcon(QIcon("icon.ico"))
        except:
            pass

    def minimize_to_tray(self) -> None:
        """最小化到系统托盘"""
        if self.window:
            self.window.hide()
        
        # 修复：确保托盘图标已创建且状态同步
        if not self.pystray_icon:
            self.create_tray_icon()
        elif self.pystray_icon:
            self.pystray_icon.update_menu()

    def create_tray_icon(self) -> None:
        """创建系统托盘图标（懒加载pystray）"""
        # 同步启动文件夹状态：若配置为开启但快捷方式不存在，则创建
        if self.auto_startup and not self.is_startup_enabled():
            logger.info("配置中开机自启为True，但启动文件夹中不存在，立即创建快捷方式")
            self.set_startup(True)
        
        if self.pystray_icon:
            # 修复：如果托盘图标已存在但状态不同步，强制更新菜单
            self.pystray_icon.update_menu()
            return
        
        # 懒加载pystray模块
        global Icon, Menu, MenuItem, Image, ImageDraw
        from pystray import Icon, Menu, MenuItem
        from PIL import Image, ImageDraw
        
        # 确保TraySignal已初始化
        if self.tray_signal is None:
            return
        
        def restore_window(icon, item):
            # ========== 关键修改：发送信号，让主线程处理UI ==========
            if self.tray_signal:
                self.tray_signal.restore_window_signal.emit()
        
        def quit_program(icon, item):
            self.running = False
            self.cleanup()
            # 强制停止托盘线程
            if self.pystray_icon:
                self.pystray_icon.stop()
            # 退出Qt事件循环
            if self.app:
                self.app.quit()
        
        def re_login(icon, item):
            if self.username and self.password:
                threading.Thread(
                    target=lambda: self.login(self.username, self.password),
                    daemon=True
                ).start()
        
        def toggle_startup(icon, item):
            # 切换状态并通过同步函数更新GUI和托盘
            new_state = not self.auto_startup
            self.set_startup(new_state)
        
        # 创建默认图标
        image = Image.new('RGB', (64, 64), color=(34, 139, 34))
        draw = ImageDraw.Draw(image)
        draw.ellipse((10, 10, 20, 20), fill="white")
        draw.ellipse((25, 15, 35, 25), fill="white")
        draw.ellipse((40, 10, 50, 20), fill="white")
        draw.line((20, 15, 25, 15), fill="white", width=2)
        draw.line((35, 20, 40, 20), fill="white", width=2)
        
        # 创建菜单
        menu = Menu(
            MenuItem('恢复窗口', restore_window),
            MenuItem('重新登录', re_login),
            MenuItem('开机自启', toggle_startup, checked=lambda item: self.auto_startup),
            MenuItem('退出', quit_program)
        )
        
        # 创建托盘图标
        self.pystray_icon = Icon(
            "CampusNetLogin",
            image,
            f"校园网登录 v{VERSION}",
            menu
        )
        
        # 修改托盘线程创建逻辑：设置为守护线程 + 异常捕获
        tray_thread = threading.Thread(
            target=self._run_tray_safe,
            daemon=True  # 主线程退出时自动终止
        )
        tray_thread.start()

    # 新增安全的托盘运行函数
    def _run_tray_safe(self):
        """带异常捕获的托盘运行逻辑"""
        try:
            if self.pystray_icon:
                self.pystray_icon.run()
        except Exception as e:
            logger.error(f"托盘运行异常: {e}")
        finally:
            # 确保托盘资源释放
            if self.pystray_icon:
                try:
                    self.pystray_icon.stop()
                except:
                    pass

    def cleanup(self):
        """清理资源"""
        self.running = False
        
        # 新增：清理单实例互斥体
        global mutex_handle
        if mutex_handle and PYWIN32_AVAILABLE:
            try:
                win32api.CloseHandle(mutex_handle)
                mutex_handle = None
            except:
                pass
        
        if self.pystray_icon:
            try:
                self.pystray_icon.stop()
            except:
                pass
        
        if self.window:
            try:
                self.window.close()
            except:
                pass
        
        if self.app:
            try:
                self.app.quit()
            except:
                pass
        
        if self.session:
            try:
                self.session.close()
            except:
                pass

    def run(self) -> None:
        """主运行函数（优化开机自启的检测频率）"""
        silent_mode = "--silent" in sys.argv
        
        # 关键修复：默认勾选所有选项，无论启动方式
        if silent_mode or (self.auto_startup and self.username and self.password):
            # 开机自启模式：先快速登录，再后台监控（检测间隔从1小时改为5分钟）
            self.auto_login()
            # 修复：确保开机自启时托盘图标正确创建
            if not self.pystray_icon:
                self.create_tray_icon()
            # 修复：确保托盘图标状态与自启状态同步
            elif self.pystray_icon:
                self.pystray_icon.update_menu()
            
            def network_monitor():
                try:
                    while self.running:
                        time.sleep(300)  # 5分钟检测一次（原3600秒）
                        if not self.is_network_connected_http():
                            self.auto_login()
                except KeyboardInterrupt:
                    self.cleanup()
            
            threading.Thread(target=network_monitor, daemon=True).start()
        else:
            # 手动启动：默认勾选所有选项
            self.create_login_window()
            # 修复：手动启动时默认勾选所有选项
            if self.window and hasattr(self.window, 'minimize_check'):
                self.window.minimize_check.setChecked(True)
            if self.window and hasattr(self.window, 'startup_check'):
                self.window.startup_check.setChecked(True)
            # 修复：确保托盘图标状态与配置同步（手动启动时也创建托盘）
            if not self.pystray_icon:
                self.create_tray_icon()

# 动态创建LoginThread类，避免类定义时的QThread为None问题
def create_login_thread_class():
    """创建LoginThread类，确保QThread已加载"""
    global QThread, pyqtSignal
    if QThread is None:
        from PyQt5.QtCore import QThread, pyqtSignal
        globals()['QThread'] = QThread
        globals()['pyqtSignal'] = pyqtSignal
    
    class LoginThread(QThread):
        """登录线程"""
        
        # 类级别定义信号
        login_signal = pyqtSignal(bool, str)
        progress_signal = pyqtSignal(int)
        
        def __init__(self, parent_app: CampusNetLogin, username: str, password: str):
            super().__init__()
            self.parent_app = parent_app
            self.username = username
            self.password = password
        
        def run(self):
            """执行登录"""
            self.progress_signal.emit(10)
            success, msg = self.parent_app.login(self.username, self.password)
            self.progress_signal.emit(100)
            self.login_signal.emit(success, msg)
    
    return LoginThread

# 创建LoginThread类
LoginThread = create_login_thread_class()

# 动态创建EnhancedMainWindow类，避免类定义时的QMainWindow为None问题
def create_enhanced_main_window_class():
    """创建EnhancedMainWindow类，确保QMainWindow已加载"""
    global QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit
    global QPushButton, QCheckBox, QMessageBox, QDesktopWidget, QGroupBox, QProgressBar
    global Qt, QIcon, QFont
    
    from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                                QLineEdit, QPushButton, QCheckBox, QMessageBox, QDesktopWidget,
                                QGroupBox, QProgressBar)
    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QIcon, QFont
    
    # 更新全局变量
    globals()['QMainWindow'] = QMainWindow
    globals()['QWidget'] = QWidget
    globals()['QVBoxLayout'] = QVBoxLayout
    globals()['QHBoxLayout'] = QHBoxLayout
    globals()['QLabel'] = QLabel
    globals()['QLineEdit'] = QLineEdit
    globals()['QPushButton'] = QPushButton
    globals()['QCheckBox'] = QCheckBox
    globals()['QMessageBox'] = QMessageBox
    globals()['QDesktopWidget'] = QDesktopWidget
    globals()['QGroupBox'] = QGroupBox
    globals()['QProgressBar'] = QProgressBar
    globals()['Qt'] = Qt
    globals()['QIcon'] = QIcon
    globals()['QFont'] = QFont
    
    class EnhancedMainWindow(QMainWindow):
        """增强版主登录窗口（关闭失败弹窗）"""
        def __init__(self, parent_app):
            super().__init__()
            self.parent_app = parent_app
            self.login_thread = None
            
            # 初始化UI
            self.init_ui()
        
        def init_ui(self):
            """初始化UI"""
            self.setWindowTitle(f"校园网自动登录 v{VERSION}")
            self.resize(600, 600)  
            self.center_on_screen()
            
            # 设置应用样式
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #ffffff;
                }
                QGroupBox {
                    font-weight: bold;
                    border: 1px solid #e0e0e0;
                    border-radius: 8px;
                    margin-top: 8px;
                    padding-top: 15px;
                    background-color: #fafafa;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 20px;
                    padding: 0 10px 0 10px;
                    color: #333333;
                    font-size: 14px;
                }
                QPushButton {
                    background-color: #0078d4;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 6px;
                    font-weight: bold;
                    font-size: 15px;
                    min-height: 40px;
                }
                QPushButton:hover {
                    background-color: #106ebe;
                }
                QPushButton:pressed {
                    background-color: #005a9e;
                }
                QPushButton:disabled {
                    background-color: #f0f0f0;
                    color: #a0a0a0;
                }
                QLineEdit {
                    padding: 10px;
                    border: 1px solid #d0d0d0;
                    border-radius: 6px;
                    font-size: 14px;
                    background-color: white;
                    min-height: 40px;
                    width: 100%;
                }
                QLineEdit:focus {
                    border-color: #0078d4;
                    outline: none;
                    border: 2px solid #0078d4;
                }
                QCheckBox {
                    font-size: 14px;
                    color: #333333;
                    spacing: 8px;
                }
                QCheckBox::indicator {
                    width: 18px;
                    height: 18px;
                    border: 2px solid #d0d0d0;
                    border-radius: 4px;
                    background-color: white;
                }
                QCheckBox::indicator:checked {
                    background-color: #0078d4;
                    border-color: #0078d4;
                }
                QLabel {
                    color: #333333;
                    font-size: 14px;
                    min-width: 60px;
                }
                QProgressBar {
                    border: 1px solid #d0d0d0;
                    border-radius: 4px;
                    text-align: center;
                    height: 10px;
                    background-color: #f0f0f0;
                }
                QProgressBar::chunk {
                    background-color: #0078d4;
                    border-radius: 3px;
                }
            """)
            
            # 创建中央部件
            central_widget = QWidget()
            self.setCentralWidget(central_widget)
            
            # 主布局
            main_layout = QVBoxLayout(central_widget)
            main_layout.setContentsMargins(25, 25, 25, 25)
            main_layout.setSpacing(20)
            main_layout.setAlignment(Qt.AlignTop)
            
            # 标题区域
            title_container = QWidget()
            title_layout = QHBoxLayout(title_container)
            title_layout.setContentsMargins(0, 0, 0, 25)
            
            title_label = QLabel("校园网自动登录")
            title_label.setFont(QFont("微软雅黑", 18, QFont.Bold))
            title_label.setStyleSheet("color: #2c3e50;")
            title_layout.addWidget(title_label)
            
            version_label = QLabel(f"v{VERSION}")
            version_label.setFont(QFont("微软雅黑", 10))
            version_label.setStyleSheet("color: #7f8c8d;")
            title_layout.setAlignment(version_label, Qt.AlignBottom)
            title_layout.addWidget(version_label)
            title_layout.setAlignment(Qt.AlignRight)
            
            main_layout.addWidget(title_container)
            
            # 账号密码输入区域
            login_group = QGroupBox("")
            login_layout = QVBoxLayout(login_group)
            login_layout.setSpacing(20)
            login_layout.setContentsMargins(20, 20, 20, 20)
            
            # 账号输入行
            username_row = QWidget()
            username_layout = QHBoxLayout(username_row)
            username_layout.setContentsMargins(0, 0, 0, 0)
            username_layout.setSpacing(10)
            
            username_label = QLabel("账号：")
            username_label.setFont(QFont("微软雅黑", 12))
            self.username_entry = QLineEdit()
            self.username_entry.setPlaceholderText("请输入校园网账号")
            self.username_entry.setMinimumHeight(45)
            self.username_entry.setMinimumWidth(280)
            
            username_layout.addWidget(username_label)
            username_layout.addWidget(self.username_entry)
            
            # 密码输入行
            password_row = QWidget()
            password_layout = QHBoxLayout(password_row)
            password_layout.setContentsMargins(0, 0, 0, 0)
            password_layout.setSpacing(10)
            
            password_label = QLabel("密码：")
            password_label.setFont(QFont("微软雅黑", 12))
            self.password_entry = QLineEdit()
            self.password_entry.setEchoMode(QLineEdit.Password)  # 默认隐藏密码
            self.password_entry.setPlaceholderText("请输入校园网密码")
            self.password_entry.setMinimumHeight(45)
            self.password_entry.setMinimumWidth(280)
            
            # 新增显示/隐藏密码按钮
            pwd_toggle_btn = QPushButton("👁️")
            pwd_toggle_btn.setCheckable(True)
            pwd_toggle_btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    border: none;
                    min-width: 30px;
                }
                QPushButton:hover {
                    background-color: #f0f0f0;
                    border-radius: 4px;
                }
            """)
            pwd_toggle_btn.clicked.connect(lambda checked:
                self.password_entry.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
            )
            
            password_layout.addWidget(password_label)
            password_layout.addWidget(self.password_entry)
            password_layout.addWidget(pwd_toggle_btn)
            
            # 优化：确保密码填充逻辑可靠
            if self.parent_app.username:
                self.username_entry.setText(self.parent_app.username)
            if self.parent_app.password:
                self.password_entry.setText(self.parent_app.password)
                # 确保密码框是隐藏状态
                self.password_entry.setEchoMode(QLineEdit.Password)
            
            login_layout.addWidget(username_row)
            login_layout.addWidget(password_row)
            main_layout.addWidget(login_group)
            
            # 设置选项区域
            settings_group = QGroupBox("系统设置")
            settings_layout = QVBoxLayout(settings_group)
            settings_layout.setSpacing(15)
            settings_layout.setContentsMargins(25, 20, 25, 20)
            
            # 开机自启
            self.startup_check = QCheckBox("开机自动登录")
            self.startup_check.setChecked(self.parent_app.auto_startup)  # 与当前配置状态同步
            self.startup_check.setFont(QFont("微软雅黑", 12))
            # 添加状态变化监听，实现双向同步
            self.startup_check.stateChanged.connect(self.on_startup_state_changed)
            settings_layout.addWidget(self.startup_check)
            
            # 最小化到托盘
            self.minimize_check = QCheckBox("关闭窗口时最小化到系统托盘")
            self.minimize_check.setChecked(True)
            self.minimize_check.setFont(QFont("微软雅黑", 12))
            settings_layout.addWidget(self.minimize_check)
            
            main_layout.addWidget(settings_group)
            
            # 登录按钮
            self.login_btn = QPushButton("立即登录")
            self.login_btn.clicked.connect(self.on_login)
            self.login_btn.setMinimumHeight(45)
            self.login_btn.setMinimumWidth(200)
            main_layout.addWidget(self.login_btn, alignment=Qt.AlignCenter)
            
            # 给账号/密码输入框添加文本变化监听（用于重置登录按钮状态）
            self.username_entry.textChanged.connect(self.reset_login_btn)
            self.password_entry.textChanged.connect(self.reset_login_btn)
            
            # 进度条
            self.progress_bar = QProgressBar()
            self.progress_bar.setVisible(False)
            self.progress_bar.setMinimumHeight(10)
            main_layout.addWidget(self.progress_bar)

        def center_on_screen(self):
            """窗口居中显示"""
            screen = QDesktopWidget().screenGeometry()
            size = self.geometry()
            x = (screen.width() - size.width()) // 2
            y = (screen.height() - size.height()) // 2
            self.move(x, y)
        
        def on_login(self):
            """登录按钮事件"""
            username = self.username_entry.text().strip()
            password = self.password_entry.text().strip()
            
            if not username or not password:
                QMessageBox.warning(self, "提示", "账号和密码不能为空！")
                return
            
            # 更新并保存配置，无论登录成功与否
            self.parent_app.username = username
            self.parent_app.password = password
            self.parent_app.save_config()
            
            # 保存开机自启设置 - 使用同步函数确保状态一致
            current_startup_state = self.startup_check.isChecked()
            if current_startup_state != self.parent_app.auto_startup:
                self.parent_app.set_startup(current_startup_state)
            
            self.login_btn.setEnabled(False)
            self.login_btn.setText("登录中...")
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
            self.login_thread = LoginThread(self.parent_app, username, password)
            self.login_thread.login_signal.connect(self.on_login_result)
            self.login_thread.progress_signal.connect(self.on_login_progress)
            self.login_thread.start()
        
        def on_login_progress(self, value):
            """登录进度更新"""
            self.progress_bar.setValue(value)
        
        def on_login_result(self, success: bool, msg: str):
            """登录结果处理 - 关闭失败弹窗，仅修改按钮文字"""
            self.login_btn.setEnabled(True)
            self.progress_bar.setVisible(False)
            
            if success:
                self.login_btn.setText("✅ 账号已在线")
            else:
                # 仅修改按钮文字，不弹出任何窗口
                self.login_btn.setText("❌ 登录失败")
        
        def reset_login_btn(self):
            """重置登录按钮状态"""
            if self.login_btn.text() in ["✅ 账号已在线", "❌ 登录失败", "登录中..."]:
                self.login_btn.setText("立即登录")
                self.login_btn.setEnabled(True)

        def on_startup_state_changed(self, state):
            """开机自启状态变化处理 - 同步到托盘"""
            new_state = state == Qt.Checked
            # 只在状态实际变化时处理，避免循环调用
            if new_state != self.parent_app.auto_startup:
                self.parent_app.set_startup(new_state)

        def closeEvent(self, event):
            """窗口关闭事件"""
            if self.minimize_check.isChecked():
                self.hide()
                # 修复：确保最小化到托盘时托盘图标已创建且状态同步
                if not self.parent_app.pystray_icon:
                    self.parent_app.create_tray_icon()
                elif self.parent_app.pystray_icon:
                    self.parent_app.pystray_icon.update_menu()
                event.ignore()
            else:
                self.parent_app.cleanup()
                event.accept()
    
    return EnhancedMainWindow

# 创建EnhancedMainWindow类
EnhancedMainWindow = create_enhanced_main_window_class()

def main():
    """主函数"""
    # 处理静默启动参数
    if "--silent" in sys.argv:
        logger.info("进入静默登录模式")
        login_core = CampusNetLogin()
        # 直接执行登录（不显示窗口）
        login_success = login_core.auto_login()
        # 登录后无需保持进程，任务计划触发后执行一次即可
        sys.exit(0 if login_success else 1)
    
    # 正常启动（显示窗口）
    # 提前声明全局变量
    global QApplication, QMessageBox
    
    try:
        # 懒加载QApplication
        from PyQt5.QtWidgets import QApplication
        
        # 确保QApplication在主线程中创建
        if not QApplication.instance():
            app_instance = QApplication(sys.argv)
            app_instance.setQuitOnLastWindowClosed(False)
        else:
            app_instance = QApplication.instance()
        
        campus_net_app = CampusNetLogin(app_instance)
        campus_net_app.run()
        
        # 启动Qt事件循环
        if app_instance:
            sys.exit(app_instance.exec_())
    except Exception as e:
        logger.error(f"程序异常退出: {e}", exc_info=True)
        # 修复QApplication未初始化的问题
        from PyQt5.QtWidgets import QMessageBox
        
        if not QApplication.instance():
            app_instance = QApplication(sys.argv)
        QMessageBox.critical(None, "程序错误", f"程序运行出错：{str(e)}")
    finally:
        if QApplication.instance():
            QApplication.instance().quit()

if __name__ == "__main__":
    main()