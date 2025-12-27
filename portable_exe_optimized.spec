# -*- mode: python ; coding: utf-8 -*-
"""
校园网WiFi自动登录工具打包配置 - 无线网络版
专门用于WiFi网络环境的校园网自动登录
"""
import os

datas = []
# 打包图标（如果有）
if os.path.exists('icon.ico'):
    datas.append(('icon.ico', '.'))

# 添加配置文件模板（如果不存在则创建）- 无线网络版默认配置
config_template = """[Login]
username = 
password = 

[System]
auto_startup = True
version = 2.3.1-WiFi
login_count = 0
total_logins = 0

[Stats]
last_login_time = 
"""

if not os.path.exists('login_config.ini'):
    with open('login_config.ini', 'w', encoding='utf-8') as f:
        f.write(config_template)
    datas.append(('login_config.ini', '.'))

a = Analysis(
    ['WIFI.py'],  # 你的主脚本名 - WiFi版
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'pystray', 'PIL', 'cryptography', 'win32event', 'win32api', 'win32con', 
        'win32gui', 'winerror', 'pythoncom', 'requests', 'urllib3', 'certifi',
        'socket', 'subprocess', 'threading', 'json', 'base64', 'hashlib',
        'platform', 'shutil', 'configparser', 'logging', 'datetime',
        'typing', 'time', 're', 'email', 'email.mime', 'email.mime.text', 
        'email.mime.multipart', 'email.mime.base', 'email.header', 'email.utils'  # WiFi连接相关依赖，包含email模块
    ],  # 必须的隐藏依赖，包含WiFi功能所需模块
    excludes=['tkinter', 'unittest', 'test', 'smtplib', 'poplib'],  # 排除无线网络版不需要的依赖，但保留email
    noarchive=False,
)
pyz = PYZ(a.pure)

# 单文件打包核心配置 - WiFi无线网络版
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name='校园网WiFi自动登录',  # 最终EXE文件名 - WiFi版
    debug=False,
    strip=False,
    upx=True,  # 压缩EXE，减小体积
    console=False,  # 关键：彻底关闭控制台
    windowed=True,   # 关键：窗口模式
    icon='icon.ico' if os.path.exists('icon.ico') else None,  # EXE图标
    disable_windowed_traceback=True,  # 禁用窗口化回溯
    argv_emulation=False,
    # WiFi版特定参数
    version=None,
    uac_admin=False,
    uac_uiaccess=False,
)