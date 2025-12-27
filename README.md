# 校园网WiFi自动登录工具

<div align="center">
  <h3>自动化校园网登录解决方案</h3>
  
[![Python](https://img.shields.io/badge/Python-3.7%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078d7)](https://www.microsoft.com/windows)

</div>

## 📋 项目简介

校园网WiFi自动登录工具是一个专为校园网络环境设计的自动化登录软件，支持深圳大学等使用类似认证系统的校园网络。该工具可以自动检测网络状态、连接WiFi并完成认证登录，同时支持开机自启和后台运行。

## ✨ 功能特性

- **自动登录**：自动检测网络状态并完成校园网认证登录
- **多服务器支持**：内置主服务器和备用服务器，提高登录成功率
- **WiFi连接管理**：自动连接到目标WiFi网络（SZU_CTC&CMCC）
- **开机自启**：支持设置开机自动运行和登录
- **后台运行**：支持最小化到系统托盘，减少对桌面的占用
- **单实例运行**：防止多个实例同时运行
- **日志记录**：详细的运行日志，便于问题排查
- **密码加密**：支持密码加密存储，提高安全性
- **网络监控**：后台监控网络状态，断线自动重连
- **界面友好**：现代化的GUI界面，操作简便

## 🛠️ 系统要求

- Windows操作系统
- Python 3.7或更高版本
- 网络连接权限

## 📦 安装与使用

### 方法一：直接运行Python脚本

1. 克隆或下载项目到本地
2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```
3. 运行主程序：
   ```bash
   python WIFI.py
   ```

### 方法二：使用预编译的可执行文件

1. 从 [Releases](https://github.com/your-username/campus-wifi-auto-login/releases) 页面下载最新版本
2. 解压后双击运行 `校园网WiFi自动登录.exe`
3. 首次使用需输入校园网账号密码并保存

## 🚀 快速开始

1. 运行程序
2. 输入校园网账号和密码
3. 选择是否开机自启
4. 点击"立即登录"
5. 程序会自动完成登录并在系统托盘中运行

## 🔧 配置说明

- 程序会自动创建 `login_config.ini` 配置文件，保存用户登录信息和设置
- 登录信息使用加密方式存储，保障账号安全
- 日志文件保存在 `logs/campus_net.log`

## 🏗️ 项目结构

```
WIFI/
├── WIFI.py               # 主程序入口
├── requirements.txt      # 项目依赖
├── portable_exe_optimized.spec  # PyInstaller打包配置
├── dist/                 # 打包输出目录
│   └── 校园网WiFi自动登录.exe
├── login_config.ini      # 登录配置文件
├── logs/                 # 日志目录
│   └── campus_net.log    # 运行日志
└── README.md             # 项目说明文档
```

## 📚 技术栈

- **语言**: Python 3
- **GUI框架**: PyQt5
- **系统托盘**: pystray
- **图像处理**: Pillow
- **HTTP请求**: requests
- **加密库**: cryptography
- **Windows集成**: pywin32

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来帮助改进这个项目！

## ⚠️ 注意事项

1. 请确保在校园网环境下使用
2. 需要正确的校园网账号和密码
3. 首次使用需要手动输入账号密码
4. 建议启用开机自启功能以实现自动登录
5. 仅在合法授权的网络环境中使用

## 🐛 故障排除

如果遇到问题，请查看 `logs/campus_net.log` 文件中的详细日志信息。

常见问题：
- 网络连接失败：检查WiFi连接状态
- 登录失败：确认账号密码正确
- 程序无法启动：检查Python环境和依赖安装
- 托盘图标不显示：确认pystray库已正确安装

## 📄 许可证

本项目仅供学习和内部使用，请遵守相关网络使用规定。

---
<div align="center">

Made with ❤️ for campus network users

</div>