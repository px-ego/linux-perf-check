#!/usr/bin/env python3
"""
自动SSH巡检脚本 - 使用pexpect自动输入密码
"""

import pexpect
import os
import sys
import time

def ssh_command_with_password(host, user, password, command):
    """
    使用pexpect执行SSH命令并自动输入密码
    """
    ssh_cmd = f'ssh {user}@{host} "{command}"'
    print(f"执行命令: {ssh_cmd}")

    try:
        # 启动SSH进程
        child = pexpect.spawn(ssh_cmd, timeout=30)

        # 等待密码提示
        i = child.expect(['password:', 'Password:', pexpect.EOF, pexpect.TIMEOUT])

        if i in [0, 1]:  # 找到密码提示
            child.sendline(password)
            child.expect(pexpect.EOF)
            result = child.before.decode('utf-8', errors='ignore')
            child.close()
            return result
        elif i == 2:  # 直接完成（可能已配置密钥认证）
            result = child.before.decode('utf-8', errors='ignore')
            child.close()
            return result
        else:  # 超时
            child.close()
            return f"SSH连接超时"

    except Exception as e:
        return f"SSH执行错误: {str(e)}"

def main():
    # 服务器信息通过环境变量提供，避免在 skill 中硬编码敏感信息。
    host = os.environ.get("LINUX_PERF_HOST", "").strip()
    user = os.environ.get("LINUX_PERF_USER", "root").strip()
    password = os.environ.get("LINUX_PERF_PASSWORD", "").strip()
    if not host or not user or not password:
        print("请先设置 LINUX_PERF_HOST、LINUX_PERF_USER、LINUX_PERF_PASSWORD")
        sys.exit(1)

    print("开始自动SSH巡检...")
    print("=" *3550)

    # 1. 测试连接和基础信息
    print("\n1. 测试SSH连接...")
    result = ssh_command_with_password(host, user, password, "echo 'SSH连接成功'; hostname")
    print(result)

    # 2. 获取系统信息
    print("\n2. 获取系统基本信息...")
    result = ssh_command_with_password(host, user, password, "uptime; echo '---'; free -h; echo '---'; df -h /")
    print(result)

    # 3. 检查运行的服务
    print("\n3. 检查运行的服务...")
    result = ssh_command_with_password(host, user, password, "systemctl list-units --type=service --state=running | head -20")
    print(result)

    # 4. 检查安全日志
    print("\n4. 检查最近登录失败...")
    result = ssh_command_with_password(host, user, password, "lastb | head -10")
    print(result)

    # 5. 检查网络连接
    print("\n5. 检查网络连接...")
    result = ssh_command_with_password(host, user, password, "ss -tulnp | grep LISTEN")
    print(result)

    # 6. 检查磁盘使用情况
    print("\n6. 详细磁盘使用情况...")
    result = ssh_command_with_password(host, user, password, "df -h")
    print(result)

    # 7. 检查进程占用资源
    print("\n7. 进程资源占用TOP10...")
    result = ssh_command_with_password(host, user, password, "ps aux --sort=-%cpu | head -11")
    print(result)

    print("\n" + "=" * 50)
    print("巡检完成!")

if __name__ == "__main__":
    main()
