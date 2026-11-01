#!/usr/bin/env python3
"""
Linux服务器性能检查 - SSH连接脚本
使用方法: python scripts/ssh_perf_check.py <host> <port> <user> <password>
示例: python scripts/ssh_perf_check.py linux.example.invalid 22 inspector <ssh-password>
"""
import paramiko
import sys
import argparse

def collect_performance_data(host, port, user, password):
    """收集服务器性能数据"""

    commands = """echo '========================================'
echo '        Linux 服务器性能检查报告'
echo '========================================'
echo ''
echo '【1】系统概览'
echo '----------------------------------------'
hostname
cat /etc/redhat-release 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME
uptime
echo ''
echo '【2】CPU 信息'
echo '----------------------------------------'
cat /proc/cpuinfo | grep "model name" | head -1
echo "CPU核心数: $(nproc)"
echo ''
echo '【3】内存使用情况'
echo '----------------------------------------'
free -h
echo ''
echo '【4】磁盘使用情况'
echo '----------------------------------------'
df -h
echo ''
echo '【5】系统负载'
echo '----------------------------------------'
cat /proc/loadavg
echo ''
echo '【6】TOP 10 进程 (按CPU占用)'
echo '----------------------------------------'
ps aux --sort=-%cpu | head -11
echo ''
echo '【7】内存占用最高的进程'
echo '----------------------------------------'
ps aux --sort=-%mem | head -6
echo ''
echo '========================================'
echo '              检查完成'
echo '========================================'
"""

    try:
        print(f"正在连接到 {user}@{host}...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, port=port, username=user, password=password, timeout=30)
        print("连接成功！")

        stdin, stdout, stderr = client.exec_command(commands, get_pty=False)
        output = stdout.read().decode('utf-8', errors='ignore')
        errors = stderr.read().decode('utf-8', errors='ignore')

        client.close()

        return output, errors

    except paramiko.AuthenticationException:
        return None, "认证失败！请检查用户名和密码是否正确"
    except paramiko.SSHException as e:
        return None, f"SSH错误: {e}"
    except Exception as e:
        return None, f"发生错误: {e}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Linux服务器性能检查')
    parser.add_argument('host', help='服务器IP地址')
    parser.add_argument('port', type=int, default=22, help='SSH端口(默认22)')
    parser.add_argument('user', help='用户名')
    parser.add_argument('password', help='密码')

    args = parser.parse_args()

    output, errors = collect_performance_data(args.host, args.port, args.user, args.password)

    if output:
        print(output)
    else:
        print(f"错误: {errors}")
        sys.exit(1)
