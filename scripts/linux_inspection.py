#!/usr/bin/env python3
"""
Linux服务器全量巡检脚本 - SSH远程执行版
通过模块注册表选择巡检指标，支持密钥认证和密码认证
支持单机巡检和批量巡检（通过inventory.json）

使用方法:
  # 单机巡检
  python scripts/linux_inspection.py --host 192.0.2.10 --user root --password xxx
  python scripts/linux_inspection.py --host 192.0.2.10 --user root --key ~/.ssh/id_ed25519
  python scripts/linux_inspection.py --host 192.0.2.10 --user root --password xxx --check cpu,memory,disk

  # 批量巡检（通过服务器清单）
  python scripts/linux_inspection.py --inventory inventory.json
  python scripts/linux_inspection.py --inventory inventory.json --workers 5
  python scripts/linux_inspection.py --inventory inventory.json --check cpu,memory,disk,alert
"""

import paramiko
import sys
import argparse
import json
import re
import os
import socket
import threading
import select
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ===================== 巡检命令定义 =====================

CHECK_MODULES = {
    "system": {
        "title": "一、系统基础信息",
        "commands": r"""
echo '=== 1.1 系统版本 ==='
cat /etc/redhat-release 2>/dev/null || cat /etc/centos-release 2>/dev/null || cat /etc/os-release 2>/dev/null
echo '=== 1.2 内核版本 ==='
uname -r
echo '=== 1.3 主机名 ==='
hostname
echo '=== 1.4 网络配置 ==='
ip addr show 2>/dev/null | grep -E 'inet |link/' | head -20
echo '=== 1.5 网关 ==='
ip route show default 2>/dev/null || route -n 2>/dev/null | head -5
echo '=== 1.6 DNS ==='
cat /etc/resolv.conf 2>/dev/null | grep -v '^#' | grep -v '^$'
echo '=== 1.7 开机运行时长 ==='
uptime
echo '=== 1.8 服务器时区 ==='
timedatectl 2>/dev/null || date +'时区: %Z  时间: %Y-%m-%d %H:%M:%S'
echo '=== 1.9 当前登录用户 ==='
who
echo '=== 1.10 最近登录记录 ==='
last -10 2>/dev/null
echo '=== 1.11 失败登录记录 ==='
lastb -10 2>/dev/null || journalctl _SYSTEMD_UNIT=sshd.service -n 20 --no-pager 2>/dev/null | grep -i 'failed'
"""
    },

    "cpu": {
        "title": "二、CPU负载巡检",
        "commands": r"""
echo '=== 2.1 CPU型号 ==='
cat /proc/cpuinfo | grep 'model name' | head -1
echo '=== 2.2 CPU核心数 ==='
echo "物理核心数: $(cat /proc/cpuinfo | grep 'cpu cores' | head -1 | awk '{print $4}')"
echo "逻辑核心数: $(nproc)"
echo '=== 2.3 CPU使用率(整体) ==='
top -bn1 | head -5
echo '=== 2.4 1/5/15分钟负载 ==='
cat /proc/loadavg
echo '=== 2.5 TOP 10 CPU进程 ==='
ps aux --sort=-%cpu | head -11
"""
    },

    "memory": {
        "title": "三、内存&Swap巡检",
        "commands": r"""
echo '=== 3.1 物理内存 ==='
free -h
echo '=== 3.2 内存详细分布 ==='
cat /proc/meminfo | grep -E 'MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree|SwapCached|Dirty|AnonPages|Mapped|Shmem'
echo '=== 3.3 Swap分区 ==='
swapon --show 2>/dev/null || cat /proc/swaps
echo '=== 3.4 OOM日志(最近) ==='
dmesg | grep -i 'oom\|out of memory\|killed process' | tail -10 2>/dev/null
journalctl -k --no-pager -n 50 2>/dev/null | grep -i 'oom\|out of memory\|killed process' | tail -10
echo '=== 3.5 TOP 10 内存进程 ==='
ps aux --sort=-%mem | head -11
"""
    },

    "disk": {
        "title": "四、磁盘空间巡检",
        "commands": r"""
echo '=== 4.1 全盘分区使用率 ==='
df -hT
echo '=== 4.2 inode使用率 ==='
df -i
echo '=== 4.3 大文件TOP20(>100MB) ==='
for search_dir in /var /opt /data /home /tmp; do
    [ -d "$search_dir" ] && timeout 20 find "$search_dir" -maxdepth 6 -xdev -type f -size +100M -exec ls -lh {} \; 2>/dev/null
done | sort -k5 -hr | head -20
echo '=== 4.4 日志垃圾文件 ==='
find /var/log -maxdepth 4 -type f \( -name '*.gz' -o -name '*.old' -o -name '*.bak' -o -name '*.[0-9]' \) 2>/dev/null | head -20
echo '=== 4.5 /tmp目录大小 ==='
du -sh /tmp 2>/dev/null
echo '=== 4.6 磁盘IO ==='
iostat -x 1 1 2>/dev/null || cat /proc/diskstats 2>/dev/null | head -20
echo '=== 4.7 挂载状态 ==='
mount | grep -E 'ext|xfs|nfs|cifs' | head -20
echo '=== 4.8 只读/异常挂载 ==='
mount | grep -E 'ro,|ro\s'
findmnt -n -O ro 2>/dev/null
"""
    },

    "network": {
        "title": "五、网络状态巡检",
        "commands": r"""
echo '=== 5.1 网卡状态 ==='
ip link show 2>/dev/null || ifconfig -a 2>/dev/null
echo '=== 5.2 网卡流量 ==='
cat /proc/net/dev | awk 'NR>2 {printf "%-15s RX: %s bytes / TX: %s bytes\n", $1, $2, $10}'
echo '=== 5.3 监听端口 ==='
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
echo '=== 5.4 TCP连接统计 ==='
ss -s 2>/dev/null || netstat -s 2>/dev/null | head -20
echo '=== 5.5 TCP连接状态 ==='
ss -tan 2>/dev/null | awk 'NR>1 {print $1}' | sort | uniq -c | sort -rn
echo '=== 5.6 ESTABLISHED连接TOP20 ==='
ss -tnp state established 2>/dev/null | head -21
echo '=== 5.7 TIME_WAIT连接数 ==='
ss -tan state time-wait 2>/dev/null | wc -l
echo '=== 5.8 路由表 ==='
ip route show 2>/dev/null || route -n 2>/dev/null
echo '=== 5.9 防火墙状态 ==='
systemctl status firewalld 2>/dev/null | head -5
firewall-cmd --list-all 2>/dev/null
iptables -L -n 2>/dev/null | head -30
echo '=== 5.10 网卡丢包统计 ==='
ip -s link show 2>/dev/null | head -40
"""
    },

    "process": {
        "title": "六、进程&服务巡检",
        "commands": r"""
echo '=== 6.1 进程总数 ==='
echo "总进程数: $(ps aux | wc -l)"
echo '=== 6.2 僵尸进程 ==='
ps aux | awk '$8 ~ /Z/ {print $0}'
echo "僵尸进程数: $(ps aux | awk '$8 ~ /Z/' | wc -l)"
echo '=== 6.3 关键服务状态 ==='
for svc in sshd crond rsyslogd NetworkManager firewalld docker; do
    systemctl is-active $svc 2>/dev/null && echo "$svc: RUNNING" || echo "$svc: NOT RUNNING"
done
echo '=== 6.4 自启服务列表 ==='
systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -30
echo '=== 6.5 定时任务 ==='
echo "--- root crontab ---"
crontab -l 2>/dev/null
echo "--- /etc/crontab ---"
cat /etc/crontab 2>/dev/null
echo "--- /etc/cron.d/ ---"
ls -la /etc/cron.d/ 2>/dev/null
echo '=== 6.6 异常进程(高CPU>50%) ==='
ps aux --sort=-%cpu | awk 'NR>1 && $3>50 {print $0}'
echo '=== 6.7 异常进程(高MEM>50%) ==='
ps aux --sort=-%mem | awk 'NR>1 && $4>50 {print $0}'
"""
    },

    "log": {
        "title": "七、日志巡检",
        "commands": r"""
echo '=== 7.1 系统日志(最近50行) ==='
tail -50 /var/log/messages 2>/dev/null || journalctl -n 50 --no-pager 2>/dev/null
echo '=== 7.2 系统日志ERROR ==='
grep -i 'error\|fail\|critical\|emergency' /var/log/messages 2>/dev/null | tail -30
journalctl -p err --no-pager -n 30 2>/dev/null
echo '=== 7.3 登录安全日志 ==='
tail -50 /var/log/secure 2>/dev/null || journalctl -u sshd --no-pager -n 50 2>/dev/null
echo '=== 7.4 暴力破解记录 ==='
grep -i 'failed password\|invalid user' /var/log/secure 2>/dev/null | tail -20
journalctl _SYSTEMD_UNIT=sshd.service --no-pager -n 30 2>/dev/null | grep -i 'failed'
echo '=== 7.5 内核报错 ==='
dmesg | grep -i 'error\|warning\|fail\|bug' | tail -20
echo '=== 7.6 最近重启记录 ==='
last reboot | head -10
echo '=== 7.7 崩溃/OOM ==='
journalctl --no-pager -n 100 2>/dev/null | grep -iE 'crash|panic|oom|killed' | tail -20
"""
    },

    "security": {
        "title": "八、用户与安全巡检",
        "commands": r"""
echo '=== 8.1 可登录用户 ==='
cat /etc/passwd | grep -E 'bash|sh$' | cut -d: -f1,7
echo '=== 8.2 空密码账号 ==='
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null
echo '=== 8.3 UID=0特权账号 ==='
awk -F: '$3 == 0 {print $1}' /etc/passwd
echo '=== 8.4 sudo权限用户 ==='
getent group sudo wheel 2>/dev/null
cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' | head -20
echo '=== 8.5 最近密码变更 ==='
chage -l root 2>/dev/null | head -10
echo '=== 8.6 可疑定时任务(all用户) ==='
for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u $u 2>/dev/null | grep -v '^#' | grep -v '^$' && echo "  -- user: $u"; done
echo '=== 8.7 SSH配置安全 ==='
grep -E 'PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port ' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'
echo '=== 8.8 SSH授权密钥 ==='
for u in $(cut -f1 -d: /etc/passwd); do
    keys=$(cat /home/$u/.ssh/authorized_keys 2>/dev/null)
    if [ -n "$keys" ]; then echo "=== $u authorized_keys ==="; echo "$keys"; fi
done
cat /root/.ssh/authorized_keys 2>/dev/null
"""
    },

    "hardware": {
        "title": "九、硬件状态巡检",
        "commands": r"""
echo '=== 9.1 CPU温度 ==='
cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | awk '{printf "温度: %.1f°C\n", $1/1000}'
sensors 2>/dev/null | head -20
echo '=== 9.2 内存硬件信息(DMI) ==='
dmidecode -t memory 2>/dev/null | grep -E 'Size|Type:|Speed|Manufacturer' | head -20
echo '=== 9.3 硬盘信息 ==='
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL 2>/dev/null
echo '=== 9.4 硬盘健康(SMART) ==='
smartctl -H /dev/sda 2>/dev/null || echo 'smartctl未安装，跳过SMART检查'
echo '=== 9.5 RAID状态 ==='
megacli -PDList -aAll 2>/dev/null | head -30
megacli -LDInfo -Lall -aAll 2>/dev/null | head -20
mdadm --detail /dev/md* 2>/dev/null | head -30
echo '=== 9.6 DMI系统信息 ==='
dmidecode -t system 2>/dev/null | head -20
echo '=== 9.7 PCI设备 ==='
lspci 2>/dev/null | head -20
"""
    },

    "middleware": {
        "title": "十、数据库/中间件专项",
        "commands": r"""
echo '=== 10.1 MySQL状态 ==='
systemctl status mysqld mariadb mysql 2>/dev/null | head -10
mysqladmin -u root -e 'status' 2>/dev/null
mysql -u root -e 'SHOW GLOBAL STATUS LIKE "Threads_connected"; SHOW GLOBAL STATUS LIKE "Slow_queries"; SHOW PROCESSLIST;' 2>/dev/null | head -30
echo '=== 10.2 Redis状态 ==='
systemctl status redis redis-server 2>/dev/null | head -5
redis-cli info 2>/dev/null | grep -E 'used_memory|maxmemory|connected_clients|blocked_clients|uptime'
echo '=== 10.3 Nginx状态 ==='
systemctl status nginx 2>/dev/null | head -5
nginx -t 2>/dev/null
curl -s http://localhost/nginx_status 2>/dev/null
curl -s http://127.0.0.1:80/ 2>/dev/null | head -5
echo '=== 10.4 Tomcat状态 ==='
ps aux | grep -i tomcat | grep -v grep
systemctl status tomcat 2>/dev/null | head -5
netstat -tlnp 2>/dev/null | grep java
echo '=== 10.5 Java进程 ==='
jps -lv 2>/dev/null
ps aux | grep java | grep -v grep | head -10
echo '=== 10.6 Docker状态 ==='
systemctl status docker 2>/dev/null | head -5
docker ps 2>/dev/null
docker stats --no-stream 2>/dev/null
echo '=== 10.7 其他常见服务 ==='
for svc in httpd postgresql mongodb elasticsearch rabbitmq kafka zookeeper; do
    systemctl is-active $svc 2>/dev/null && echo "$svc: RUNNING" || true
done
"""
    },

    "backup": {
        "title": "十一、备份&业务巡检",
        "commands": r"""
echo '=== 11.1 crontab备份任务 ==='
grep -ri 'backup\|bak\|dump\|rsync' /var/spool/cron/* 2>/dev/null
grep -ri 'backup\|bak\|dump\|rsync' /etc/crontab /etc/cron.d/* 2>/dev/null
echo '=== 11.2 备份目录 ==='
ls -lh /backup/ 2>/dev/null | tail -20
ls -lh /data/backup/ 2>/dev/null | tail -20
echo '=== 11.3 MySQL备份文件 ==='
find /backup /data/backup /home -name '*.sql' -mtime -7 -exec ls -lh {} \; 2>/dev/null | head -20
echo '=== 11.4 业务端口可用性 ==='
for port in 80 443 8080 3306 6379 22; do
    (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null && echo "端口 $port: 可达" || echo "端口 $port: 不可达"
done
echo '=== 11.5 SSL证书有效期 ==='
for cert in /etc/pki/tls/certs/*.pem /etc/ssl/certs/*.pem /etc/nginx/ssl/*.pem; do
    if [ -f "$cert" ]; then
        echo -n "$cert 有效期: "
        openssl x509 -in "$cert" -noout -enddate 2>/dev/null
    fi
done
echo '=== 11.6 网站可达性 ==='
curl -sI --connect-timeout 5 http://localhost 2>/dev/null | head -5
"""
    },

        "alert": {
        "title": "十二、资源阈值告警汇总",
        "commands": r"""
echo '=== 12.1 CPU使用率 ==='
CPU_IDLE=$(top -bn1 | grep 'Cpu' | awk '{print $8}' | cut -d'%' -f1)
CPU_USED=$(echo "100 - ${CPU_IDLE:-0}" | bc 2>/dev/null || echo "N/A")
echo "CPU使用率: ${CPU_USED}%"
echo '=== 12.2 内存使用率 ==='
MEM_TOTAL=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
MEM_AVAIL=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
if [ -n "$MEM_TOTAL" ] && [ -n "$MEM_AVAIL" ]; then
    MEM_USED_PCT=$(awk "BEGIN {printf \"%.1f\", ($MEM_TOTAL - $MEM_AVAIL) / $MEM_TOTAL * 100}")
    echo "内存使用率: ${MEM_USED_PCT}%"
else
    echo "内存使用率: N/A"
fi
echo '=== 12.3 磁盘使用率(>85%告警) ==='
df -h | awk 'NR>1 && int($5) > 85 {print "告警: " $0}'
echo '=== 12.4 Swap使用率 ==='
SWAP_TOTAL=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)
SWAP_FREE=$(awk '/SwapFree/ {print $2}' /proc/meminfo)
if [ -n "$SWAP_TOTAL" ] && [ "$SWAP_TOTAL" -gt 0 ]; then
    SWAP_PCT=$(awk "BEGIN {printf \"%.1f\", ($SWAP_TOTAL - $SWAP_FREE) / $SWAP_TOTAL * 100}")
    echo "Swap使用率: ${SWAP_PCT}%"
    if [ "$(awk "BEGIN {print ($SWAP_TOTAL - $SWAP_FREE) / $SWAP_TOTAL * 100 > 50}")" = "1" ]; then
        echo "告警: Swap使用率超过50%"
    fi
else
    echo "Swap: 未配置或未使用"
fi
echo '=== 12.5 失败登录次数 ==='
FAIL_COUNT=$(grep -c 'Failed password' /var/log/secure 2>/dev/null)
echo "最近失败登录次数: ${FAIL_COUNT:-0}"
echo '=== 12.6 僵尸进程 ==='
ZOMBIE_COUNT=$(ps aux | awk '$8 ~ /Z/' | wc -l)
echo "僵尸进程数: $ZOMBIE_COUNT"
echo '=== 12.7 磁盘inode使用率(>85%告警) ==='
df -i | awk 'NR>1 && int($5) > 85 {print "告警: " $0}'
echo '=== 12.8 TCP连接状态汇总 ==='
ss -tan 2>/dev/null | awk 'NR>1 {s[$1]++} END {for(k in s) print k": "s[k]}' | sort -t: -k2 -rn
"""
    },

    "jvm_crash": {
        "title": "十三、Java 宕机分析",
        "commands": r"""
echo '=== 13.1 Java 进程列表 ==='
JAVA_COUNT=$(ps aux | grep '[j]ava' | grep -vc 'bash -c')
echo "Java进程总数: $JAVA_COUNT"
jps -lv 2>/dev/null || echo '[提示] jps 命令不可用'
ps aux | grep '[j]ava' | grep -v 'bash -c' | head -20

echo '=== 13.2 JVM 崩溃日志(30天内) ==='
CRASH_LOGS=$(timeout 30 find /var /opt /home /tmp /data -maxdepth 5 -name "hs_err_pid*.log" -mtime -30 2>/dev/null)
CRASH_COUNT=$(echo "$CRASH_LOGS" | grep -c 'hs_err_pid' 2>/dev/null || echo 0)
echo "近30天 JVM crash 日志数: $CRASH_COUNT"
if [ -n "$CRASH_LOGS" ] && [ "$CRASH_COUNT" -gt 0 ]; then
    echo "$CRASH_LOGS" | while IFS= read -r f; do
        [ -z "$f" ] && continue
        echo ""
        echo "========== $f (仅摘要) =========="
        head -50 "$f" 2>/dev/null
        echo "========== EOF =========="
        echo ""
    done
fi

echo '=== 13.3 系统 OOM Killer 记录 ==='
dmesg 2>/dev/null | grep -i 'out of memory\|killed process\|oom' | tail -20
journalctl -k --no-pager -n 100 2>/dev/null | grep -i 'out of memory\|killed process\|oom' | tail -20 || true

echo '=== 13.4 每个 Java 进程诊断快照 ==='
for pid in $(jps -q 2>/dev/null); do
    echo ""
    echo "========== PID: $pid =========="
    echo "--- 进程资源 ---"
    ps -p $pid -o pid,ppid,user,%cpu,%mem,rss,vsz,etime,args --no-headers 2>/dev/null
    echo "--- jstat GC 统计(最近1次快照) ---"
    jstat -gcutil $pid 1 1 2>/dev/null || echo 'jstat 不可用(需JDK)'
    echo "--- 堆内存对象 TOP 20 ---"
    jmap -histo:live $pid 2>/dev/null | head -23 || echo '[提示] jmap 不可用(可能需 root 或 JDK 版本不匹配)'
    echo "--- 线程状态统计 ---"
    jstack $pid 2>/dev/null | grep 'java.lang.Thread.State' | awk -F': ' '{print $2}' | sort | uniq -c | sort -rn || echo 'jstack 不可用'
    echo "--- 死锁检测 ---"
    jstack -l $pid 2>/dev/null | grep -A 60 'Found.*deadlock' || echo '未检测到死锁'
    echo "--- BLOCKED 线程(前10) ---"
    jstack $pid 2>/dev/null | grep -B 1 -A 10 'BLOCKED' | head -60 || true
    echo ""
done 2>/dev/null

echo '=== 13.5 应用日志异常(最近1天) ==='
for logdir in /opt /app /home /data /usr/local /var/log; do
    [ -d "$logdir" ] || continue
    timeout 30 find $logdir -maxdepth 5 -path "*/logs/*" -name "*.log" -mtime -1 2>/dev/null | while read f; do
        if timeout 10 grep -qil 'exception\|error\|fatal\|outofmemory\|OutOfMemory\|StackOverflow\|timeout' "$f" 2>/dev/null; then
            echo "--- $f ---"
            grep -i 'exception\|error\|fatal\|outofmemory\|StackOverflow' "$f" 2>/dev/null | tail -10
        fi
    done
done 2>/dev/null || true
echo '[提示] 应用日志扫描完成'
"""
    },

    "mysql_deep": {
        "title": "十四、MySQL深度诊断",
        "type": "python_db",
        "runner": "run_mysql_deep",
    },
    "oracle_deep": {
        "title": "十五、Oracle深度诊断",
        "type": "python_db",
        "runner": "run_oracle_deep",
    },
    "mssql_deep": {
        "title": "十六、SQL Server深度诊断",
        "type": "python_db",
        "runner": "run_mssql_deep",
    },
    "db_health": {
        "title": "十五、数据库健康诊断",
        "type": "ssh_db",
        "queries": [
            ("版本与运行时间",
             "SELECT VERSION() AS version, NOW() AS current_time, "
             "  FLOOR(VARIABLE_VALUE / 86400) AS uptime_days "
             "FROM performance_schema.global_status WHERE VARIABLE_NAME='Uptime';"),
            ("总大小",
             "SELECT ROUND(SUM(data_length + index_length) / 1073741824, 2) AS total_size_gb "
             "FROM information_schema.TABLES;"),
            ("连接状态",
             "SELECT COUNT(*) AS total, "
             "  SUM(CASE WHEN state IS NOT NULL AND state != '' THEN 1 ELSE 0 END) AS active, "
             "  SUM(CASE WHEN time > 30 THEN 1 ELSE 0 END) AS long_running_30s "
             "FROM information_schema.PROCESSLIST;"),
            ("缓冲池命中率",
             "SELECT ROUND((1 - "
             "  (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Innodb_buffer_pool_reads') / "
             "  GREATEST((SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Innodb_buffer_pool_read_requests'), 1)) * 100, 2) AS buffer_pool_hit_pct;"),
            ("慢查询统计",
             "SELECT VARIABLE_VALUE AS slow_query_count "
             "FROM performance_schema.global_status WHERE VARIABLE_NAME='Slow_queries';"),
            ("数据库大小 TOP10",
             "SELECT table_schema AS db, "
             "  ROUND(SUM(data_length + index_length) / 1073741824, 4) AS size_gb "
             "FROM information_schema.TABLES GROUP BY table_schema "
             "ORDER BY size_gb DESC LIMIT 10;"),
            ("大表 TOP10",
             "SELECT table_schema AS db, table_name AS tbl, "
             "  ROUND((data_length + index_length) / 1073741824, 4) AS size_gb, "
             "  table_rows AS rows_est "
             "FROM information_schema.TABLES "
             "WHERE table_schema NOT IN ('mysql','sys','performance_schema','information_schema') "
             "ORDER BY (data_length + index_length) DESC LIMIT 10;"),
            ("连接使用率",
             "SELECT ROUND("
             "  (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Threads_connected') * 100.0 / "
             "  (SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME='max_connections'), 2) AS conn_usage_pct;"),
            ("瓶颈检测(五大方向)",
             "-- CPU: 活跃线程\n"
             "SELECT 'CPU_threads_running' AS metric, VARIABLE_VALUE AS value FROM performance_schema.global_status WHERE VARIABLE_NAME='Threads_running'\n"
             "UNION ALL\n"
             "-- 锁: 行锁等待\n"
             "SELECT 'row_lock_waits' AS metric, VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Innodb_row_lock_current_waits'\n"
             "UNION ALL\n"
             "-- IO: 缓冲池读请求\n"
             "SELECT 'bp_read_requests' AS metric, VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Innodb_buffer_pool_read_requests'\n"
             "UNION ALL\n"
             "SELECT 'bp_reads' AS metric, VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Innodb_buffer_pool_reads';"),
            ("当前活跃查询 TOP5",
             "SELECT id, user, host, db, time AS sec, state, LEFT(INFO, 120) AS query "
             "FROM information_schema.PROCESSLIST "
             "WHERE command != 'Sleep' ORDER BY time DESC LIMIT 5;"),
        ],
    },
    "db_security": {
        "title": "十六、数据库安全审计",
        "type": "ssh_db",
        "queries": [
            ("匿名用户/空密码",
             "SELECT user, host, plugin FROM mysql.user WHERE user='' OR authentication_string='' OR plugin='';"),
            ("任意主机访问",
             "SELECT user, host FROM mysql.user WHERE host='%';"),
            ("用户权限列表",
             "SELECT user, host, Select_priv, Insert_priv, Update_priv, Delete_priv, "
             "  Create_priv, Drop_priv, Grant_priv, Super_priv FROM mysql.user;"),
            ("关键安全配置",
             "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables "
             "WHERE VARIABLE_NAME IN ('local_infile','secure_file_priv','log_bin','general_log','sql_mode',"
             "'default_authentication_plugin','validate_password.policy');"),
            ("敏感数据列扫描",
             "SELECT table_schema, table_name, column_name, "
             "  CASE WHEN column_name REGEXP 'pass|pwd' THEN '密码' "
             "       WHEN column_name REGEXP 'phone|mobile' THEN '手机号' "
             "       WHEN column_name REGEXP 'email|mail' THEN '邮箱' "
             "       WHEN column_name REGEXP 'id_card|card_no' THEN '身份证/卡号' "
             "       WHEN column_name REGEXP 'salary|bank' THEN '财务' "
             "  END AS sensitive_type "
             "FROM information_schema.COLUMNS "
             "WHERE table_schema NOT IN ('mysql','sys','performance_schema','information_schema') "
             "  AND (column_name REGEXP 'pass|pwd|phone|mobile|email|mail|id_card|card_no|salary|bank') "
             "ORDER BY table_schema, table_name;"),
        ],
    },
    "db_locks": {
        "title": "十七、数据库锁分析",
        "type": "ssh_db",
        "queries": [
            ("当前事务概览",
             "SELECT COUNT(*) AS total_trx, "
             "  SUM(CASE WHEN trx_state='LOCK WAIT' THEN 1 ELSE 0 END) AS lock_waiting, "
             "  MAX(TIMESTAMPDIFF(SECOND, trx_started, NOW())) AS max_trx_age_sec, "
             "  SUM(CASE WHEN trx_state='RUNNING' AND TIMESTAMPDIFF(SECOND, trx_started, NOW()) > 300 THEN 1 ELSE 0 END) AS long_running_5min "
             "FROM information_schema.INNODB_TRX;"),
            ("锁等待详情(MySQL 8.0+)",
             "SELECT waiting_pid, waiting_query, blocking_pid, blocking_query, "
             "  wait_age_secs, locked_table, locked_index, locked_type "
             "FROM sys.innodb_lock_waits;"),
            ("阻塞链(MySQL 5.7兼容)",
             "SELECT r.trx_mysql_thread_id AS waiting_thread, "
             "  TIMESTAMPDIFF(SECOND, r.trx_started, NOW()) AS wait_sec, "
             "  LEFT(r.trx_query, 100) AS waiting_query, "
             "  b.trx_mysql_thread_id AS blocking_thread, "
             "  LEFT(b.trx_query, 100) AS blocking_query "
             "FROM information_schema.INNODB_LOCK_WAITS w "
             "JOIN information_schema.INNODB_TRX r ON w.requesting_trx_id=r.trx_id "
             "JOIN information_schema.INNODB_TRX b ON w.blocking_trx_id=b.trx_id;"),
            ("InnoDB引擎锁状态",
             "SELECT lock_type, lock_table, lock_index, lock_mode, lock_status, lock_data "
             "FROM performance_schema.data_locks LIMIT 20;"),
        ],
    },
    "db_backup": {
        "title": "十八、数据库备份调度",
        "type": "ssh_db",
        "queries": [
            ("备份相关配置",
             "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables "
             "WHERE VARIABLE_NAME IN ('log_bin','expire_logs_days','binlog_expire_logs_seconds',"
             "'innodb_data_home_dir','datadir');"),
            ("表列表(按引擎)",
             "SELECT ENGINE, COUNT(*) AS table_count, "
             "  ROUND(SUM(data_length + index_length) / 1073741824, 2) AS total_gb "
             "FROM information_schema.TABLES "
             "WHERE table_schema NOT IN ('mysql','sys','performance_schema','information_schema') "
             "GROUP BY ENGINE ORDER BY total_gb DESC;"),
            ("自增ID使用率(风险预测)",
             "SELECT table_schema, table_name, auto_increment, "
             "  IFNULL(COLUMN_TYPE, 'N/A') AS col_type, "
             "  CASE "
             "    WHEN COLUMN_TYPE LIKE '%int%' AND auto_increment > 2000000000 THEN 'HIGH' "
             "    WHEN auto_increment > 1000000000 THEN 'MED' "
             "    ELSE 'OK' "
             "  END AS risk "
             "FROM information_schema.TABLES "
             "WHERE auto_increment IS NOT NULL AND auto_increment > 100000 "
             "ORDER BY auto_increment DESC LIMIT 20;"),
        ],
    },
    "db_sql": {
        "title": "十九、SQL审核辅助",
        "type": "ssh_db",
        "queries": [
            ("无主键表",
             "SELECT table_schema, table_name, engine, table_rows "
             "FROM information_schema.TABLES "
             "WHERE table_schema NOT IN ('mysql','sys','performance_schema','information_schema') "
             "  AND table_type='BASE TABLE' "
             "  AND table_name NOT IN ("
             "    SELECT DISTINCT table_name FROM information_schema.TABLE_CONSTRAINTS "
             "    WHERE constraint_type='PRIMARY KEY' AND table_schema NOT IN ('mysql','sys','performance_schema','information_schema')"
             "  ) "
             "ORDER BY table_rows DESC LIMIT 30;"),
            ("缺失索引建议(全表扫描表)",
             "SELECT t.table_schema, t.table_name, "
             "  ROUND(t.data_length / 1073741824, 3) AS size_gb, "
             "  t.table_rows, "
             "  (SELECT COUNT(*) FROM information_schema.STATISTICS s "
             "   WHERE s.table_schema=t.table_schema AND s.table_name=t.table_name) AS idx_count "
             "FROM information_schema.TABLES t "
             "WHERE t.table_schema NOT IN ('mysql','sys','performance_schema','information_schema') "
             "  AND t.table_type='BASE TABLE' "
             "  AND t.table_rows > 10000 "
             "ORDER BY t.table_rows DESC LIMIT 20;"),
            ("未使用索引(MySQL 8.0+)",
             "SELECT object_schema, object_name, index_name, "
             "  COUNT_STAR AS total_io, COUNT_READ, COUNT_WRITE "
             "FROM performance_schema.table_io_waits_summary_by_index_usage "
             "WHERE object_schema NOT IN ('mysql','sys','performance_schema') "
             "  AND index_name IS NOT NULL "
             "  AND COUNT_READ=0 "
             "ORDER BY COUNT_STAR DESC LIMIT 30;"),
            ("冗余索引检测",
             "SELECT table_schema, table_name, index_name, "
             "  GROUP_CONCAT(column_name ORDER BY seq_in_index) AS columns_included, "
             "  COUNT(*) AS col_count "
             "FROM information_schema.STATISTICS "
             "WHERE table_schema NOT IN ('mysql','sys','performance_schema','information_schema') "
             "  AND index_name != 'PRIMARY' "
             "GROUP BY table_schema, table_name, index_name "
             "HAVING col_count > 2 "
             "ORDER BY col_count DESC LIMIT 30;"),
        ],
    },
}

# 所有可用模块名称
ALL_MODULES = list(CHECK_MODULES.keys())

# ===================== Python 数据库直连函数 =====================

def _fmt_table(cursor, rows):
    """把查询结果格式化为 mysql CLI 风格的制表符分隔文本"""
    headers = [d[0] for d in cursor.description]
    lines = ['\t'.join(str(h) for h in headers)]
    for row in rows:
        lines.append('\t'.join(str(v) if v is not None else 'NULL' for v in row))
    return '\n'.join(lines)


def _fetch_one(cursor, sql):
    """执行SQL并格式化单行结果（无标题）"""
    cursor.execute(sql)
    row = cursor.fetchone()
    if row:
        return '\n'.join(str(v) if v is not None else 'NULL' for v in row)
    return ''


def run_mysql_deep_inspection(creds, ssh_client=None):
    """pymysql 直连 MySQL，直连失败时通过 SSH 隧道回退，返回 (stdout_text, stderr_text)"""
    import pymysql
    out = []
    err = []
    label = "14"

    def _connect(host, port):
        return pymysql.connect(
            host=host, port=port,
            user=creds['user'], password=creds['password'],
            connect_timeout=10, read_timeout=60,
            charset='utf8mb4', cursorclass=pymysql.cursors.Cursor
        )

    tunnel_sock = None
    cur = None
    conn = None

    # 尝试直连
    try:
        conn = _connect(creds['host'], creds['port'])
        cur = conn.cursor()
    except pymysql.Error as e1:
        # 直连失败，尝试SSH端口转发
        if ssh_client is None:
            return None, f'[错误] MySQL连接失败: {e1}'
        try:
            tunnel_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tunnel_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tunnel_sock.bind(('127.0.0.1', 0))
            tunnel_sock.listen(1)
            local_port = tunnel_sock.getsockname()[1]

            def _forward():
                try:
                    client, _ = tunnel_sock.accept()
                    chan = ssh_client.get_transport().open_channel(
                        "direct-tcpip", (creds['host'], creds['port']), client.getpeername()
                    )
                    while True:
                        r, w, x = select.select([client, chan], [], [], 1)
                        if client in r:
                            data = client.recv(4096)
                            if not data: break
                            chan.send(data)
                        if chan in r:
                            data = chan.recv(4096)
                            if not data: break
                            client.send(data)
                except Exception:
                    pass

            threading.Thread(target=_forward, daemon=True).start()
            conn = _connect('127.0.0.1', local_port)
            cur = conn.cursor()
            out.append(f'[信息] 通过SSH隧道连接 {creds["host"]}:{creds["port"]}\n')
        except Exception as e2:
            return None, f'[错误] MySQL直连失败({e1})，SSH隧道也失败({e2})'

    try:
        # 14.1 基础状态
        out.append(f'=== {label}.1 基础状态 ===')
        out.append(_fetch_one(cur, "SELECT VERSION() AS version"))
        cur.execute("SHOW GLOBAL STATUS LIKE 'Uptime'")
        out.append(_fmt_table(cur, cur.fetchall()))
        cur.execute("SHOW GLOBAL STATUS LIKE 'Threads_connected'")
        out.append(_fmt_table(cur, cur.fetchall()))
        cur.execute("SHOW GLOBAL VARIABLES LIKE 'max_connections'")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 14.2 连接使用率
        out.append(f'=== {label}.2 连接使用率 ===')
        cur.execute("""
            SELECT
              (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Threads_connected') AS connected,
              (SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME='max_connections') AS max_conn,
              ROUND((SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Threads_connected') /
                    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME='max_connections') * 100, 1) AS usage_pct
        """)
        out.append(_fmt_table(cur, cur.fetchall()))

        # 14.2b 连接池详情
        out.append(f'=== {label}.2b 连接池详情 ===')
        cur.execute("SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_running','Aborted_connects','Aborted_clients','Max_used_connections','Connection_errors_max_connections','Connection_errors_internal','Connection_errors_accept')")
        rows = list(cur.fetchall())
        rows.sort(key=lambda r: r[0])
        out.append(_fmt_table(cur, rows))

        # 14.3 内存配置
        out.append(f'=== {label}.3 内存配置 ===')
        cur.execute("SHOW GLOBAL VARIABLES WHERE Variable_name IN ('innodb_buffer_pool_size','key_buffer_size','query_cache_size','innodb_log_buffer_size','tmp_table_size','max_heap_table_size','innodb_buffer_pool_instances')")
        rows = list(cur.fetchall())
        rows.sort(key=lambda r: r[0])  # MySQL 5.7 SHOW VARIABLES 不支持 ORDER BY
        out.append(_fmt_table(cur, rows))

        # 14.4 缓冲池命中率
        out.append(f'=== {label}.4 缓冲池命中率 ===')
        out.append(_fetch_one(cur, """
            SELECT ROUND((1 - (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Innodb_buffer_pool_reads') /
                       (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Innodb_buffer_pool_read_requests')) * 100, 2) AS hit_ratio
        """))

        # 14.5 数据库大小 TOP10（独立连接，避免卡死主连接）
        out.append(f'=== {label}.5 数据库大小 TOP10 ===')
        try:
            _ic = pymysql.connect(
                host=creds['host'], port=creds['port'],
                user=creds['user'], password=creds['password'],
                connect_timeout=5, read_timeout=30,
                charset='utf8mb4', cursorclass=pymysql.cursors.Cursor
            )
            _icu = _ic.cursor()
            _icu.execute("""
                SELECT table_schema AS '数据库',
                  ROUND(SUM(data_length+index_length)/1024/1024/1024,3) AS '大小_GB',
                  COUNT(*) AS '表数量'
                FROM information_schema.tables
                WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys')
                GROUP BY table_schema
                ORDER BY SUM(data_length+index_length) DESC
                LIMIT 10
            """)
            out.append(_fmt_table(_icu, _icu.fetchall()))
            _ic.close()
        except Exception:
            out.append('[提示] information_schema查询超时(>30s)，跳过DB大小检查')

        # 14.6 大表 TOP10（优先 information_schema，超时则回退 innodb_table_stats）
        out.append(f'=== {label}.6 大表 TOP10 ===')
        large_tables_ok = False
        try:
            _ic = pymysql.connect(
                host=creds['host'], port=creds['port'],
                user=creds['user'], password=creds['password'],
                connect_timeout=5, read_timeout=30,
                charset='utf8mb4', cursorclass=pymysql.cursors.Cursor
            )
            _icu = _ic.cursor()
            _icu.execute("""
                SELECT table_schema AS '库', table_name AS '表',
                  ROUND((data_length+index_length)/1024/1024/1024,3) AS '大小_GB',
                  table_rows AS '估算行数',
                  engine AS '引擎'
                FROM information_schema.tables
                WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys')
                ORDER BY (data_length+index_length) DESC
                LIMIT 10
            """)
            out.append(_fmt_table(_icu, _icu.fetchall()))
            _ic.close()
            large_tables_ok = True
        except Exception:
            out.append('[提示] information_schema查询超时(>30s)，尝试 mysql.innodb_table_stats 回退...')

        # 回退：使用 mysql.innodb_table_stats（仅 InnoDB，速度极快）
        if not large_tables_ok:
            try:
                _ic2 = pymysql.connect(
                    host=creds['host'], port=creds['port'],
                    user=creds['user'], password=creds['password'],
                    connect_timeout=5, read_timeout=15,
                    charset='utf8mb4', cursorclass=pymysql.cursors.Cursor
                )
                _ic2u = _ic2.cursor()
                _ic2u.execute("""
                    SELECT database_name AS '库', table_name AS '表',
                      ROUND((clustered_index_size+sum_of_other_index_sizes)*@@innodb_page_size/1024/1024/1024,3) AS '大小_GB',
                      n_rows AS '估算行数',
                      'InnoDB' AS '引擎'
                    FROM mysql.innodb_table_stats
                    WHERE database_name NOT IN ('mysql','sys')
                    ORDER BY (clustered_index_size+sum_of_other_index_sizes) DESC
                    LIMIT 10
                """)
                out.append(_fmt_table(_ic2u, _ic2u.fetchall()))
                out.append('[提示] 仅覆盖 InnoDB 表，MyISAM/其他引擎表未包含')
                _ic2.close()
            except Exception as e2:
                out.append(f'[提示] innodb_table_stats 回退也失败: {e2}')

        # 14.7 性能指标
        out.append(f'=== {label}.7 性能指标 ===')
        cur.execute("SHOW GLOBAL STATUS WHERE Variable_name IN ('Slow_queries','Questions','Com_select','Com_insert','Com_update','Com_delete','Innodb_row_lock_waits','Innodb_row_lock_time_avg','Select_scan','Created_tmp_disk_tables','Created_tmp_tables')")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 14.8 慢查询配置
        out.append(f'=== {label}.8 慢查询配置 ===')
        try:
            cur.execute("SELECT COUNT(*) AS slow_query_count FROM mysql.slow_log")
            out.append(_fmt_table(cur, cur.fetchall()))
        except Exception:
            out.append('[提示] slow_log表不可用或未启用')
        cur.execute("SHOW GLOBAL VARIABLES LIKE 'slow_query_log'")
        out.append(_fmt_table(cur, cur.fetchall()))
        cur.execute("SHOW GLOBAL VARIABLES LIKE 'long_query_time'")
        out.append(_fmt_table(cur, cur.fetchall()))
        cur.execute("SHOW GLOBAL VARIABLES LIKE 'slow_query_log_file'")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 14.8b 慢查询摘要（性能模式 Top 10）
        out.append(f'=== {label}.8b 慢查询摘要(Top10) ===')
        try:
            cur.execute("""
                SELECT LEFT(DIGEST_TEXT, 120) AS query_snippet,
                  COUNT_STAR AS exec_count,
                  ROUND(AVG_TIMER_WAIT/1000000000000, 2) AS avg_sec,
                  ROUND(SUM_TIMER_WAIT/1000000000000, 2) AS total_sec,
                  ROUND(SUM_ROWS_EXAMINED/COUNT_STAR, 1) AS avg_rows_examined,
                  ROUND(SUM_ROWS_SENT/COUNT_STAR, 1) AS avg_rows_sent
                FROM performance_schema.events_statements_summary_by_digest
                WHERE AVG_TIMER_WAIT > 1000000000000 AND DIGEST_TEXT IS NOT NULL
                ORDER BY SUM_TIMER_WAIT DESC
                LIMIT 10
            """)
            rows = cur.fetchall()
            if rows:
                out.append(_fmt_table(cur, rows))
            else:
                out.append('[提示] 无符合条件的慢查询(平均>1秒)')
        except Exception as e:
            out.append(f'[提示] performance_schema 查询不可用: {e}')

        # 14.9 安全审计
        out.append(f'=== {label}.9 安全审计 ===')
        cur.execute("SELECT '匿名用户' AS 检查项, COUNT(*) AS 数量 FROM mysql.user WHERE User=''")
        out.append(_fmt_table(cur, cur.fetchall()))
        cur.execute("SELECT '空密码用户' AS 检查项, COUNT(*) AS 数量 FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL")
        out.append(_fmt_table(cur, cur.fetchall()))
        cur.execute("SELECT '远程root' AS 检查项, COUNT(*) AS 数量 FROM mysql.user WHERE User='root' AND Host='%'")
        out.append(_fmt_table(cur, cur.fetchall()))
        cur.execute("SELECT 'test数据库' AS 检查项, COUNT(*) AS 数量 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='test'")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 14.10 索引分析-无主键表（独立短超时连接）
        out.append(f'=== {label}.10 索引分析-无主键表 ===')
        try:
            _ic = pymysql.connect(
                host=creds['host'], port=creds['port'],
                user=creds['user'], password=creds['password'],
                connect_timeout=5, read_timeout=15,
                charset='utf8mb4', cursorclass=pymysql.cursors.Cursor
            )
            _icu = _ic.cursor()
            _icu.execute("""
                SELECT table_schema, table_name
                FROM information_schema.tables t
                WHERE t.table_schema NOT IN ('information_schema','performance_schema','mysql','sys')
                  AND t.table_type = 'BASE TABLE'
                  AND NOT EXISTS (
                    SELECT 1 FROM information_schema.table_constraints c
                    WHERE c.constraint_type = 'PRIMARY KEY'
                      AND c.table_schema = t.table_schema
                      AND c.table_name = t.table_name
                  )
                LIMIT 20
            """)
            out.append(_fmt_table(_icu, _icu.fetchall()))
            _ic.close()
        except Exception:
            out.append('[提示] information_schema查询超时(>15s)，跳过无主键表检查')

        # 14.11 主从复制状态
        out.append(f'=== {label}.11 主从复制状态 ===')
        try:
            cur.execute("SHOW SLAVE STATUS")
            row = cur.fetchone()
            if row:
                cols = [d[0] for d in cur.description]
                for col, val in zip(cols, row):
                    if col in ('Slave_IO_Running', 'Slave_SQL_Running', 'Seconds_Behind_Master', 'Master_Host', 'Master_Log_File'):
                        out.append(f'{col}: {val}')
            else:
                out.append('[提示] 未配置主从复制')
        except Exception:
            out.append('[提示] 未配置主从复制')

        # 14.12 关键配置参数
        out.append(f'=== {label}.12 关键配置参数 ===')
        cur.execute("SHOW GLOBAL VARIABLES WHERE Variable_name IN ('max_allowed_packet','innodb_log_file_size','innodb_flush_log_at_trx_commit','sync_binlog','binlog_format','expire_logs_days','binlog_expire_logs_seconds','innodb_flush_method','innodb_io_capacity','innodb_file_per_table','character_set_server','collation_server','sql_mode','transaction_isolation','autocommit')")
        rows = list(cur.fetchall())
        rows.sort(key=lambda r: r[0])  # MySQL 5.7 SHOW VARIABLES 不支持 ORDER BY
        out.append(_fmt_table(cur, rows))

        # 14.13 InnoDB引擎状态(摘要)
        out.append(f'=== {label}.13 InnoDB引擎状态(摘要) ===')
        try:
            cur.execute("SHOW ENGINE INNODB STATUS")
            row = cur.fetchone()
            inno_text = row[2] if row and len(row) > 2 else ''
            # Buffer Pool
            out.append('--- BUFFER POOL ---')
            for section in ['BUFFER POOL AND MEMORY', 'LATEST DETECTED DEADLOCK', 'ROW OPERATIONS']:
                out.append(f'--- {section} ---')
                pos = inno_text.find(section)
                if pos >= 0:
                    chunk = inno_text[pos:pos+800]
                    out.append(chunk[:800])
                else:
                    out.append(f'[无{section}记录]')
        except Exception as e:
            out.append(f'[提示] SHOW ENGINE INNODB STATUS 不可用: {e}')

        # 14.14 当前连接详情
        out.append(f'=== {label}.14 当前连接详情 ===')
        cur.execute("SELECT ID, USER, HOST, DB, COMMAND, TIME, STATE, LEFT(IFNULL(INFO,''), 100) AS QUERY_PREVIEW FROM information_schema.processlist ORDER BY TIME DESC LIMIT 20")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 14.15 慢查询日志详情（Top 10）
        out.append(f'=== {label}.15 慢查询日志详情(Top10) ===')
        try:
            cur.execute("""
                SELECT
                  TIME_TO_SEC(query_time) AS query_time_sec,
                  lock_time,
                  rows_examined,
                  rows_sent,
                  LEFT(sql_text, 200) AS sql_snippet,
                  db
                FROM mysql.slow_log
                ORDER BY query_time DESC
                LIMIT 10
            """)
            rows = cur.fetchall()
            if rows:
                out.append(_fmt_table(cur, rows))
            else:
                out.append('[提示] slow_log表为空或log_output未设为TABLE')
        except Exception as e:
            out.append(f'[提示] slow_log表不可用(可能log_output=FILE): {e}')

        # 14.16 InnoDB 死锁专检
        out.append(f'=== {label}.16 InnoDB 死锁专检 ===')
        cur.execute("SHOW GLOBAL STATUS LIKE 'Innodb_deadlocks'")
        dl_rows = cur.fetchall()
        if dl_rows:
            out.append(_fmt_table(cur, dl_rows))
        else:
            out.append('Innodb_deadlocks\t0\t(状态变量未注册，默认无死锁)')
        try:
            cur.execute("SHOW ENGINE INNODB STATUS")
            row = cur.fetchone()
            inno_text = row[2] if row and len(row) > 2 else ''
            pos = inno_text.find('LATEST DETECTED DEADLOCK')
            if pos >= 0:
                # 提取死锁段（最多3000字符，比14.13的800字符更完整）
                deadlock_section = inno_text[pos:pos+3000]
                end = deadlock_section.find('------------\nTRANSACTIONS')
                if end < 0:
                    end = deadlock_section.find('\n---')
                if end > 0:
                    deadlock_section = deadlock_section[:end]
                out.append(deadlock_section)
            else:
                out.append('[无] 近期未检测到死锁')
        except Exception as e:
            out.append(f'[提示] 死锁检测异常: {e}')

        # 14.17 性能瓶颈诊断（数据库响应慢排查）
        out.append(f'=== {label}.17 性能瓶颈诊断 ===')
        try:
            cur.execute("""SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME IN ('Innodb_buffer_pool_reads','Innodb_buffer_pool_read_requests','Innodb_row_lock_waits','Innodb_row_lock_time_avg','Innodb_row_lock_time_max','Table_locks_waited','Slow_queries','Threads_running')""")
            out.append(_fmt_table(cur, cur.fetchall()))
        except Exception as e:
            out.append(f'[提示] 性能瓶颈诊断异常: {e}')

        # 14.18 慢查询-执行时间分析（增强）
        out.append(f'=== {label}.18 慢查询-执行时间TOP20 ===')
        try:
            cur.execute("""SELECT DIGEST_TEXT, COUNT_STAR AS exec_count, ROUND(SUM_TIMER_WAIT/1000000000000, 2) AS total_sec, ROUND(AVG_TIMER_WAIT/1000000000000, 2) AS avg_sec, SUM_ROWS_EXAMINED, SUM_NO_INDEX_USED FROM performance_schema.events_statements_summary_by_digest WHERE AVG_TIMER_WAIT > 1000000000000 AND DIGEST_TEXT IS NOT NULL ORDER BY SUM_TIMER_WAIT DESC LIMIT 20""")
            rows = cur.fetchall()
            if rows:
                out.append(_fmt_table(cur, rows))
            else:
                out.append('[提示] 无执行时间超过1秒的查询')
        except Exception as e:
            out.append(f'[提示] 慢查询详情不可用: {e}')

        # 14.19 索引分析-未使用索引
        out.append(f'=== {label}.19 索引分析-未使用索引(Top20) ===')
        try:
            cur.execute("SELECT * FROM sys.schema_unused_indexes LIMIT 20")
            rows = cur.fetchall()
            if rows:
                out.append(_fmt_table(cur, rows))
            else:
                out.append('[提示] 无未使用索引或sys库不可用')
        except Exception as e:
            out.append(f'[提示] 未使用索引检测不可用: {e}')

        # 14.20 回表检测（covering index / back-table lookup）
        out.append(f'=== {label}.20 回表检测（高频全表扫描Top20） ===')
        try:
            cur.execute("""SELECT DIGEST_TEXT, SUM_ROWS_EXAMINED, SUM_ROWS_SENT, COUNT_STAR, ROUND(SUM_ROWS_EXAMINED/NULLIF(COUNT_STAR,0), 2) AS avg_rows_per_exec FROM performance_schema.events_statements_summary_by_digest WHERE SUM_ROWS_EXAMINED > 1000 AND DIGEST_TEXT IS NOT NULL AND DIGEST_TEXT NOT LIKE '%EXPLAIN%' ORDER BY SUM_ROWS_EXAMINED DESC LIMIT 20""")
            rows = cur.fetchall()
            if rows:
                out.append(_fmt_table(cur, rows))
            else:
                out.append('[提示] 无高频全表扫描查询')
        except Exception as e:
            out.append(f'[提示] 回表检测不可用: {e}')

        # 14.21 索引健康-冗余索引
        out.append(f'=== {label}.21 索引健康-冗余索引(Top20) ===')
        try:
            cur.execute("SELECT * FROM sys.schema_redundant_indexes LIMIT 20")
            rows = cur.fetchall()
            if rows:
                out.append(_fmt_table(cur, rows))
            else:
                out.append('[提示] 无冗余索引或sys库不可用')
        except Exception as e:
            out.append(f'[提示] 冗余索引检测不可用: {e}')

        # 14.22 索引健康-缺失索引（全表扫描查询）
        out.append(f'=== {label}.22 索引健康-缺失索引（全扫描Top20） ===')
        try:
            cur.execute("""SELECT DIGEST_TEXT, SUM_ROWS_EXAMINED, COUNT_STAR, FIRST_SEEN, LAST_SEEN FROM performance_schema.events_statements_summary_by_digest WHERE (SUM_NO_INDEX_USED > 0 OR SUM_ROWS_EXAMINED > 100000) AND DIGEST_TEXT IS NOT NULL AND DIGEST_TEXT NOT LIKE '%EXPLAIN%' ORDER BY SUM_ROWS_EXAMINED DESC LIMIT 20""")
            rows = cur.fetchall()
            if rows:
                out.append(_fmt_table(cur, rows))
            else:
                out.append('[提示] 无缺失索引相关的全扫描查询')
        except Exception as e:
            out.append(f'[提示] 缺失索引检测不可用: {e}')

        # 14.23 MySQL 参数调优建议
        out.append(f'=== {label}.23 MySQL 参数调优建议 ===')
        try:
            cur.execute("""SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME IN ('innodb_buffer_pool_size','innodb_log_file_size','innodb_flush_log_at_trx_commit','sync_binlog','max_connections','thread_cache_size','table_open_cache','query_cache_size','tmp_table_size','max_heap_table_size','sort_buffer_size','join_buffer_size','read_buffer_size','innodb_io_capacity')""")
            out.append(_fmt_table(cur, cur.fetchall()))
            cur.execute("""SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME IN ('Max_used_connections','Threads_created')""")
            out.append(_fmt_table(cur, cur.fetchall()))
            out.append('--- 调优建议 ---')
            out.append('1. innodb_buffer_pool_size: 建议设置为物理内存的60-80%')
            out.append('2. innodb_log_file_size: 建议设置为buffer pool的25%')
            out.append('3. max_connections: 建议大于Max_used_connections*1.5')
            out.append('4. thread_cache_size: 如Threads_created很高建议增大')
        except Exception as e:
            out.append(f'[提示] 配置优化建议生成失败: {e}')

        conn.close()
        return '\n'.join(out), '\n'.join(err) if err else ''

    except pymysql.Error as e:
        return None, f'[错误] MySQL查询失败: {e}'
    except Exception as e:
        return None, f'[错误] {e}'
    finally:
        if tunnel_sock:
            try:
                tunnel_sock.close()
            except Exception:
                pass


def run_oracle_deep_inspection(creds):
    """oracledb 直连 Oracle，返回 (stdout_text, stderr_text)"""
    try:
        import oracledb
    except ImportError:
        return ("=== 15 Oracle深度诊断 ===\n⚠️ 跳过：缺少 oracledb 模块，请执行 pip install oracledb\n", "")
    out = []
    err = []
    label = "15"
    try:
        dsn = f"{creds['host']}:{creds['port']}/{creds.get('service','ORCL')}"
        conn = oracledb.connect(user=creds['user'], password=creds['password'], dsn=dsn)
        cur = conn.cursor()

        # 15.1 基础状态
        out.append(f'=== {label}.1 基础状态 ===')
        out.append(_fetch_one(cur, "SELECT banner AS version FROM v$version WHERE ROWNUM=1"))
        cur.execute("SELECT instance_name, host_name, status, TO_CHAR(startup_time,'YYYY-MM-DD HH24:MI:SS') AS startup_time FROM v$instance")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 15.2 连接使用率
        out.append(f'=== {label}.2 连接使用率 ===')
        cur.execute("SELECT (SELECT COUNT(*) FROM v$session) AS current_sessions, (SELECT value FROM v$parameter WHERE name='processes') AS max_processes, ROUND((SELECT COUNT(*) FROM v$session)/(SELECT value FROM v$parameter WHERE name='processes')*100,1) AS usage_pct FROM dual")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 15.3 内存配置 (SGA/PGA)
        out.append(f'=== {label}.3 内存配置 ===')
        cur.execute("SELECT name, ROUND(value/1024/1024,2) AS size_mb FROM v$parameter WHERE name IN ('sga_target','sga_max_size','pga_aggregate_target','pga_aggregate_limit','memory_target','memory_max_target','db_cache_size','shared_pool_size') ORDER BY name")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 15.4 缓冲命中率
        out.append(f'=== {label}.4 缓冲命中率 ===')
        cur.execute("SELECT ROUND((1-(SUM(DECODE(name,'physical reads',value,0))/(SUM(DECODE(name,'db block gets',value,0))+SUM(DECODE(name,'consistent gets',value,0)))))*100,2) AS buffer_hit_ratio FROM v$sysstat")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 15.5 表空间使用率 TOP20
        out.append(f'=== {label}.5 表空间使用率 TOP20 ===')
        cur.execute("""SELECT * FROM (
            SELECT tablespace_name,
              ROUND(SUM(bytes)/1024/1024,2) AS total_mb,
              ROUND(SUM(DECODE(maxbytes,0,bytes,maxbytes))/1024/1024,2) AS max_mb,
              ROUND((SUM(bytes)/SUM(DECODE(maxbytes,0,bytes,maxbytes)))*100,1) AS used_pct
            FROM dba_data_files GROUP BY tablespace_name
            ORDER BY used_pct DESC
        ) WHERE ROWNUM <= 20""")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 15.6 段大小 TOP20 (就是表大小 TOP20)
        out.append(f'=== {label}.6 段大小 TOP20 ===')
        cur.execute("""SELECT * FROM (
            SELECT owner, segment_name, segment_type,
              ROUND(SUM(bytes)/1024/1024,2) AS size_mb
            FROM dba_segments
            WHERE segment_type LIKE 'TABLE%'
            GROUP BY owner, segment_name, segment_type
            ORDER BY SUM(bytes) DESC
        ) WHERE ROWNUM <= 20""")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 15.7 性能指标
        out.append(f'=== {label}.7 性能指标 ===')
        cur.execute("SELECT name, value FROM v$sysstat WHERE name IN ('user commits','user rollbacks','physical reads','physical writes','db block gets','consistent gets','redo size','parse count (total)','execute count','CPU used by this session')")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 15.8 慢SQL/AWR
        out.append(f'=== {label}.8 AWR状态 ===')
        cur.execute("SELECT dbid, retention/86400 AS retention_days FROM dba_hist_wr_control")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 15.9 安全审计
        out.append(f'=== {label}.9 安全审计 ===')
        cur.execute("SELECT '过期用户' AS 检查项, COUNT(*) AS 数量 FROM dba_users WHERE expiry_date < SYSDATE")
        out.append(_fmt_table(cur, cur.fetchall()))
        cur.execute("SELECT '锁定用户' AS 检查项, COUNT(*) AS 数量 FROM dba_users WHERE account_status LIKE '%LOCKED%'")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 15.10 索引分析
        out.append(f'=== {label}.10 索引分析-无主键表 ===')
        cur.execute("""SELECT owner, table_name FROM dba_tables
            WHERE owner NOT IN ('SYS','SYSTEM','XDB','WMSYS','MDSYS','CTXSYS','OLAPSYS')
            AND table_name NOT IN (SELECT table_name FROM dba_constraints WHERE constraint_type='P') AND ROWNUM <= 20""")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 15.11 死锁检测
        out.append(f'=== {label}.11 死锁检测 ===')
        cur.execute("SELECT sid, serial#, username, event, blocking_session, seconds_in_wait FROM v$session WHERE blocking_session IS NOT NULL")
        rows = cur.fetchall()
        if rows:
            out.append(_fmt_table(cur, rows))
        else:
            out.append('[提示] 当前无阻塞/死锁会话')
        # 也检查 enqueue 死锁
        cur.execute("SELECT * FROM v$enqueue_lock WHERE lockwait IS NOT NULL AND ROWNUM <= 20")
        enq_rows = cur.fetchall()
        if enq_rows:
            out.append('--- enqueue 死锁 ---')
            out.append(_fmt_table(cur, enq_rows))

        # 15.12 关键参数
        out.append(f'=== {label}.12 关键配置参数 ===')
        cur.execute("SELECT name, value FROM v$parameter WHERE name IN ('processes','sessions','open_cursors','db_block_size','db_files','log_buffer','control_file_record_keep_time','undo_retention','optimizer_mode','nls_characterset') ORDER BY name")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 15.13 表空间摘要
        out.append(f'=== {label}.13 表空间摘要 ===')
        cur.execute("""SELECT tablespace_name, ROUND(SUM(bytes)/1024/1024,2) AS free_mb,
            (SELECT ROUND(SUM(DECODE(maxbytes,0,bytes,maxbytes))/1024/1024,2) FROM dba_data_files WHERE tablespace_name=a.tablespace_name) AS max_mb
            FROM dba_free_space a GROUP BY tablespace_name ORDER BY free_mb DESC""")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 15.14 当前会话
        out.append(f'=== {label}.14 当前会话详情 ===')
        cur.execute("SELECT * FROM (SELECT sid, serial#, username, status, osuser, machine, program, sql_id, event FROM v$session WHERE type!='BACKGROUND' ORDER BY sid) WHERE ROWNUM <= 20")
        out.append(_fmt_table(cur, cur.fetchall()))

        conn.close()
        return '\n'.join(out), '\n'.join(err) if err else ''

    except oracledb.Error as e:
        return None, f'[错误] Oracle连接失败: {e}'
    except Exception as e:
        return None, f'[错误] {e}'


def run_mssql_deep_inspection(creds):
    """pyodbc 直连 SQL Server，返回 (stdout_text, stderr_text)"""
    try:
        import pyodbc
    except ImportError:
        return ("=== 16 SQL Server深度诊断 ===\n⚠️ 跳过：缺少 pyodbc 模块\n", "")
    out = []
    err = []
    label = "16"
    try:
        conn_str = (
            f"DRIVER={{ODBC Driver 17 for SQL Server}};"
            f"SERVER={creds['host']},{creds['port']};"
            f"UID={creds['user']};PWD={creds['password']};"
            f"Connect Timeout=5;"
        )
        try:
            conn = pyodbc.connect(conn_str)
        except pyodbc.Error:
            # 尝试 ODBC Driver 13 for SQL Server 作为降级
            conn_str2 = conn_str.replace('ODBC Driver 17', 'ODBC Driver 13')
            conn = pyodbc.connect(conn_str2)
        cur = conn.cursor()

        # 16.1 基础状态
        out.append(f'=== {label}.1 基础状态 ===')
        cur.execute("SELECT @@VERSION AS version")
        out.append(_fmt_table(cur, cur.fetchall()))
        cur.execute("SELECT sqlserver_start_time AS startup_time, DATEDIFF(DAY, sqlserver_start_time, GETDATE()) AS uptime_days FROM sys.dm_os_sys_info")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 16.2 连接使用率
        out.append(f'=== {label}.2 连接使用率 ===')
        cur.execute("SELECT COUNT(*) AS current_connections FROM sys.dm_exec_sessions")
        row = cur.fetchone()
        cur.execute("SELECT value AS max_connections FROM sys.configurations WHERE name='user connections'")
        row2 = cur.fetchone()
        max_conn = int(row2[0]) if row2 and int(row2[0]) > 0 else 32767
        current = row[0] if row else 0
        usage_pct = round(current / max_conn * 100, 1)
        out.append(f'current_connections\tmax_connections\tusage_pct\n{current}\t{max_conn}\t{usage_pct}')

        # 16.3 内存配置
        out.append(f'=== {label}.3 内存配置 ===')
        cur.execute("SELECT name, value, value_in_use FROM sys.configurations WHERE name IN ('max server memory (MB)','min server memory (MB)','max degree of parallelism','cost threshold for parallelism')")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 16.4 缓冲池命中率
        out.append(f'=== {label}.4 缓冲池命中率 ===')
        cur.execute("SELECT counter_name, cntr_value FROM sys.dm_os_performance_counters WHERE object_name LIKE '%Buffer Manager%' AND counter_name IN ('Buffer cache hit ratio','Page life expectancy')")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 16.5 数据库大小 TOP20
        out.append(f'=== {label}.5 数据库大小 TOP20 ===')
        cur.execute("SELECT TOP 20 DB_NAME(database_id) AS db_name, CAST(SUM(size)*8/1024.0 AS DECIMAL(10,2)) AS size_mb FROM sys.master_files GROUP BY database_id ORDER BY SUM(size) DESC")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 16.6 表大小 TOP20 (跨所有库)
        out.append(f'=== {label}.6 表大小 TOP20 ===')
        try:
            cur.execute("""
                SELECT TOP 20 DB_NAME() AS db_name, OBJECT_NAME(p.object_id) AS table_name,
                  SUM(p.reserved_page_count)*8/1024 AS size_mb,
                  SUM(p.row_count) AS row_count
                FROM sys.dm_db_partition_stats p
                JOIN sys.tables t ON t.object_id = p.object_id
                GROUP BY p.object_id ORDER BY SUM(p.reserved_page_count) DESC
            """)
            out.append(_fmt_table(cur, cur.fetchall()))
        except Exception as e:
            out.append(f'[提示] 当前库查询: {e}')

        # 16.7 性能指标
        out.append(f'=== {label}.7 性能指标 ===')
        cur.execute("""SELECT counter_name, cntr_value FROM sys.dm_os_performance_counters
            WHERE object_name LIKE '%:SQL Statistics%' OR object_name LIKE '%:Locks%'
            AND counter_name IN ('Batch Requests/sec','SQL Compilations/sec','Lock Waits/sec','Lock Wait Time (ms)')""")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 16.8 慢查询/Query Store
        out.append(f'=== {label}.8 Query Store 状态 ===')
        cur.execute("SELECT name, desired_state_desc, actual_state_desc FROM sys.database_query_store_options")
        rows = cur.fetchall()
        if rows:
            out.append(_fmt_table(cur, rows))
        else:
            out.append('[提示] Query Store 未启用')

        # 16.9 安全审计
        out.append(f'=== {label}.9 安全审计 ===')
        cur.execute("SELECT 'sysadmin成员' AS 检查项, COUNT(*) AS 数量 FROM sys.syslogins WHERE sysadmin=1")
        out.append(_fmt_table(cur, cur.fetchall()))
        cur.execute("SELECT 'SQL认证用户' AS 检查项, COUNT(*) AS 数量 FROM sys.syslogins WHERE password IS NOT NULL")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 16.10 缺失索引
        out.append(f'=== {label}.10 缺失索引 TOP20 ===')
        cur.execute("""SELECT TOP 20 DB_NAME(mid.database_id) AS db_name,
            mid.statement AS table_name,
            mid.avg_user_impact, mid.user_seeks
            FROM sys.dm_db_missing_index_details mid
            JOIN sys.dm_db_missing_index_groups mig ON mid.index_handle = mig.index_handle
            ORDER BY mid.avg_user_impact DESC""")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 16.11 死锁检测
        out.append(f'=== {label}.11 死锁检测 ===')
        cur.execute("SELECT session_id AS blocked_spid, blocking_session_id, wait_type, wait_time FROM sys.dm_os_waiting_tasks WHERE blocking_session_id IS NOT NULL")
        rows = cur.fetchall()
        if rows:
            out.append(_fmt_table(cur, rows))
        else:
            out.append('[提示] 当前无阻塞/死锁会话')
        # 最近死锁事件
        out.append('--- 最近死锁事件（最多5条）---')
        cur.execute("""SELECT TOP 5 DATEADD(ms, -1 * (ms_ticks - timestamp), GETDATE()) AS deadlock_time,
            CAST(record AS XML).value('(/Record/Deadlock/ResourceList/DeadlockResource/@WaiterMode)[1]','varchar(50)') AS waiter_mode
            FROM sys.dm_os_ring_buffers
            WHERE ring_buffer_type = 'RING_BUFFER_DEADLOCK'""")
        rows = cur.fetchall()
        if rows:
            out.append(_fmt_table(cur, rows))
        else:
            out.append('[无死锁记录]')

        # 16.12 关键配置参数
        out.append(f'=== {label}.12 关键配置参数 ===')
        cur.execute("SELECT name, value, value_in_use FROM sys.configurations WHERE name IN ('max worker threads','backup compression default','remote admin connections','blocked process threshold (s)','clr enabled','xp_cmdshell')")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 16.13 数据库选项
        out.append(f'=== {label}.13 数据库选项摘要 ===')
        cur.execute("SELECT name, recovery_model_desc, state_desc, compatibility_level, is_auto_shrink_on, is_auto_create_stats_on FROM sys.databases WHERE database_id > 4")
        out.append(_fmt_table(cur, cur.fetchall()))

        # 16.14 当前连接详情
        out.append(f'=== {label}.14 当前连接详情 ===')
        cur.execute("SELECT TOP 20 session_id, login_name, host_name, program_name, status, cpu_time, memory_usage, last_request_start_time FROM sys.dm_exec_sessions WHERE is_user_process=1 ORDER BY session_id")
        out.append(_fmt_table(cur, cur.fetchall()))

        conn.close()
        return '\n'.join(out), '\n'.join(err) if err else ''

    except pyodbc.Error as e:
        return None, f'[错误] SQL Server连接失败: {e}'
    except Exception as e:
        return None, f'[错误] {e}'


# 数据库直连函数注册表
DB_RUNNERS = {
    "run_mysql_deep": run_mysql_deep_inspection,
    "run_oracle_deep": run_oracle_deep_inspection,
    "run_mssql_deep": run_mssql_deep_inspection,
}


# ===================== 单模块线程执行器 =====================

def _exec_single_module(module_name, module, host, port, user,
                        password=None, key_file=None, timeout=120,
                        mysql_creds=None, oracle_creds=None, mssql_creds=None):
    """在线程中执行单个巡检模块，创建独立的SSH连接。
    返回: (module_name, title, stdout, stderr, error_msg, skipped)"""
    title = module["title"]
    client = None
    stdout = None
    stderr = None
    error_msg = None
    skipped = False

    try:
        if module.get("type") == "python_db":
            # Python 直连数据库 — 先建 SSH 隧道用于回退
            runner_name = module["runner"]
            creds = None
            if module_name == "mysql_deep":
                creds = mysql_creds
            elif module_name == "oracle_deep":
                creds = oracle_creds
            elif module_name == "mssql_deep":
                creds = mssql_creds

            if not creds:
                skipped = True
                error_msg = f"[跳过] 未提供{module_name}数据库凭证"
            else:
                # 为 mysql_deep 建立 SSH 连接（用于隧道回退）
                db_ssh_client = None
                if runner_name == "run_mysql_deep":
                    db_ssh_client, conn_err = ssh_connect(
                        host, port, user, password, key_file, timeout)
                    if conn_err:
                        skipped = True
                        error_msg = f"[跳过] SSH连接失败，无法建立隧道: {conn_err}"

                if not skipped:
                    runner_fn = DB_RUNNERS.get(runner_name)
                    if runner_fn:
                        if runner_name == "run_mysql_deep":
                            stdout, stderr = runner_fn(creds, ssh_client=db_ssh_client)
                        else:
                            stdout, stderr = runner_fn(creds)
                    else:
                        error_msg = f"[错误] 未知运行器: {runner_name}"
                if db_ssh_client:
                    try:
                        db_ssh_client.close()
                    except Exception:
                        pass

        elif module.get("type") == "ssh_db":
            # SSH 隧道 + MySQL CLI 模式
            if not mysql_creds:
                skipped = True
                error_msg = f"[跳过] 未提供MySQL数据库凭证，无法执行{module_name}"
            else:
                client, conn_err = ssh_connect(host, port, user, password, key_file, timeout)
                if conn_err:
                    error_msg = f"[跳过] SSH连接失败: {conn_err}"
                else:
                    m_host = mysql_creds.get("host", "127.0.0.1")
                    m_port = mysql_creds.get("port", 3306)
                    m_user = mysql_creds.get("user", "root")
                    m_pass = mysql_creds.get("password", "")
                    queries = module["queries"]

                    script_lines = []
                    for label, sql in queries:
                        sql_oneline = ' '.join(line.strip() for line in sql.split('\n') if line.strip())
                        sql_escaped = sql_oneline.replace("'", "'\\''")
                        script_lines.append(f'echo "=== {label} ==="')
                        script_lines.append(
                            f'MYSQL_PWD="{m_pass}" mysql -h{m_host} -P{m_port} '
                            f'-u{m_user} --connect-timeout=10 -e \'{sql_escaped}\' 2>&1'
                        )
                        script_lines.append('echo ""')

                    combined_cmd = '\n'.join(script_lines)
                    stdout, stderr = exec_command(client, combined_cmd, timeout * 3)
        else:
            # 普通 SSH 模式 — 创建独立连接
            client, conn_err = ssh_connect(host, port, user, password, key_file, timeout)
            if conn_err:
                error_msg = f"[跳过] SSH连接失败: {conn_err}"
            else:
                commands = module["commands"]
                stdout, stderr = exec_command(client, commands, timeout)

    except Exception as e:
        error_msg = f"[跳过] 模块执行异常: {e}"
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass

    return (module_name, title, stdout, stderr, error_msg, skipped)


def ssh_connect(host, port, user, password=None, key_file=None, timeout=30):
    """建立SSH连接，支持密钥和密码认证"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        if key_file:
            client.connect(
                hostname=host,
                port=port,
                username=user,
                key_filename=key_file,
                timeout=timeout,
                look_for_keys=False
            )
        elif password:
            client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=timeout
            )
        else:
            raise ValueError("必须提供 --password 或 --key 参数")
        return client, None
    except paramiko.AuthenticationException:
        return None, "认证失败！请检查用户名、密码或密钥文件"
    except paramiko.SSHException as e:
        return None, f"SSH连接错误: {e}"
    except Exception as e:
        return None, f"连接失败: {e}"


def exec_command(client, command, timeout=120):
    """执行远程命令并返回stdout和stderr"""
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode('utf-8', errors='ignore')
        err = stderr.read().decode('utf-8', errors='ignore')
        return out, err
    except Exception as e:
        return None, str(e)


def run_inspection(host, port, user, password=None, key_file=None,
                   modules=None, output_file=None, json_output=None, timeout=120,
                   mysql_creds=None, oracle_creds=None, mssql_creds=None,
                   module_workers=5, module_timeout=None):
    """执行完整巡检，返回 (success, results_dict)

    Args:
        module_workers: 模块并发线程数 (默认5)，设为1则回退到串行
        module_timeout: 单模块超时秒数 (默认继承 timeout)
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 确定巡检模块
    if modules:
        raw = modules.strip().lower()
        # --check all 一键全量：展开为所有 SSH 模块 + 可用的 DB 模块
        if raw == "all":
            selected = [m for m in ALL_MODULES]
        else:
            selected = [m.strip().lower() for m in raw.split(',')]
        valid = [m for m in selected if m in CHECK_MODULES]
        invalid = [m for m in selected if m not in CHECK_MODULES]
        if invalid:
            print(f"[警告] 未知模块将被跳过: {invalid}")
    else:
        valid = ALL_MODULES

    if not valid:
        print("[错误] 没有有效的巡检模块")
        return False, {}

    # DB凭证映射
    db_cred_map = {
        "mysql_deep": mysql_creds,
        "oracle_deep": oracle_creds,
        "mssql_deep": mssql_creds,
    }

    # ===== 多线程并发执行模块 =====
    # 确定单模块超时
    mod_timeout = module_timeout if module_timeout else timeout

    # 分离模块类型
    ssh_modules = [m for m in valid if CHECK_MODULES[m].get("type") != "python_db"]
    db_modules = [m for m in valid if CHECK_MODULES[m].get("type") == "python_db"]

    # 先做一次 SSH 连通性验证
    need_ssh = len(ssh_modules) > 0
    test_error = None
    if need_ssh:
        test_client, test_error = ssh_connect(host, port, user, password, key_file, timeout)
        if test_error:
            print(f"[连接失败] {test_error}")
            # 标记所有 SSH 模块为失败
            results = {}
            section_map = {}
            for m in ssh_modules:
                results[m] = {"error": test_error}
                section_map[m] = f"\n{'='*60}\n{CHECK_MODULES[m]['title']}\n{'='*60}\n[错误] SSH连接失败: {test_error}\n"
                print(f"[跳过] {CHECK_MODULES[m]['title']} - SSH连接失败")
            # DB 模块也跳过（因为没有 SSH 隧道）
            for m in db_modules:
                results[m] = {"error": test_error}
                section_map[m] = f"\n{'='*60}\n{CHECK_MODULES[m]['title']}\n{'='*60}\n[跳过] SSH连接失败，无法执行{m}\n"
                print(f"[跳过] {CHECK_MODULES[m]['title']} - SSH连接失败")
            # 按顺序组装报告
            report_sections = [section_map[m] for m in valid if m in section_map]
        else:
            test_client.close()
            print(f"[连接成功] {user}@{host}:{port}")
    else:
        print(f"\n[数据库直连模式] 无需SSH")

    # 发起并发巡检（仅当 SSH 验证通过后）
    if need_ssh and test_error:
        # SSH 连接失败，不执行并发
        client = None
    else:
        # 确定并发数
        actual_workers = min(module_workers, len(valid))
        if actual_workers <= 1:
            # 串行模式（回退路径：保持向后兼容）
            print(f"\n[串行巡检] {len(valid)} 个模块，逐一执行\n")
            results = {}
            section_map = {}
            client = None
            if need_ssh:
                client, _ = ssh_connect(host, port, user, password, key_file, timeout)
            else:
                client = None

            for module_name in valid:
                module = CHECK_MODULES[module_name]
                title = module["title"]
                print(f"[巡检中] {title} ...", end=" ", flush=True)

                if module.get("type") == "python_db":
                    runner_name = module["runner"]
                    creds = db_cred_map.get(module_name)
                    if not creds:
                        stdout, stderr = None, f"[跳过] 未提供{module_name}数据库凭证"
                    else:
                        runner_fn = DB_RUNNERS.get(runner_name)
                        if runner_fn:
                            if runner_name == "run_mysql_deep":
                                stdout, stderr = runner_fn(creds, ssh_client=client)
                            else:
                                stdout, stderr = runner_fn(creds)
                        else:
                            stdout, stderr = None, f"[错误] 未知运行器: {runner_name}"
                elif module.get("type") == "ssh_db":
                    if not mysql_creds:
                        stdout, stderr = None, f"[跳过] 未提供MySQL数据库凭证，无法执行{module_name}"
                    elif not client:
                        stdout, stderr = None, f"[跳过] 需要SSH连接才能执行{module_name}"
                    else:
                        m_host = mysql_creds.get("host", "127.0.0.1")
                        m_port = mysql_creds.get("port", 3306)
                        m_user = mysql_creds.get("user", "root")
                        m_pass = mysql_creds.get("password", "")
                        queries = module["queries"]
                        script_lines = []
                        for label, sql in queries:
                            sql_oneline = ' '.join(line.strip() for line in sql.split('\n') if line.strip())
                            sql_escaped = sql_oneline.replace("'", "'\\''")
                            script_lines.append(f'echo "=== {label} ==="')
                            script_lines.append(f'MYSQL_PWD="{m_pass}" mysql -h{m_host} -P{m_port} -u{m_user} --connect-timeout=10 -e \'{sql_escaped}\' 2>&1')
                            script_lines.append('echo ""')
                        combined_cmd = '\n'.join(script_lines)
                        stdout, stderr = exec_command(client, combined_cmd, timeout * 3)
                else:
                    commands = module["commands"]
                    stdout, stderr = exec_command(client, commands, timeout)

                if stdout is not None:
                    results[module_name] = {"stdout": stdout, "stderr": stderr}
                    section_map[module_name] = f"\n{'='*60}\n{title}\n{'='*60}\n{stdout}"
                    if stderr and stderr.strip():
                        section_map[module_name] += f"\n[stderr] {stderr}\n"
                    print("完成")
                else:
                    results[module_name] = {"error": stderr}
                    section_map[module_name] = f"\n{'='*60}\n{title}\n{'='*60}\n[错误] {stderr}\n"
                    print(f"失败: {stderr}")

            if client:
                client.close()
            client = None
            report_sections = [section_map[m] for m in valid if m in section_map]
        else:
            # 多线程并发模式
            print(f"\n[并发巡检] {len(valid)} 个模块, {actual_workers} 个并发线程\n")
            results = {}
            section_map = {}
            result_lock = threading.Lock()

            with ThreadPoolExecutor(max_workers=actual_workers) as executor:
                future_map = {}
                for mname in valid:
                    module = CHECK_MODULES[mname]
                    future = executor.submit(
                        _exec_single_module,
                        mname, module, host, port, user,
                        password, key_file, mod_timeout,
                        mysql_creds, oracle_creds, mssql_creds
                    )
                    future_map[future] = mname

                for future in as_completed(future_map):
                    mname = future_map[future]
                    module = CHECK_MODULES[mname]
                    try:
                        fmname, title, stdout, stderr, error_msg, skipped = \
                            future.result(timeout=mod_timeout + 30)
                    except Exception as e:
                        # 超时或其他异常 — 跳过不卡死
                        with result_lock:
                            results[mname] = {"error": f"超时/异常: {e}"}
                            section_map[mname] = (
                                f"\n{'='*60}\n{module['title']}\n{'='*60}\n"
                                f"[跳过] {mname} 超时/异常: {e}\n"
                            )
                        print(f"[跳过] {module['title']} - 超时/异常")
                        continue

                    with result_lock:
                        if error_msg:
                            results[mname] = {"error": error_msg}
                            section_map[mname] = (
                                f"\n{'='*60}\n{title}\n{'='*60}\n{error_msg}\n"
                            )
                            status = "跳过" if skipped else "失败"
                            print(f"[{status}] {title} - {error_msg}")
                        elif stdout is not None:
                            results[mname] = {"stdout": stdout, "stderr": stderr}
                            section = f"\n{'='*60}\n{title}\n{'='*60}\n{stdout}"
                            if stderr and stderr.strip():
                                section += f"\n[stderr] {stderr}\n"
                            section_map[mname] = section
                            print(f"[完成] {title}")
                        else:
                            results[mname] = {"error": "未知错误"}
                            section_map[mname] = (
                                f"\n{'='*60}\n{title}\n{'='*60}\n[错误] 未知错误\n"
                            )
                            print(f"[失败] {title}")

            # 按原始顺序排列报告段落
            report_sections = [section_map[m] for m in valid if m in section_map]
            client = None

    # 组装完整报告
    full_report = f"\n{'#'*60}\n"
    full_report += f"  Linux服务器巡检报告\n"
    full_report += f"  主机: {host}:{port}  用户: {user}\n"
    full_report += f"  时间: {now}\n"
    full_report += f"{'#'*60}"
    full_report += "\n".join(report_sections)
    full_report += f"\n{'#'*60}\n  巡检结束\n{'#'*60}\n"

    # 输出到终端
    print(full_report)

    # 保存为文本文件
    if output_file:
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(full_report)
        print(f"[报告已保存] {output_file}")

    # 保存为JSON文件
    if json_output:
        os.makedirs(os.path.dirname(json_output) if os.path.dirname(json_output) else '.', exist_ok=True)
        json_data = {
            "meta": {
                "host": host,
                "port": port,
                "user": user,
                "time": now,
                "modules": valid
            },
            "results": results
        }
        with open(json_output, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)
        print(f"[JSON已保存] {json_output}")

    # 阈值告警汇总
    alert_section = results.get("alert", {})
    if alert_section.get("stdout"):
        print("\n" + "!"*60)
        print("  告警汇总（自动提取）")
        print("!"*60)
        alert_text = alert_section["stdout"]
        for line in alert_text.split('\n'):
            line_s = line.strip()
            if not line_s or line_s.startswith('===') or '===' in line_s:
                continue
            if '告警' in line_s or ('失败' in line_s and '登录' in line_s) or '僵尸' in line_s:
                parts = line_s.split(':')
                val = parts[-1].strip() if len(parts) > 1 else ''
                if val.isdigit() and int(val) == 0:
                    continue
                print(f"  {line_s}")
        print("!"*60)

    return True, results


def load_inventory(inventory_file):
    """加载服务器清单文件"""
    if not os.path.exists(inventory_file):
        print(f"[错误] 清单文件不存在: {inventory_file}")
        return None, f"文件不存在: {inventory_file}"

    try:
        with open(inventory_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[错误] 清单文件JSON格式错误: {e}")
        return None, f"JSON格式错误: {e}"

    servers = data.get("servers", [])
    if not servers:
        print("[错误] 清单中没有服务器配置")
        return None, "没有服务器配置"

    # 过滤enabled=true的服务器
    enabled_servers = [s for s in servers if s.get("enabled", True)]
    disabled_count = len(servers) - len(enabled_servers)

    if disabled_count > 0:
        print(f"[信息] 跳过 {disabled_count} 台已禁用的服务器")

    if not enabled_servers:
        print("[错误] 没有启用的服务器")
        return None, "没有启用的服务器"

    return enabled_servers, data.get("settings", {})


def inspect_single_server(server_info, modules=None, output_dir=None, timeout=120,
                          global_db_auth=None, global_oracle_auth=None, global_mssql_auth=None,
                          module_workers=5, module_timeout=None):
    """
    巡检单台服务器（供批量模式调用）
    返回: {host, alias, success, error, json_path, results}
    """
    host = server_info.get("host", "")
    port = server_info.get("port", 22)
    user = server_info.get("user", "root")
    alias = server_info.get("alias", host)
    auth = server_info.get("auth", {})
    auth_type = auth.get("type", "password")
    auth_value = auth.get("value", "")

    password = None
    key_file = None
    if auth_type == "key":
        key_file = os.path.expanduser(auth_value)
    else:
        password = auth_value

    # 提取数据库凭证（服务器级 > 全局级）
    def _build_db_creds(server_key, global_auth, default_port):
        db_auth = server_info.get(server_key) or global_auth
        if db_auth:
            return {
                "host": db_auth.get("host", "127.0.0.1"),
                "port": db_auth.get("port", default_port),
                "user": db_auth.get("user", "root"),
                "password": db_auth.get("password", ""),
            }
        return None

    db_auth = server_info.get("db_auth") or global_db_auth
    mysql_creds = None
    if db_auth:
        mysql_creds = {
            "host": db_auth.get("host", "127.0.0.1"),
            "port": db_auth.get("port", 3306),
            "user": db_auth.get("user", "root"),
            "password": db_auth.get("password", "")
        }
    oracle_creds = _build_db_creds("oracle_auth", global_oracle_auth, 1521)
    mssql_creds = _build_db_creds("mssql_auth", global_mssql_auth, 1433)

    # 输出文件路径
    safe_host = host.replace('.', '_').replace(':', '_')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_path = None
    txt_path = None
    if output_dir:
        json_path = os.path.join(output_dir, f"{safe_host}_{timestamp}.json")
        txt_path = os.path.join(output_dir, f"{safe_host}_{timestamp}.txt")

    # 执行巡检（不打印到终端，静默模式）
    import io
    from contextlib import redirect_stdout, redirect_stderr

    buf_out = io.StringIO()
    buf_err = io.StringIO()

    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        success, results = run_inspection(
            host=host, port=port, user=user,
            password=password, key_file=key_file,
            modules=modules,
            output_file=txt_path,
            json_output=json_path,
            timeout=timeout,
            mysql_creds=mysql_creds,
            oracle_creds=oracle_creds,
            mssql_creds=mssql_creds,
            module_workers=module_workers,
            module_timeout=module_timeout,
        )

    output_text = buf_out.getvalue()

    return {
        "host": host,
        "port": port,
        "user": user,
        "alias": alias,
        "tags": server_info.get("tags", []),
        "success": success,
        "error": None if success else "连接或巡检失败",
        "json_path": json_path,
        "txt_path": txt_path,
        "results": results,
        "output": output_text,
        "time": timestamp
    }


def generate_batch_summary(batch_results, output_dir):
    """生成批量巡检汇总报告（文本格式）"""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total = len(batch_results)
    success_count = sum(1 for r in batch_results if r["success"])
    fail_count = total - success_count

    lines = []
    lines.append(f"\n{'='*70}")
    lines.append(f"  批量巡检汇总报告")
    lines.append(f"  巡检时间: {now}")
    lines.append(f"  服务器总数: {total}  成功: {success_count}  失败: {fail_count}")
    lines.append(f"{'='*70}\n")

    # 概览表格
    lines.append(f"{'序号':<4} {'服务器':<25} {'别名':<20} {'状态':<6} {'JSON报告'}")
    lines.append(f"{'-'*4} {'-'*25} {'-'*20} {'-'*6} {'-'*40}")

    for i, r in enumerate(batch_results, 1):
        status = "OK" if r["success"] else "FAIL"
        json_file = os.path.basename(r["json_path"]) if r.get("json_path") else "-"
        lines.append(f"{i:<4} {r['host']:<25} {r['alias']:<20} {status:<6} {json_file}")

    # 失败详情
    failed = [r for r in batch_results if not r["success"]]
    if failed:
        lines.append(f"\n[失败详情]")
        for r in failed:
            lines.append(f"  - {r['alias']} ({r['host']}): {r.get('error', '未知错误')}")

    # 告警汇总
    lines.append(f"\n[告警汇总]")
    for r in batch_results:
        if not r["success"]:
            continue
        alert_data = r["results"].get("alert", {})
        alert_text = alert_data.get("stdout", "")
        alerts = []
        for line in alert_text.split('\n'):
            line_s = line.strip()
            if not line_s or line_s.startswith('===') or '===' in line_s:
                continue
            if '告警' in line_s or ('失败' in line_s and '登录' in line_s) or '僵尸' in line_s:
                parts = line_s.split(':')
                val = parts[-1].strip() if len(parts) > 1 else ''
                if val.isdigit() and int(val) == 0:
                    continue
                alerts.append(line_s)
        if alerts:
            lines.append(f"\n  {r['alias']} ({r['host']}):")
            for a in alerts:
                lines.append(f"    {a}")
        else:
            lines.append(f"  {r['alias']} ({r['host']}): 无告警")

    report = "\n".join(lines)

    # 保存
    summary_path = os.path.join(output_dir, f"batch_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    os.makedirs(output_dir, exist_ok=True)
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(report)

    return report, summary_path


def run_batch_inspection(inventory_file, modules=None, workers=3, output_dir=None, generate_html=False,
                          module_workers=5, module_timeout=None):
    """执行批量巡检"""
    servers, settings = load_inventory(inventory_file)
    if servers is None:
        return False

    # 合并配置
    check_modules = modules or settings.get("check_modules", None)
    if check_modules:
        check_modules = check_modules if isinstance(check_modules, str) else ",".join(check_modules)
    timeout = settings.get("timeout", 120)
    actual_workers = min(workers or settings.get("workers", 3), len(servers))
    actual_module_workers = module_workers or settings.get("module_workers", 5)
    actual_module_timeout = module_timeout or settings.get("module_timeout", None)
    out_dir = output_dir or settings.get("output_dir", "./reports")
    do_html = generate_html or settings.get("generate_html", False)

    os.makedirs(out_dir, exist_ok=True)

    total = len(servers)
    print(f"\n{'*'*70}")
    print(f"  批量巡检启动")
    print(f"  服务器数量: {total}")
    print(f"  服务器并发: {actual_workers}")
    print(f"  模块并发: {actual_module_workers}")
    print(f"  巡检模块: {check_modules or '全部'}")
    print(f"  报告输出: {out_dir}")
    print(f"{'*'*70}\n")

    # 打印服务器列表
    for i, s in enumerate(servers, 1):
        tags_str = f" [{', '.join(s.get('tags', []))}]" if s.get('tags') else ""
        print(f"  {i}. {s.get('alias', s['host'])} ({s['host']}:{s.get('port', 22)}){tags_str}")

    print(f"\n开始巡检...\n")

    # 全局数据库凭证（单机可覆盖）
    global_db_auth = settings.get("db_auth", None)
    global_oracle_auth = settings.get("oracle_auth", None)
    global_mssql_auth = settings.get("mssql_auth", None)

    # 并发巡检
    batch_results = []
    with ThreadPoolExecutor(max_workers=actual_workers) as executor:
        futures = {
            executor.submit(
                inspect_single_server,
                server, check_modules, out_dir, timeout,
                global_db_auth, global_oracle_auth, global_mssql_auth,
                actual_module_workers, actual_module_timeout
            ): server for server in servers
        }

        for future in as_completed(futures):
            server = futures[future]
            alias = server.get("alias", server["host"])
            try:
                result = future.result()
                batch_results.append(result)
                status = "成功" if result["success"] else "失败"
                print(f"  [{status}] {alias} ({result['host']})")
            except Exception as e:
                print(f"  [异常] {alias}: {e}")
                batch_results.append({
                    "host": server["host"],
                    "alias": alias,
                    "success": False,
                    "error": str(e),
                    "results": {},
                    "json_path": None,
                    "txt_path": None,
                    "tags": server.get("tags", []),
                    "time": datetime.now().strftime('%Y%m%d_%H%M%S')
                })

    # 按host排序，保持稳定输出
    batch_results.sort(key=lambda r: r["host"])

    # 生成汇总报告
    print(f"\n{'='*70}")
    summary_report, summary_path = generate_batch_summary(batch_results, out_dir)
    print(summary_report)
    print(f"\n[汇总报告已保存] {summary_path}")

    # 生成HTML汇总报告
    if do_html:
        html_path = generate_batch_html(batch_results, out_dir)
        if html_path:
            print(f"[HTML报告已生成] {html_path}")

    return True


def generate_batch_html(batch_results, output_dir):
    """生成批量巡检HTML汇总报告（包含已映射模块的详情）"""
    import html as html_lib

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total = len(batch_results)
    success_count = sum(1 for r in batch_results if r["success"])

    CSS = """
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, 'Microsoft YaHei', sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
    .container { max-width: 1400px; margin: 0 auto; }
    h1 { text-align: center; font-size: 28px; color: #f8fafc; margin-bottom: 8px; }
    h2 { font-size: 20px; margin-bottom: 16px; color: #f8fafc; }
    .subtitle { text-align: center; color: #94a3b8; margin-bottom: 24px; }
    .stats { display: flex; gap: 16px; justify-content: center; flex-wrap: wrap; margin-bottom: 32px; }
    .stat-card { background: #1e293b; border-radius: 12px; padding: 20px 28px; text-align: center; min-width: 140px; border: 1px solid #334155; }
    .stat-card .num { font-size: 36px; font-weight: 700; }
    .stat-card .label { font-size: 13px; color: #94a3b8; margin-top: 4px; }
    .num-green { color: #22c55e; } .num-red { color: #ef4444; } .num-blue { color: #3b82f6; } .num-yellow { color: #f59e0b; }

    .server-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(600px, 1fr)); gap: 20px; margin-bottom: 32px; }
    .server-card { background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155; }
    .server-card.fail { border-color: #ef4444; opacity: 0.7; }
    .server-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
    .server-name { font-size: 18px; font-weight: 600; }
    .server-host { color: #94a3b8; font-size: 14px; }
    .badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
    .badge-ok { background: #166534; color: #86efac; } .badge-fail { background: #7f1d1d; color: #fca5a5; } .badge-warn { background: #713f12; color: #fde68a; }
    .tags { margin-top: 4px; }
    .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; background: #334155; color: #94a3b8; margin-right: 4px; }

    .metrics { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 10px; }
    .metric { text-align: center; padding: 10px; background: #0f172a; border-radius: 8px; }
    .metric .val { font-size: 20px; font-weight: 700; }
    .metric .lbl { font-size: 11px; color: #94a3b8; margin-top: 2px; }

    .comparison-table { background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155; overflow-x: auto; margin-bottom: 32px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #334155; font-size: 14px; }
    th { color: #94a3b8; font-weight: 600; position: sticky; top: 0; background: #1e293b; }
    tr:hover { background: #334155; }
    .progress-bar { height: 8px; background: #334155; border-radius: 4px; overflow: hidden; min-width: 80px; }
    .progress-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
    .fill-green { background: #22c55e; } .fill-yellow { background: #f59e0b; } .fill-red { background: #ef4444; }

    /* 详情面板 */
    .detail-section { background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155; margin-bottom: 24px; }
    .detail-toggle { cursor: pointer; display: flex; justify-content: space-between; align-items: center; padding: 8px 0; user-select: none; }
    .detail-toggle:hover { opacity: 0.85; }
    .detail-toggle .arrow { transition: transform 0.2s; font-size: 12px; color: #94a3b8; }
    .detail-toggle.open .arrow { transform: rotate(90deg); }
    .detail-content { display: none; margin-top: 16px; }
    .detail-content.show { display: block; }
    .module-section { background: #0f172a; border-radius: 10px; padding: 16px; margin-bottom: 12px; }
    .module-title { font-size: 15px; font-weight: 600; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
    .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
    .dot-ok { background: #22c55e; } .dot-warn { background: #f59e0b; } .dot-err { background: #ef4444; } .dot-info { background: #3b82f6; }
    pre.raw-output { background: #0f172a; color: #cbd5e1; padding: 14px; border-radius: 8px; font-size: 12px; font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 400px; overflow-y: auto; line-height: 1.5; border: 1px solid #334155; }
    .tag-mod { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .tag-ok { background: #166534; color: #86efac; } .tag-warn { background: #713f12; color: #fde68a; } .tag-err { background: #7f1d1d; color: #fca5a5; } .tag-off { background: #334155; color: #94a3b8; }

    /* 发现问题 */
    .findings-section { background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155; margin-bottom: 32px; }
    .findings-section h2 { color: #f59e0b; }
    .finding-item { padding: 12px 16px; margin-bottom: 8px; background: #0f172a; border-radius: 8px; font-size: 14px; display: flex; gap: 12px; }
    .finding-item.f-mid { border-left: 4px solid #f59e0b; } .finding-item.f-low { border-left: 4px solid #3b82f6; } .finding-item.f-info { border-left: 4px solid #64748b; }
    .finding-level { flex-shrink: 0; padding: 2px 10px; border-radius: 10px; font-size: 11px; font-weight: 700; color: #fff; }
    .l-mid { background: #f59e0b; } .l-low { background: #3b82f6; } .l-info { background: #64748b; }
    .finding-server { color: #94a3b8; font-size: 12px; }

    .no-alerts { text-align: center; padding: 20px; color: #22c55e; font-size: 16px; }
    .footer { text-align: center; padding: 30px; color: #64748b; font-size: 12px; }
    @media print { body { background: #fff; color: #1e293b; } .server-card, .detail-section, .comparison-table, .findings-section { background: #f8fafc; border-color: #e2e8f0; } pre.raw-output { max-height: none; } }
    """

    # ---- 数据提取辅助函数 ----
    def safe_extract(text, patterns, default=None):
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                try: return m.group(1)
                except: continue
        return default

    def extract_os(results):
        t = results.get("system", {}).get("stdout", "")
        return safe_extract(t, [r'(CentOS|Ubuntu|Red Hat|Debian|SUSE|Rocky|AlmaLinux)[^\n]*'], "未知")

    def extract_hostname(results):
        t = results.get("system", {}).get("stdout", "")
        m = re.search(r'=== 1\.3 主机名 ===\s*\n(.+)', t)
        return m.group(1).strip() if m else "未知"

    def extract_uptime(results):
        t = results.get("system", {}).get("stdout", "")
        m = re.search(r'up\s+(.+?),\s+\d+ users?', t)
        return m.group(1).strip() if m else "未知"

    def extract_cpu_pct(results):
        t = results.get("cpu", {}).get("stdout", "")
        # top 输出: %Cpu(s):  0.0 us,  3.1 sy,  0.0 ni, 96.9 id
        m = re.search(r'%Cpu\(s\):\s*([\d.]+)\s*us,\s*([\d.]+)\s*sy,\s*([\d.]+)\s*ni,\s*([\d.]+)\s*id', t)
        if m:
            used = 100 - float(m.group(4))  # 100 - idle
            return used
        return None

    def extract_mem_pct(results):
        t = results.get("memory", {}).get("stdout", "")
        m = re.search(r'Mem:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', t)
        if m:
            total = parse_size(m.group(1))
            used = parse_size(m.group(2))
            if total > 0: return (used / total) * 100
        return None

    def extract_swap_pct(results):
        t = results.get("memory", {}).get("stdout", "")
        m = re.search(r'Swap:\s+(\S+)\s+(\S+)\s+(\S+)', t)
        if m:
            total = parse_size(m.group(1))
            used = parse_size(m.group(2))
            if total > 0: return (used / total) * 100
        return None

    def extract_disk_pct(results):
        t = results.get("disk", {}).get("stdout", "")
        # df 输出格式: /dev/sda1      xfs       150G  4.0G  146G    3% /
        lines = t.split('\n')
        for line in lines:
            if '/' in line and '/dev/' in line and not line.strip().startswith('==='):
                # 找挂载点为 / 的行
                parts = line.split()
                if parts and parts[-1] == '/' and len(parts) >= 5:
                    # 使用率在倒数第二个位置（如 "3%"）
                    pct_str = parts[-2].replace('%','')
                    try: return int(pct_str)
                    except: continue
        return None

    def extract_mem_total(results):
        t = results.get("memory", {}).get("stdout", "")
        return safe_extract(t, [r'Mem:\s+(\S+)'], "N/A")

    def extract_cpu_cores(results):
        t = results.get("cpu", {}).get("stdout", "")
        return safe_extract(t, [r'逻辑核心数:\s*(\d+)'], "N/A")

    def extract_listening_ports(results):
        t = results.get("network", {}).get("stdout", "")
        # ss -tlnp 格式: LISTEN  0  128  *:22  *:* 或 0.0.0.0:22
        ports = re.findall(r':(\d+)\s', t)
        # 过滤掉只包含标题或非端口号的数字
        valid_ports = []
        for p in ports:
            try:
                pn = int(p)
                if 1 <= pn <= 65535:
                    valid_ports.append(pn)
            except: continue
        return len(set(valid_ports))

    def extract_total_procs(results):
        t = results.get("process", {}).get("stdout", "")
        return safe_extract(t, [r'总进程数:\s*(\d+)'], "N/A")

    def parse_size(s):
        """将人类可读大小转为KB"""
        s = s.strip()
        try:
            if 'G' in s: return float(s.replace('G','')) * 1024 * 1024
            if 'M' in s: return float(s.replace('M','')) * 1024
            if 'K' in s: return float(s.replace('K',''))
            if 'T' in s: return float(s.replace('T','')) * 1024 * 1024 * 1024
            return float(s)
        except: return 0

    def pct_color(v, warn=70, danger=85):
        if v is None: return "num-blue", ""
        v = float(v)
        if v < warn: return "num-green", "fill-green"
        if v < danger: return "num-yellow", "fill-yellow"
        return "num-red", "fill-red"

    def pct_str(v):
        return f"{v:.1f}%" if v is not None else "N/A"

    def pct_fill(v):
        return round(min(float(v), 100), 1) if v is not None else 0

    def extract_alerts(results):
        alert_text = results.get("alert", {}).get("stdout", "")
        alerts = []
        for line in alert_text.split('\n'):
            line_s = line.strip()
            if not line_s or line_s.startswith('===') or '===' in line_s or line_s.startswith('echo'):
                continue
            if '告警' in line_s or ('失败' in line_s and '登录' in line_s) or '僵尸' in line_s:
                parts = line_s.split(':')
                val = parts[-1].strip() if len(parts) > 1 else ''
                if val.isdigit() and int(val) == 0: continue
                if len(parts) <= 1 and not any(c.isdigit() for c in line_s): continue
                alerts.append(line_s)
        return alerts

    def extract_java_metrics(results):
        """从 jvm_crash 模块提取Java宕机关键指标"""
        t = results.get("jvm_crash", {}).get("stdout", "")
        if not t:
            return {"proc_count": 0, "crash_logs": 0, "has_deadlock": False, "has_oom": False}
        return {
            "proc_count": safe_extract(t, [r'Java进程总数:\s*(\d+)'], "0"),
            "crash_logs": safe_extract(t, [r'近30天 JVM crash 日志数:\s*(\d+)'], "0"),
            "has_deadlock": 'Found' in t and 'deadlock' in t,
            "has_oom": bool(re.search(r'out of memory|killed process', t, re.IGNORECASE))
        }

    def extract_mysql_metrics(results):
        """从 MySQL 诊断输出中提取关键指标"""
        mysql_stdout = results.get("mysql_deep", {}).get("stdout", "")
        if not mysql_stdout or "ERROR" in mysql_stdout:
            return {}
        metrics = {}
        # 连接使用率
        m = re.search(r'usage_pct[:\s]+([\d.]+)', mysql_stdout)
        if m:
            metrics["mysql_conn_usage"] = float(m.group(1))
        # 缓冲池命中率
        m = re.search(r'hit_ratio[:\s]+([\d.]+)', mysql_stdout)
        if m:
            metrics["mysql_hit_ratio"] = float(m.group(1))
        # 慢查询数量
        m = re.search(r'Slow_queries\s+(\d+)', mysql_stdout)
        if m:
            metrics["mysql_slow"] = int(m.group(1))
        # 连接数
        m = re.search(r'Threads_connected\s+(\d+)', mysql_stdout)
        if m:
            metrics["mysql_conn"] = int(m.group(1))
        # 版本
        m = re.search(r'version\n([\d.]+)', mysql_stdout)
        if not m:
            m = re.search(r'5\\.\d+\\.\d+|8\\.\d+\\.\d+|10\\.\d+\\.\d+', mysql_stdout)
        if m:
            metrics["mysql_version"] = m.group(0)
        # 死锁次数
        m = re.search(r'Innodb_deadlocks\s+(\d+)', mysql_stdout)
        if m:
            metrics["mysql_deadlocks"] = int(m.group(1))
        # 活跃线程
        m = re.search(r'Threads_running\s+(\d+)', mysql_stdout)
        if m:
            metrics["mysql_threads_running"] = int(m.group(1))
        # 异常断开数(客户端)
        m = re.search(r'Aborted_connects\s+(\d+)', mysql_stdout)
        if m:
            metrics["mysql_aborted_connects"] = int(m.group(1))
        # 慢SQL详情条数（14.15中有多少条记录）
        slow_detail_count = len(re.findall(r'query_time_sec', mysql_stdout.split('=== 14.15')[1].split('===')[0]) if '=== 14.15' in mysql_stdout else '')
        try:
            metrics["mysql_slow_detail_count"] = int(slow_detail_count)
        except:
            metrics["mysql_slow_detail_count"] = 0
        # 峰值连接数
        m = re.search(r'Max_used_connections\s+(\d+)', mysql_stdout)
        if m:
            metrics["mysql_max_used"] = int(m.group(1))
        return metrics

    def extract_oracle_metrics(results):
        """从 Oracle 诊断输出中提取关键指标"""
        txt = results.get("oracle_deep", {}).get("stdout", "")
        if not txt or "ERROR" in txt:
            return {}
        metrics = {}
        m = re.search(r'usage_pct[:\s]+([\d.]+)', txt)
        if m: metrics["ora_conn_usage"] = float(m.group(1))
        m = re.search(r'buffer_hit_ratio[:\s]+([\d.]+)', txt)
        if m: metrics["ora_hit_ratio"] = float(m.group(1))
        m = re.search(r'version\n(.+)', txt)
        if m: metrics["ora_version"] = m.group(1).strip()[:30]
        elif re.search(r'Oracle Database (\d+\w?)', txt):
            mm = re.search(r'Oracle Database (\d+\w?)', txt)
            if mm: metrics["ora_version"] = "Oracle " + mm.group(1)
        return metrics

    def extract_mssql_metrics(results):
        """从 SQL Server 诊断输出中提取关键指标"""
        txt = results.get("mssql_deep", {}).get("stdout", "")
        if not txt or "ERROR" in txt:
            return {}
        metrics = {}
        m = re.search(r'usage_pct[:\s]+([\d.]+)', txt)
        if m: metrics["mssql_conn_usage"] = float(m.group(1))
        m = re.search(r'Buffer cache hit ratio\s+(\d+)', txt)
        if m:
            metrics["mssql_hit_ratio"] = float(m.group(1))
        else:
            m = re.search(r'cache hit ratio[:\s]+([\d.]+)', txt)
            if m: metrics["mssql_hit_ratio"] = float(m.group(1))
        m = re.search(r'version\n(.+)', txt)
        if m: metrics["mssql_version"] = m.group(1).strip()[:30]
        return metrics

    def extract_findings(results):
        """从日志和安全模块提取问题发现"""
        findings = []
        log_text = results.get("log", {}).get("stdout", "")
        sec_text = results.get("security", {}).get("stdout", "")
        proc_text = results.get("process", {}).get("stdout", "")
        backup_text = results.get("backup", {}).get("stdout", "")

        # 日志模块的问题
        if 'postfix' in log_text.lower() and ('error' in log_text.lower() or 'failed' in log_text.lower() or '失败' in log_text):
            # 提取具体错误行（最多5行），去掉章节标题
            log_body = '\n'.join([l for l in log_text.split('\n') if not l.strip().startswith('===')])
            postfix_errs = [l.strip() for l in log_body.split('\n') if 'postfix' in l.lower() or 'aliasesdb' in l.lower()][:5]
            err_detail = '; '.join(postfix_errs) if postfix_errs else '详见日志模块'
            # 判断具体根因
            if 'libmysqlclient.so.18' in log_body:
                cause = '根因：postfix 依赖 libmysqlclient.so.18（MySQL 5.5/5.6 客户端库），但当前系统运行 MySQL 5.7，该库缺失。每次开机 postfix 自启即失败。建议：若不需邮件服务，执行 systemctl disable postfix 关闭自启；若需要，执行 yum install -y mysql-community-libs-compat 补齐依赖。'
            elif 'libcrypto' in log_body.lower() or 'libssl' in log_body.lower():
                cause = '根因：postfix 依赖的 SSL/加密库不兼容，可能因系统升级导致。建议重新编译或重装 postfix。'
            else:
                cause = '根因：postfix 服务启动失败，详见上方错误日志。'
            findings.append({"level": "mid", "title": "postfix 启动失败", "desc": f"错误详情：{err_detail}。{cause}"})
        # 排除模块标题中的 "OOM" 字样，只匹配 dmesg/journalctl 中的真实 OOM 事件
        log_body = '\n'.join([l for l in log_text.split('\n') if not l.strip().startswith('===')])
        if 'killed process' in log_body.lower() or 'out of memory' in log_body.lower():
            findings.append({"level": "mid", "title": "存在 OOM 记录", "desc": "系统发生过内存溢出，请查看日志模块详情"})

        # 安全模块的问题
        if 'PasswordAuthentication' in sec_text and 'yes' in sec_text.lower():
            findings.append({"level": "mid", "title": "SSH 密码认证已开启", "desc": "建议改用密钥认证"})
        if '99999' in sec_text:
            findings.append({"level": "low", "title": "root 密码永不过期", "desc": "建议设置密码过期策略"})
        ssh_keys = re.findall(r'authorized_keys', sec_text)
        if 'SSH 授权密钥' in sec_text and '无' in sec_text.split('SSH 授权密钥')[1][:20] if 'SSH 授权密钥' in sec_text else False:
            findings.append({"level": "low", "title": "SSH 未配置授权密钥", "desc": "建议配置 authorized_keys"})

        # 进程模块
        if '僵尸进程' in proc_text:
            m = re.search(r'僵尸进程[：:]\s*(\d+)', proc_text)
            if m and int(m.group(1)) > 0:
                findings.append({"level": "mid", "title": f"存在 {m.group(1)} 个僵尸进程", "desc": "建议排查僵尸进程来源"})

        # 备份模块
        if '无' in backup_text and 'crontab' in backup_text.lower():
            findings.append({"level": "mid", "title": "无定时备份任务", "desc": "建议配置数据库/文件定时备份"})
        if '不存在' in backup_text:
            findings.append({"level": "low", "title": "备份目录不存在", "desc": "建议创建并配置备份策略"})

        # Java 宕机模块
        jvm_text = results.get("jvm_crash", {}).get("stdout", "")
        if jvm_text:
            if 'Found' in jvm_text and 'deadlock' in jvm_text:
                findings.append({"level": "mid", "title": "检测到 Java 线程死锁！", "desc": "请查看 jvm_crash 模块中的 jstack 死锁详情"})
            if 'BLOCKED' in jvm_text:
                blocked_count = jvm_text.count('BLOCKED')
                if blocked_count > 3:
                    findings.append({"level": "mid", "title": f"Java 线程阻塞较多({blocked_count}处)", "desc": "可能存在锁竞争或资源瓶颈"})
            if re.search(r'out of memory|OutOfMemory', jvm_text):
                findings.append({"level": "mid", "title": "发现 OOM/OutOfMemory 记录", "desc": "请检查 heap dump 和应用日志定位内存泄漏"})
            crash_count = safe_extract(jvm_text, [r'近30天 JVM crash 日志数:\s*(\d+)'], "0")
            if crash_count.isdigit() and int(crash_count) > 0:
                findings.append({"level": "mid", "title": f"近30天有 {crash_count} 个 JVM crash 日志", "desc": "建议分析 hs_err_pid*.log 定位崩溃根因"})

        # MySQL深度诊断
        mysql_text = results.get("mysql_deep", {}).get("stdout", "")
        if mysql_text and "ERROR" not in mysql_text[:200]:
            # 1. 连接使用率 >80%
            m = re.search(r'usage_pct[:\s]+([\d.]+)', mysql_text)
            if m and float(m.group(1)) > 80:
                findings.append({"level": "mid", "title": "MySQL连接使用率过高",
                    "desc": f"当前连接使用率{m.group(1)}%，接近max_connections上限，建议排查连接泄漏或增加最大连接数"})

            # 2. 缓冲池命中率 <95%
            m = re.search(r'hit_ratio[:\s]+([\d.]+)', mysql_text)
            if m and float(m.group(1)) < 95:
                findings.append({"level": "low", "title": "InnoDB缓冲池命中率偏低",
                    "desc": f"当前命中率{m.group(1)}%，低于95%建议值。可考虑增大innodb_buffer_pool_size"})

            # 3. 慢查询数量
            m = re.search(r'slow_query_count[:\s]+(\d+)', mysql_text)
            if m and int(m.group(1)) > 100:
                findings.append({"level": "low", "title": "存在大量慢查询",
                    "desc": f"慢查询累计{m.group(1)}条，建议启用slow_query_log并优化相关SQL"})

            # 4. 安全风险检测
            for label, keyword, level, title, desc in [
                ('匿名用户', '匿名用户', 'mid', '检测到MySQL匿名用户',
                 '存在匿名用户账号，建议执行 DROP USER \'\'@\'localhost\' 删除'),
                ('空密码用户', '空密码用户', 'mid', '检测到MySQL空密码用户',
                 '存在空密码用户账号，建议立即设置密码'),
                ('远程root', '远程root', 'low', 'root用户允许远程登录',
                 'root@\'%\' 存在安全风险，建议限制为 localhost 或特定IP'),
            ]:
                if keyword in mysql_text:
                    # 查找该检查项后面的数量
                    m2 = re.search(keyword + r'.*?(\d+)', mysql_text.replace('\n',' '))
                    if m2 and int(m2.group(1)) > 0:
                        findings.append({"level": level, "title": title, "desc": desc})

            # 5. 无主键表
            if '14.10' in mysql_text:
                idx_section = mysql_text.split('14.10')[1].split('===')[0] if '14.10' in mysql_text else ''
                tables = [l for l in idx_section.strip().split('\n') if l.strip()
                         and not l.startswith('table_schema') and not l.startswith('[提示]')
                         and l.strip() != '' and 'in set' not in l]
                if len(tables) > 0:
                    findings.append({"level": "low", "title": f"发现{len(tables)}个无主键表",
                        "desc": "无主键可能导致主从延迟和性能问题，建议为核心表添加主键"})

            # 6. 主从延迟
            m = re.search(r'Seconds_Behind_Master[:\s]+(\d+)', mysql_text)
            if m and int(m.group(1)) > 60:
                findings.append({"level": "mid", "title": "主从复制延迟严重",
                    "desc": f"从库延迟{m.group(1)}秒，建议检查网络和从库负载"})

        # 连接失败（需要在 mysql_text 检查之后，因为前面用了 ERROR 判断）
        if mysql_text and ("ERROR 1045" in mysql_text or "Access denied" in mysql_text):
            findings.append({"level": "mid", "title": "MySQL连接失败(认证错误)",
                "desc": "无法连接到MySQL，请检查数据库用户名和密码"})
        elif mysql_text and ("ERROR 2003" in mysql_text or "Can't connect" in mysql_text):
            findings.append({"level": "mid", "title": "MySQL连接失败(网络不通)",
                "desc": "无法连接到MySQL服务器，请检查数据库地址和端口"})

        return findings

    # 模块标题和状态映射
    MODULE_INFO = {
        "system":    {"title": "一、系统基础信息", "dot": "dot-info"},
        "cpu":       {"title": "二、CPU 负载巡检", "dot": "dot-ok"},
        "memory":    {"title": "三、内存 & Swap 巡检", "dot": "dot-ok"},
        "disk":      {"title": "四、磁盘空间巡检", "dot": "dot-ok"},
        "network":   {"title": "五、网络状态巡检", "dot": "dot-ok"},
        "process":   {"title": "六、进程 & 服务巡检", "dot": "dot-warn"},
        "log":       {"title": "七、日志巡检", "dot": "dot-warn"},
        "security":  {"title": "八、用户与安全巡检", "dot": "dot-warn"},
        "hardware":  {"title": "九、硬件状态巡检", "dot": "dot-info"},
        "middleware": {"title": "十、数据库/中间件巡检", "dot": "dot-ok"},
        "backup":    {"title": "十一、备份 & 业务巡检", "dot": "dot-err"},
        "alert":     {"title": "十二、资源阈值告警汇总", "dot": "dot-ok"},
        "jvm_crash": {"title": "十三、Java 宕机分析", "dot": "dot-warn"},
        "mysql_deep":{"title": "十四、MySQL深度诊断", "dot": "dot-ok"},
        "oracle_deep":{"title": "十五、Oracle深度诊断", "dot": "dot-ok"},
        "mssql_deep":{"title": "十六、SQL Server深度诊断", "dot": "dot-ok"},
    }

    # ---- 构建HTML ----
    server_cards = []
    comparison_rows = []
    detail_panels = []
    all_findings = []
    all_alerts = []

    for r in batch_results:
        alias = r.get("alias", r["host"])
        host = r["host"]
        tags_html = "".join(f'<span class="tag">{t}</span>' for t in r.get("tags", []))

        if not r["success"]:
            server_cards.append(f"""
            <div class="server-card fail">
                <div class="server-header">
                    <div><div class="server-name">{alias}</div><div class="server-host">{host}:{r.get('port',22)}</div><div class="tags">{tags_html}</div></div>
                    <span class="badge badge-fail">连接失败</span>
                </div>
                <div style="color:#ef4444;font-size:14px">{html_lib.escape(str(r.get('error','未知错误')))}</div>
            </div>""")
            continue

        results = r.get("results", {})

        # 提取指标
        os_info = extract_os(results)
        hostname = extract_hostname(results)
        uptime = extract_uptime(results)
        cpu_pct = extract_cpu_pct(results)
        mem_pct = extract_mem_pct(results)
        swap_pct = extract_swap_pct(results)
        disk_pct = extract_disk_pct(results)
        mem_total = extract_mem_total(results)
        cpu_cores = extract_cpu_cores(results)
        listen_ports = extract_listening_ports(results)
        total_procs = extract_total_procs(results)
        alerts = extract_alerts(results)
        findings = extract_findings(results)
        java_m = extract_java_metrics(results)
        mysql_m = extract_mysql_metrics(results)
        oracle_m = extract_oracle_metrics(results)
        mssql_m = extract_mssql_metrics(results)

        all_alerts.append({"alias": alias, "host": host, "alerts": alerts})
        for f in findings:
            f["server"] = f"{alias} ({host})"
            all_findings.append(f)

        # 状态判断
        has_alerts = len(alerts) > 0
        has_findings = len(findings) > 0
        badge_html = '<span class="badge badge-warn">有告警</span>' if has_alerts else ('<span class="badge badge-warn">需关注</span>' if has_findings else '<span class="badge badge-ok">正常</span>')

        cpu_c, cpu_f = pct_color(cpu_pct, 70, 80)
        mem_c, mem_f = pct_color(mem_pct, 70, 85)
        swap_c, swap_f = pct_color(swap_pct, 30, 50)
        disk_c, disk_f = pct_color(disk_pct, 70, 85)

        # 概览卡片
        server_cards.append(f"""
        <div class="server-card">
            <div class="server-header">
                <div>
                    <div class="server-name">{alias}</div>
                    <div class="server-host">{host}:{r.get('port',22)}</div>
                    <div class="tags">{tags_html}</div>
                </div>
                {badge_html}
            </div>
            <div style="font-size:13px;color:#64748b;margin-bottom:12px">
                {os_info} | {hostname} | 运行: {uptime}
            </div>
            <div class="metrics">
                <div class="metric"><div class="val {cpu_c}">{pct_str(cpu_pct)}</div><div class="lbl">CPU ({cpu_cores}核)</div>
                    <div class="progress-bar"><div class="progress-fill {cpu_f}" style="width:{pct_fill(cpu_pct)}%"></div></div></div>
                <div class="metric"><div class="val {mem_c}">{pct_str(mem_pct)}</div><div class="lbl">内存 ({mem_total})</div>
                    <div class="progress-bar"><div class="progress-fill {mem_f}" style="width:{pct_fill(mem_pct)}%"></div></div></div>
                <div class="metric"><div class="val {disk_c}">{f'{disk_pct}%' if disk_pct is not None else 'N/A'}</div><div class="lbl">磁盘 (/)</div>
                    <div class="progress-bar"><div class="progress-fill {disk_f}" style="width:{pct_fill(disk_pct)}%"></div></div></div>
                <div class="metric"><div class="val {swap_c}">{pct_str(swap_pct)}</div><div class="lbl">Swap</div>
                    <div class="progress-bar"><div class="progress-fill {swap_f}" style="width:{pct_fill(swap_pct)}%"></div></div></div>
                <div class="metric"><div class="val num-blue">{listen_ports}</div><div class="lbl">监听端口</div></div>
                <div class="metric"><div class="val num-blue">{total_procs}</div><div class="lbl">总进程数</div></div>
            </div>
            {f'''<div style="margin-top:10px;padding:8px 12px;background:#0f172a;border-radius:8px;font-size:12px;display:flex;gap:16px;flex-wrap:wrap">
                <span><span style="color:#3b82f6">Java进程:</span> {java_m["proc_count"]}</span>
                <span><span style="color:{"#ef4444" if java_m["crash_logs"] != "0" else "#64748b"}">Crash日志:</span> {java_m["crash_logs"]}</span>
                <span><span style="color:{"#ef4444" if java_m["has_deadlock"] else "#22c55e"}">死锁:</span> {"是" if java_m["has_deadlock"] else "否"}</span>
                <span><span style="color:{"#ef4444" if java_m["has_oom"] else "#64748b"}">OOM记录:</span> {"有" if java_m["has_oom"] else "无"}</span>
            </div>''' if java_m and int(java_m.get("proc_count", 0) or 0) > 0 else ""}
            {f'''<div style="margin-top:10px;padding:8px 12px;background:#0f172a;border-radius:8px;font-size:12px;display:flex;gap:16px;flex-wrap:wrap">
                <span><span style="color:#3b82f6">MySQL版本:</span> {mysql_m.get("mysql_version","N/A")}</span>
                <span><span style="color:#3b82f6">连接数:</span> {mysql_m.get("mysql_conn","N/A")}</span>
                <span><span style="color:{"#22c55e" if mysql_m.get("mysql_hit_ratio",100) >= 95 else "#f59e0b"}">命中率:</span> {mysql_m.get("mysql_hit_ratio","N/A")}%</span>
                <span><span style="color:{"#ef4444" if mysql_m.get("mysql_conn_usage",0) > 80 else "#64748b"}">使用率:</span> {mysql_m.get("mysql_conn_usage","N/A")}%</span>
                <span><span style="color:{"#f59e0b" if mysql_m.get("mysql_slow",0) > 0 else "#64748b"}">慢查询:</span> {mysql_m.get("mysql_slow","N/A")}</span>
            </div>''' if mysql_m else ""}
            {f'''<div style="margin-top:10px;padding:8px 12px;background:#0f172a;border-radius:8px;font-size:12px;display:flex;gap:16px;flex-wrap:wrap">
                <span><span style="color:#f59e0b">Oracle版本:</span> {oracle_m.get("ora_version","N/A")}</span>
                <span><span style="color:{"#22c55e" if oracle_m.get("ora_hit_ratio",100) >= 95 else "#f59e0b"}">命中率:</span> {oracle_m.get("ora_hit_ratio","N/A")}%</span>
                <span><span style="color:{"#ef4444" if oracle_m.get("ora_conn_usage",0) > 80 else "#64748b"}">使用率:</span> {oracle_m.get("ora_conn_usage","N/A")}%</span>
            </div>''' if oracle_m else ""}
            {f'''<div style="margin-top:10px;padding:8px 12px;background:#0f172a;border-radius:8px;font-size:12px;display:flex;gap:16px;flex-wrap:wrap">
                <span><span style="color:#06b6d4">MSSQL版本:</span> {mssql_m.get("mssql_version","N/A")}</span>
                <span><span style="color:{"#22c55e" if mssql_m.get("mssql_hit_ratio",100) >= 95 else "#f59e0b"}">命中率:</span> {mssql_m.get("mssql_hit_ratio","N/A")}%</span>
                <span><span style="color:{"#ef4444" if mssql_m.get("mssql_conn_usage",0) > 80 else "#64748b"}">使用率:</span> {mssql_m.get("mssql_conn_usage","N/A")}%</span>
            </div>''' if mssql_m else ""}
            {f'<div style="margin-top:12px;font-size:13px;color:#f59e0b">告警: {len(alerts)} 项 | 问题: {len(findings)} 项</div>' if (has_alerts or has_findings) else ''}
        </div>""")

        # 对比行
        comparison_rows.append(f"""
        <tr>
            <td><strong>{alias}</strong><br><small style="color:#64748b">{host}</small></td>
            <td style="font-size:13px">{os_info}</td>
            <td class="{cpu_c}">{pct_str(cpu_pct)}</td>
            <td><div class="progress-bar"><div class="progress-fill {cpu_f}" style="width:{pct_fill(cpu_pct)}%"></div></div></td>
            <td class="{mem_c}">{pct_str(mem_pct)}</td>
            <td><div class="progress-bar"><div class="progress-fill {mem_f}" style="width:{pct_fill(mem_pct)}%"></div></div></td>
            <td class="{disk_c}">{f'{disk_pct}%' if disk_pct is not None else 'N/A'}</td>
            <td><div class="progress-bar"><div class="progress-fill {disk_f}" style="width:{pct_fill(disk_pct)}%"></div></div></td>
            <td class="{swap_c}">{pct_str(swap_pct)}</td>
            <td>{listen_ports}</td>
            <td>{total_procs}</td>
            <td style="color:#3b82f6">{java_m.get("proc_count", 0)}</td>
            <td style="color:{'#ef4444' if java_m.get('crash_logs','0') != '0' else '#64748b'}">{java_m.get('crash_logs', 0)}</td>
            <td style="color:{'#ef4444' if java_m.get('has_deadlock') else '#22c55e'}">{'Y' if java_m.get('has_deadlock') else 'N'}</td>
            <td style="color:#3b82f6">{mysql_m.get('mysql_version','-') if mysql_m else '-'}</td>
            <td style="color:{'#f59e0b' if mysql_m and mysql_m.get('mysql_hit_ratio',100) < 95 else '#22c55e'}">{f'{mysql_m["mysql_hit_ratio"]}%' if mysql_m and 'mysql_hit_ratio' in mysql_m else '-'}</td>
            <td style="color:#f59e0b">{oracle_m.get('ora_version','-') if oracle_m else '-'}</td>
            <td style="color:{'#f59e0b' if oracle_m and oracle_m.get('ora_hit_ratio',100) < 95 else '#22c55e'}">{f'{oracle_m["ora_hit_ratio"]}%' if oracle_m and 'ora_hit_ratio' in oracle_m else '-'}</td>
            <td style="color:#06b6d4">{mssql_m.get('mssql_version','-') if mssql_m else '-'}</td>
            <td style="color:{'#f59e0b' if mssql_m and mssql_m.get('mssql_hit_ratio',100) < 95 else '#22c55e'}">{f'{mssql_m["mssql_hit_ratio"]}%' if mssql_m and 'mssql_hit_ratio' in mssql_m else '-'}</td>
            <td><span class="badge {'badge-warn' if (has_alerts or has_findings) else 'badge-ok'}">{'需关注' if (has_alerts or has_findings) else '正常'}</span></td>
        </tr>""")

        # 详情面板 - 为每台服务器生成可展开的12类巡检详情
        module_html_parts = []
        for mod_key, mod_data in MODULE_INFO.items():
            if mod_key not in results:
                continue
            stdout = results[mod_key].get("stdout", "")
            stderr = results[mod_key].get("stderr", "")
            if not stdout and not stderr:
                continue
            raw = stdout if stdout else stderr
            escaped_raw = html_lib.escape(raw).replace('\n', '<br>')
            dot_class = mod_data["dot"]

            # 判断模块状态
            mod_status = "tag-ok"
            if mod_key in ("log",):
                if 'error' in raw.lower() or 'failed' in raw.lower() or '失败' in raw:
                    mod_status = "tag-err"
                elif 'warning' in raw.lower() or 'warn' in raw.lower():
                    mod_status = "tag-warn"
            elif mod_key in ("security",):
                if 'PasswordAuthentication' in raw and 'yes' in raw.lower():
                    mod_status = "tag-warn"
                elif '99999' in raw:
                    mod_status = "tag-warn"
            elif mod_key in ("backup",):
                if '不存在' in raw or ('无' in raw and 'crontab' in raw.lower()):
                    mod_status = "tag-err"
            elif mod_key in ("process",):
                if '僵尸进程' in raw:
                    m_z = re.search(r'僵尸进程[：:]\s*(\d+)', raw)
                    if m_z and int(m_z.group(1)) > 0:
                        mod_status = "tag-err"
            elif mod_key in ("jvm_crash",):
                if 'Found' in raw and 'deadlock' in raw:
                    mod_status = "tag-err"
                elif 'out of memory' in raw.lower() or 'OutOfMemory' in raw:
                    mod_status = "tag-err"
                elif re.search(r'近30天 JVM crash 日志数:\s*[1-9]', raw):
                    mod_status = "tag-warn"
            elif mod_key in ("mysql_deep",):
                if "ERROR 1045" in raw or "Access denied" in raw or "ERROR 2003" in raw:
                    mod_status = "tag-err"
                else:
                    # 检测安全风险非零
                    for kw in ['匿名用户', '空密码用户', '远程root']:
                        m = re.search(kw + r'\s+(\d+)', raw)
                        if m and int(m.group(1)) > 0:
                            mod_status = "tag-warn"
                            break
                    # 连接使用率 >80%
                    if mod_status == "tag-ok":
                        m = re.search(r'usage_pct[:\s]+([\d.]+)', raw)
                        if m and float(m.group(1)) > 80:
                            mod_status = "tag-warn"
            elif mod_key in ("oracle_deep",):
                if "连接失败" in raw or "ERROR" in raw[:200]:
                    mod_status = "tag-err"
                else:
                    m = re.search(r'usage_pct[:\s]+([\d.]+)', raw)
                    if m and float(m.group(1)) > 80:
                        mod_status = "tag-warn"
                    # 检测死锁/阻塞
                    if mod_status == "tag-ok" and ('blocking_session' in raw.lower() and 'NOT NULL' not in raw):
                        mod_status = "tag-warn"
            elif mod_key in ("mssql_deep",):
                if "连接失败" in raw or "ERROR" in raw[:200]:
                    mod_status = "tag-err"
                else:
                    m = re.search(r'usage_pct[:\s]+([\d.]+)', raw)
                    if m and float(m.group(1)) > 80:
                        mod_status = "tag-warn"
                    # 检测死锁
                    if mod_status == "tag-ok" and 'blocking_session_id' in raw and 'NULL' not in raw.split('blocking_session_id')[1][:20] if 'blocking_session_id' in raw else False:
                        mod_status = "tag-warn"

            module_html_parts.append(f"""
            <div class="module-section">
                <div class="module-title">
                    <span class="dot {dot_class}"></span>
                    {mod_data['title']}
                    <span class="tag-mod {mod_status}">{'正常' if mod_status == 'tag-ok' else ('异常' if mod_status == 'tag-err' else '注意')}</span>
                </div>
                <pre class="raw-output">{escaped_raw}</pre>
            </div>""")

        modules_html = "".join(module_html_parts)
        detail_panels.append(f"""
        <div class="detail-section">
            <div class="detail-toggle" onclick="toggleDetail(this)">
                <span style="font-size:18px;font-weight:600">{alias} ({host}) — 巡检详情（点击展开）</span>
                <span class="arrow">&#9654;</span>
            </div>
            <div class="detail-content">{modules_html}</div>
        </div>""")

    # 告警汇总
    alert_items_html = []
    for a in all_alerts:
        for al in a["alerts"]:
            alert_items_html.append(f"""
            <div class="alert-item" style="margin-bottom:8px;background:#0f172a;border-radius:8px;border-left:4px solid #f59e0b;padding:10px 16px">
                <div style="color:#94a3b8;font-size:12px">{a['alias']} ({a['host']})</div>
                <div style="font-size:14px">{html_lib.escape(al)}</div>
            </div>""")

    alerts_section_html = ""
    if alert_items_html:
        alerts_section_html = f"""
        <div class="detail-section">
            <h2 style="color:#f59e0b">告警汇总 ({len(alert_items_html)} 项)</h2>
            {"".join(alert_items_html)}
        </div>"""
    else:
        alerts_section_html = '<div class="no-alerts">所有服务器巡检通过，无告警项</div>'

    # 发现问题汇总
    findings_html = ""
    if all_findings:
        finding_items = []
        for f in sorted(all_findings, key=lambda x: {"mid":0,"low":1,"info":2}.get(x["level"],3)):
            level_map = {"mid": ("中","l-mid","f-mid"), "low": ("低","l-low","f-low"), "info": ("信息","l-info","f-info")}
            lv_text, lv_class, f_class = level_map.get(f["level"], ("信息","l-info","f-info"))
            finding_items.append(f"""
            <div class="finding-item {f_class}">
                <div class="finding-level {lv_class}">{lv_text}</div>
                <div><div style="font-weight:600">{html_lib.escape(f['title'])}</div>
                <div style="color:#94a3b8;font-size:12px;margin-top:2px">{f['server']}</div>
                <div style="color:#cbd5e1;font-size:13px;margin-top:4px">{html_lib.escape(f['desc'])}</div></div>
            </div>""")
        findings_html = f"""
        <div class="findings-section">
            <h2 style="color:#f59e0b">发现的问题 & 建议 ({len(all_findings)} 项)</h2>
            {"".join(finding_items)}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>批量巡检报告 - {now}</title>
    <style>{CSS}</style>
</head>
<body>
    <div class="container">
        <h1>Linux 服务器批量巡检报告</h1>
        <p class="subtitle">{now} &nbsp;|&nbsp; 共 {total} 台服务器 &nbsp;|&nbsp; 成功 {success_count} &nbsp;|&nbsp; 失败 {total - success_count}</p>

        <div class="stats">
            <div class="stat-card"><div class="num num-blue">{total}</div><div class="label">服务器总数</div></div>
            <div class="stat-card"><div class="num num-green">{success_count}</div><div class="label">巡检成功</div></div>
            <div class="stat-card"><div class="num num-red">{total - success_count}</div><div class="label">巡检失败</div></div>
            <div class="stat-card"><div class="num num-yellow">{len(alert_items_html)}</div><div class="label">告警项</div></div>
            <div class="stat-card"><div class="num num-yellow">{len(all_findings)}</div><div class="label">待处理问题</div></div>
        </div>

        <h2>服务器概览</h2>
        <div class="server-grid">{"".join(server_cards)}</div>

        <div class="comparison-table">
            <h2>跨服务器对比</h2>
            <table>
                <thead><tr>
                    <th>服务器</th><th>操作系统</th><th>CPU</th><th>CPU</th><th>内存</th><th>内存</th><th>磁盘(/)</th><th>磁盘</th><th>Swap</th><th>端口</th><th>进程</th><th>Java</th><th>Crash</th><th>死锁</th><th>MySQL</th><th>命中率</th><th>Oracle</th><th>O命中</th><th>MSSQL</th><th>M命中</th><th>状态</th>
                </tr></thead>
                <tbody>{"".join(comparison_rows)}</tbody>
            </table>
        </div>

        {alerts_section_html}
        {findings_html}

        <h2>巡检详情（点击服务器展开）</h2>
        {"".join(detail_panels)}

    </div>
    <div class="footer">Linux 服务器批量巡检报告 &nbsp;|&nbsp; AI 自动化巡检 &nbsp;|&nbsp; {now}</div>

    <script>
    function toggleDetail(el) {{
        el.classList.toggle('open');
        var content = el.nextElementSibling;
        content.classList.toggle('show');
    }}
    </script>
</body>
</html>"""

    html_path = os.path.join(output_dir, f"batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    os.makedirs(output_dir, exist_ok=True)
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)

    return html_path


def main():
    parser = argparse.ArgumentParser(
        description='Linux服务器全量巡检工具（支持单机 & 批量巡检）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
巡检模块（可用: {', '.join(ALL_MODULES)}）:
  system     系统基础信息
  cpu        CPU负载巡检
  memory     内存&Swap巡检
  disk       磁盘空间巡检
  network    网络状态巡检
  process    进程&服务巡检
  log        日志巡检
  security   用户与安全巡检
  hardware   硬件状态巡检
  middleware 数据库/中间件专项
  backup     备份&业务巡检
  alert      资源阈值告警汇总
  jvm_crash  Java 宕机分析（jstack/jmap/jstat/crash log）
  mysql_deep MySQL/MariaDB 深度诊断（需 --mysql-host --mysql-user --mysql-password）
  oracle_deep Oracle 深度诊断（需 --oracle-host --oracle-user --oracle-password）
  mssql_deep  SQL Server 深度诊断（需 --mssql-host --mssql-user --mssql-password）

示例:
  # 单机巡检（密码认证）
  python %(prog)s --host 192.0.2.10 --user root --password xxx

  # 单机巡检（密钥认证）
  python %(prog)s --host 192.0.2.10 --user root --key ~/.ssh/id_ed25519

  # 只检查CPU和内存
  python %(prog)s --host 192.0.2.10 --user root --password xxx --check cpu,memory

  # MySQL深度诊断（单机模式，直连数据库）
  python %(prog)s --host 192.0.2.10 --user root --password xxx --check mysql_deep --mysql-host 192.0.2.20 --mysql-user root --mysql-password root

  # Oracle深度诊断
  python %(prog)s --host 192.0.2.10 --user root --password xxx --check oracle_deep --oracle-host 192.0.2.20 --oracle-user system --oracle-password <database-password>

  # SQL Server深度诊断
  python %(prog)s --host 192.0.2.10 --user root --password xxx --check mssql_deep --mssql-host 192.0.2.20 --mssql-user sa --mssql-password <database-password>

  # 批量巡检
  python %(prog)s --inventory inventory.json

  # 批量巡检（指定并发数和模块）
  python %(prog)s --inventory inventory.json --workers 5 --check cpu,memory,disk,alert

  # 批量巡检（指定输出目录，生成HTML）
  python %(prog)s --inventory inventory.json --output-dir ./reports --html
        """
    )

    # 单机巡检参数
    parser.add_argument('--host', help='服务器IP地址（单机模式）')
    parser.add_argument('--port', type=int, default=22, help='SSH端口 (默认: 22)')
    parser.add_argument('--user', help='SSH用户名（单机模式）')
    parser.add_argument('--password', help='SSH密码')
    parser.add_argument('--key', help='SSH密钥文件路径')

    # 批量巡检参数
    parser.add_argument('--inventory', help='服务器清单文件路径（JSON格式）')
    parser.add_argument('--workers', type=int, default=3, help='批量巡检服务器并发线程数 (默认: 3)')

    # 模块并发参数
    parser.add_argument('--module-workers', type=int, default=5,
                        help='单服务器模块并发线程数 (默认: 5, 设为1回退串行)')
    parser.add_argument('--module-timeout', type=int, default=None,
                        help='单模块超时秒数 (默认: 继承 --timeout)')

    # 通用参数
    parser.add_argument('--check', help=f'巡检模块，逗号分隔 (默认: 全部)')
    parser.add_argument('-o', '--output', help='报告保存路径（文本，单机模式）')
    parser.add_argument('--json-output', help='报告保存路径（JSON，单机模式）')
    parser.add_argument('--output-dir', help='报告输出目录（批量模式，默认: ./reports）')
    parser.add_argument('--html', action='store_true', help='生成HTML汇总报告（批量模式）')
    parser.add_argument('--timeout', type=int, default=120, help='命令超时秒数 (默认: 120)')
    parser.add_argument('--mysql-host', default='127.0.0.1', help='MySQL数据库地址 (默认: 127.0.0.1)')
    parser.add_argument('--mysql-port', type=int, default=3306, help='MySQL端口 (默认: 3306)')
    parser.add_argument('--mysql-user', default='root', help='MySQL用户名 (默认: root)')
    parser.add_argument('--mysql-password', default='', help='MySQL密码')
    parser.add_argument('--oracle-host', default='127.0.0.1', help='Oracle数据库地址 (默认: 127.0.0.1)')
    parser.add_argument('--oracle-port', type=int, default=1521, help='Oracle端口 (默认: 1521)')
    parser.add_argument('--oracle-user', default='system', help='Oracle用户名 (默认: system)')
    parser.add_argument('--oracle-password', default='', help='Oracle密码')
    parser.add_argument('--oracle-service', default='ORCL', help='Oracle Service Name (默认: ORCL)')
    parser.add_argument('--mssql-host', default='127.0.0.1', help='SQL Server数据库地址 (默认: 127.0.0.1)')
    parser.add_argument('--mssql-port', type=int, default=1433, help='SQL Server端口 (默认: 1433)')
    parser.add_argument('--mssql-user', default='sa', help='SQL Server用户名 (默认: sa)')
    parser.add_argument('--mssql-password', default='', help='SQL Server密码')

    args = parser.parse_args()

    # 模式判断
    if args.inventory:
        # 批量巡检模式
        if not os.path.exists(args.inventory):
            print(f"[错误] 清单文件不存在: {args.inventory}")
            sys.exit(1)
        success = run_batch_inspection(
            inventory_file=args.inventory,
            modules=args.check,
            workers=args.workers,
            output_dir=args.output_dir,
            generate_html=args.html,
            module_workers=args.module_workers,
            module_timeout=args.module_timeout,
        )
    elif args.host:
        # 单机巡检模式
        if not args.user:
            parser.error("单机模式必须提供 --user 参数")
        if not args.password and not args.key:
            parser.error("必须提供 --password 或 --key 参数")

        # 组装数据库凭证
        def _need_module(name):
            if not args.check:
                return True
            check_str = args.check.replace(' ', '')
            # --check all 时所有模块都需要凭证
            if check_str == 'all':
                return True
            return name in check_str

        mysql_creds = None
        if _need_module('mysql_deep'):
            mysql_creds = {"host": args.mysql_host, "port": args.mysql_port, "user": args.mysql_user, "password": args.mysql_password}
        oracle_creds = None
        if _need_module('oracle_deep'):
            oracle_creds = {"host": args.oracle_host, "port": args.oracle_port, "user": args.oracle_user, "password": args.oracle_password, "service": args.oracle_service}
        mssql_creds = None
        if _need_module('mssql_deep'):
            mssql_creds = {"host": args.mssql_host, "port": args.mssql_port, "user": args.mssql_user, "password": args.mssql_password}

        success, _ = run_inspection(
            host=args.host,
            port=args.port,
            user=args.user,
            password=args.password,
            key_file=args.key,
            modules=args.check,
            output_file=args.output,
            json_output=args.json_output,
            timeout=args.timeout,
            mysql_creds=mysql_creds,
            oracle_creds=oracle_creds,
            mssql_creds=mssql_creds,
            module_workers=args.module_workers,
            module_timeout=args.module_timeout,
        )
    else:
        parser.error("请指定 --host（单机巡检）或 --inventory（批量巡检）")

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
