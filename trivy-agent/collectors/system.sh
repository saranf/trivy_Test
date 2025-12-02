#!/bin/bash
# 📊 System Collector - 시스템 정보 수집
# 수집 항목: 호스트 정보, 메모리, 디스크, 로드

# CPU 정보
cpu_count=$(nproc 2>/dev/null || echo "unknown")
load_avg=$(cat /proc/loadavg 2>/dev/null | awk '{print $1","$2","$3}' || echo "0,0,0")

# 메모리 정보
mem_total=$(free -b 2>/dev/null | grep Mem | awk '{print $2}' || echo 0)
mem_used=$(free -b 2>/dev/null | grep Mem | awk '{print $3}' || echo 0)
mem_free=$(free -b 2>/dev/null | grep Mem | awk '{print $4}' || echo 0)

# 디스크 정보
disk_info=$(df -B1 / 2>/dev/null | tail -1 | awk '{print "{\"total\":"$2",\"used\":"$3",\"available\":"$4",\"percent\":\""$5"\"}"}' || echo '{}')

# 업타임
uptime_seconds=$(cat /proc/uptime 2>/dev/null | awk '{print int($1)}' || echo 0)

# 출력
cat <<EOF
{
    "hostname": "$(hostname)",
    "cpu_count": ${cpu_count},
    "load_avg": [${load_avg}],
    "memory": {
        "total": ${mem_total},
        "used": ${mem_used},
        "free": ${mem_free}
    },
    "disk": ${disk_info},
    "uptime_seconds": ${uptime_seconds},
    "collected_at": "$(date -Iseconds)"
}
EOF

