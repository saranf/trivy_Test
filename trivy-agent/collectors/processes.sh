#!/bin/bash
# 📊 Process Collector - 프로세스 정보 수집
# 수집 항목: 실행 중인 프로세스, CPU/메모리 사용량 상위 프로세스

# 전체 프로세스 수
total_processes=$(ps aux 2>/dev/null | wc -l)

# 상위 10개 프로세스 (CPU 사용량 기준)
top_cpu=$(ps aux --sort=-%cpu 2>/dev/null | head -11 | tail -10 | awk '
BEGIN { printf "[" }
NR>0 {
    if (NR>1) printf ","
    gsub(/"/, "\\\"", $11)
    printf "{\"user\":\"%s\",\"pid\":%s,\"cpu\":%.1f,\"mem\":%.1f,\"command\":\"%s\"}", $1, $2, $3, $4, $11
}
END { printf "]" }
')

# 상위 10개 프로세스 (메모리 사용량 기준)
top_mem=$(ps aux --sort=-%mem 2>/dev/null | head -11 | tail -10 | awk '
BEGIN { printf "[" }
NR>0 {
    if (NR>1) printf ","
    gsub(/"/, "\\\"", $11)
    printf "{\"user\":\"%s\",\"pid\":%s,\"cpu\":%.1f,\"mem\":%.1f,\"command\":\"%s\"}", $1, $2, $3, $4, $11
}
END { printf "]" }
')

# 리스닝 포트
listening_ports=$(netstat -tlnp 2>/dev/null | grep LISTEN | awk '
BEGIN { printf "[" }
NR>0 {
    if (NR>1) printf ","
    split($4, a, ":")
    port = a[length(a)]
    gsub(/\/.*/, "", $7)
    printf "{\"port\":%s,\"pid\":\"%s\"}", port, $7
}
END { printf "]" }
' || echo "[]")

cat <<EOF
{
    "total_processes": ${total_processes},
    "top_cpu": ${top_cpu:-[]},
    "top_mem": ${top_mem:-[]},
    "listening_ports": ${listening_ports},
    "collected_at": "$(date -Iseconds)"
}
EOF

