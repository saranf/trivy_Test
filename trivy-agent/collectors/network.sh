#!/bin/bash
# 🌐 Network Collector - 네트워크 정보 수집
# 수집 항목: 인터페이스, 연결 상태, 라우팅

# 네트워크 인터페이스
interfaces=$(ip -j addr 2>/dev/null || echo "[]")

# 활성 연결 (ESTABLISHED)
connections=$(netstat -tn 2>/dev/null | grep ESTABLISHED | awk '
BEGIN { printf "[" }
NR>0 {
    if (NR>1) printf ","
    printf "{\"local\":\"%s\",\"remote\":\"%s\",\"state\":\"ESTABLISHED\"}", $4, $5
}
END { printf "]" }
' || echo "[]")

# 연결 상태 요약
conn_summary=$(netstat -tn 2>/dev/null | tail -n +3 | awk '
{
    state[$6]++
}
END {
    printf "{"
    first=1
    for (s in state) {
        if (!first) printf ","
        printf "\"%s\":%d", s, state[s]
        first=0
    }
    printf "}"
}
' || echo '{}')

# 라우팅 테이블
routes=$(ip -j route 2>/dev/null || echo "[]")

# DNS 서버
dns_servers=$(cat /etc/resolv.conf 2>/dev/null | grep nameserver | awk '
BEGIN { printf "[" }
NR>0 {
    if (NR>1) printf ","
    printf "\"%s\"", $2
}
END { printf "]" }
' || echo "[]")

cat <<EOF
{
    "interfaces": ${interfaces},
    "connection_summary": ${conn_summary},
    "active_connections": ${connections},
    "routes": ${routes},
    "dns_servers": ${dns_servers},
    "collected_at": "$(date -Iseconds)"
}
EOF

