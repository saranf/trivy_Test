#!/bin/bash
# 🔥 IPTables Collector - 방화벽 규칙 수집
# 수집 항목: INPUT/OUTPUT/FORWARD 체인 규칙

# iptables 명령 실행 가능 여부 확인
if ! command -v iptables &> /dev/null; then
    echo '{"error": "iptables not available", "collected_at": "'$(date -Iseconds)'"}'
    exit 0
fi

# INPUT 체인
input_rules=$(iptables -L INPUT -n -v 2>/dev/null | tail -n +3 | awk '
BEGIN { printf "[" }
NR>0 {
    if (NR>1) printf ","
    printf "{\"pkts\":%s,\"bytes\":%s,\"target\":\"%s\",\"prot\":\"%s\",\"source\":\"%s\",\"dest\":\"%s\"}", $1, $2, $3, $4, $8, $9
}
END { printf "]" }
' || echo "[]")

# OUTPUT 체인
output_rules=$(iptables -L OUTPUT -n -v 2>/dev/null | tail -n +3 | awk '
BEGIN { printf "[" }
NR>0 {
    if (NR>1) printf ","
    printf "{\"pkts\":%s,\"bytes\":%s,\"target\":\"%s\",\"prot\":\"%s\",\"source\":\"%s\",\"dest\":\"%s\"}", $1, $2, $3, $4, $8, $9
}
END { printf "]" }
' || echo "[]")

# FORWARD 체인
forward_rules=$(iptables -L FORWARD -n -v 2>/dev/null | tail -n +3 | awk '
BEGIN { printf "[" }
NR>0 {
    if (NR>1) printf ","
    printf "{\"pkts\":%s,\"bytes\":%s,\"target\":\"%s\",\"prot\":\"%s\",\"source\":\"%s\",\"dest\":\"%s\"}", $1, $2, $3, $4, $8, $9
}
END { printf "]" }
' || echo "[]")

# 정책
input_policy=$(iptables -L INPUT 2>/dev/null | head -1 | grep -oP 'policy \K\w+' || echo "unknown")
output_policy=$(iptables -L OUTPUT 2>/dev/null | head -1 | grep -oP 'policy \K\w+' || echo "unknown")
forward_policy=$(iptables -L FORWARD 2>/dev/null | head -1 | grep -oP 'policy \K\w+' || echo "unknown")

cat <<EOF
{
    "policies": {
        "INPUT": "${input_policy}",
        "OUTPUT": "${output_policy}",
        "FORWARD": "${forward_policy}"
    },
    "INPUT": ${input_rules},
    "OUTPUT": ${output_rules},
    "FORWARD": ${forward_rules},
    "collected_at": "$(date -Iseconds)"
}
EOF

