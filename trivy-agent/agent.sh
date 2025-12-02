#!/bin/bash
# 🤖 Trivy Agent - Main Script
# 확장 가능한 보안 스캐너 에이전트

set -e

# ========================================
# 설정
# ========================================
CENTRAL_API_URL="${CENTRAL_API_URL:-http://localhost/api/agent.php}"
AGENT_TOKEN="${AGENT_TOKEN:-default-agent-token-change-me}"
AGENT_ID="${AGENT_ID:-$(hostname)-$(cat /proc/sys/kernel/random/uuid 2>/dev/null | cut -d'-' -f1 || echo $$)}"
HEARTBEAT_INTERVAL="${HEARTBEAT_INTERVAL:-60}"
SCAN_INTERVAL="${SCAN_INTERVAL:-300}"
COLLECTORS="${COLLECTORS:-trivy}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

AGENT_DIR="/opt/agent"
DATA_DIR="${AGENT_DIR}/data"
LOG_FILE="${AGENT_DIR}/logs/agent.log"

# ========================================
# 유틸리티 함수
# ========================================
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }

# API 호출 함수
api_call() {
    local action="$1"
    local data="$2"
    local method="${3:-POST}"
    
    local url="${CENTRAL_API_URL}?action=${action}"
    
    if [ "${method}" = "GET" ]; then
        curl -sf -X GET \
            -H "X-Agent-Token: ${AGENT_TOKEN}" \
            -H "Content-Type: application/json" \
            "${url}&${data}" 2>/dev/null
    else
        curl -sf -X POST \
            -H "X-Agent-Token: ${AGENT_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "${data}" \
            "${url}" 2>/dev/null
    fi
}

# 시스템 정보 수집
get_system_info() {
    local hostname=$(hostname)
    local os_info=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || uname -a)
    local ip_address=$(hostname -i 2>/dev/null | awk '{print $1}' || echo "unknown")
    
    echo "{\"hostname\":\"${hostname}\",\"os_info\":\"${os_info}\",\"ip_address\":\"${ip_address}\"}"
}

# ========================================
# 에이전트 등록
# ========================================
register_agent() {
    log_info "Registering agent: ${AGENT_ID}"
    
    local sys_info=$(get_system_info)
    local hostname=$(echo "$sys_info" | jq -r '.hostname')
    local os_info=$(echo "$sys_info" | jq -r '.os_info')
    local ip_address=$(echo "$sys_info" | jq -r '.ip_address')
    
    local data=$(cat <<EOF
{
    "agent_id": "${AGENT_ID}",
    "hostname": "${hostname}",
    "ip_address": "${ip_address}",
    "os_info": "${os_info}",
    "version": "1.0.0",
    "config": {
        "collectors": "${COLLECTORS}",
        "heartbeat_interval": ${HEARTBEAT_INTERVAL},
        "scan_interval": ${SCAN_INTERVAL}
    }
}
EOF
)
    
    local response=$(api_call "register" "${data}")
    
    if echo "$response" | jq -e '.success' > /dev/null 2>&1; then
        log_info "Agent registered successfully"
        
        # 대기 명령 처리
        local commands=$(echo "$response" | jq -c '.data.pending_commands // []')
        process_commands "$commands"
        return 0
    else
        log_error "Failed to register agent: $response"
        return 1
    fi
}

# ========================================
# 하트비트
# ========================================
send_heartbeat() {
    local data="{\"agent_id\": \"${AGENT_ID}\"}"
    local response=$(api_call "heartbeat" "${data}")
    
    if echo "$response" | jq -e '.success' > /dev/null 2>&1; then
        # 대기 명령 처리
        local commands=$(echo "$response" | jq -c '.data.commands // []')
        process_commands "$commands"
        return 0
    else
        log_warn "Heartbeat failed: $response"
        return 1
    fi
}

# ========================================
# 명령 처리
# ========================================
process_commands() {
    local commands="$1"
    
    if [ -z "$commands" ] || [ "$commands" = "[]" ] || [ "$commands" = "null" ]; then
        return 0
    fi
    
    echo "$commands" | jq -c '.[]' | while read -r cmd; do
        local cmd_id=$(echo "$cmd" | jq -r '.id')
        local cmd_type=$(echo "$cmd" | jq -r '.command_type')
        local cmd_data=$(echo "$cmd" | jq -c '.command_data // {}')
        
        log_info "Processing command: ${cmd_type} (ID: ${cmd_id})"
        
        local result=""
        local status="completed"
        
        case "$cmd_type" in
            "scan_image")
                local image=$(echo "$cmd_data" | jq -r '.image // ""')
                if [ -n "$image" ]; then
                    result=$(run_trivy_scan "$image")
                else
                    result="No image specified"
                    status="failed"
                fi
                ;;
            "scan_all")
                run_all_scans
                result="Scan completed"
                ;;
            "collect")
                local collector=$(echo "$cmd_data" | jq -r '.collector // ""')
                run_collector "$collector"
                result="Collection completed"
                ;;
            *)
                log_warn "Unknown command type: ${cmd_type}"
                result="Unknown command"
                status="failed"
                ;;
        esac
        
        # 결과 보고
        report_command_result "$cmd_id" "$status" "$result"
    done
}

report_command_result() {
    local cmd_id="$1"
    local status="$2"
    local result="$3"

    local data=$(cat <<EOF
{
    "command_id": ${cmd_id},
    "status": "${status}",
    "result": "${result}"
}
EOF
)
    api_call "command_result" "${data}"
}

# ========================================
# Trivy 스캔
# ========================================
run_trivy_scan() {
    local image="$1"
    log_info "Scanning image: ${image}"

    local result=$(trivy image --format json --security-checks vuln,config "${image}" 2>/dev/null)

    if [ -n "$result" ]; then
        # 결과 전송
        local data=$(cat <<EOF
{
    "agent_id": "${AGENT_ID}",
    "data_type": "trivy_scan",
    "data": [{"image": "${image}", "result": ${result}}]
}
EOF
)
        api_call "report" "${data}"
        log_info "Scan result reported for: ${image}"
        echo "success"
    else
        log_error "Scan failed for: ${image}"
        echo "failed"
    fi
}

run_all_scans() {
    log_info "Running scan on all containers..."

    # 실행 중인 컨테이너 이미지 목록
    local images=$(docker ps --format '{{.Image}}' 2>/dev/null | sort -u)

    for image in $images; do
        run_trivy_scan "$image"
        sleep 2  # Rate limiting
    done
}

# ========================================
# Collector 실행
# ========================================
run_collector() {
    local collector="$1"
    local collector_script="${AGENT_DIR}/collectors/${collector}.sh"

    if [ -x "$collector_script" ]; then
        log_info "Running collector: ${collector}"
        local result=$("$collector_script")

        if [ -n "$result" ]; then
            local data=$(cat <<EOF
{
    "agent_id": "${AGENT_ID}",
    "data_type": "${collector}",
    "data": ${result}
}
EOF
)
            api_call "report" "${data}"
        fi
    else
        log_warn "Collector not found: ${collector}"
    fi
}

run_all_collectors() {
    IFS=',' read -ra cols <<< "$COLLECTORS"
    for collector in "${cols[@]}"; do
        collector=$(echo "$collector" | xargs)  # trim
        if [ "$collector" = "trivy" ]; then
            run_all_scans
        else
            run_collector "$collector"
        fi
    done
}

# ========================================
# Docker 이벤트 감시
# ========================================
watch_docker_events() {
    log_info "Watching Docker events..."

    docker events --filter 'event=start' --filter 'type=container' --format '{{.Actor.Attributes.image}}' 2>/dev/null | while read -r image; do
        if [ -n "$image" ]; then
            log_info "Container started: ${image}"
            sleep 5  # 컨테이너 안정화 대기
            run_trivy_scan "$image"
        fi
    done
}

# ========================================
# 메인 루프
# ========================================
main() {
    log_info "=========================================="
    log_info "Trivy Agent Starting..."
    log_info "Agent ID: ${AGENT_ID}"
    log_info "Central API: ${CENTRAL_API_URL}"
    log_info "Collectors: ${COLLECTORS}"
    log_info "=========================================="

    # 에이전트 등록 (재시도)
    local retry=0
    while ! register_agent; do
        retry=$((retry + 1))
        if [ $retry -ge 10 ]; then
            log_error "Failed to register after 10 attempts. Exiting."
            exit 1
        fi
        log_warn "Registration failed. Retrying in 30s... (${retry}/10)"
        sleep 30
    done

    # Docker 이벤트 감시 (백그라운드)
    watch_docker_events &
    DOCKER_WATCH_PID=$!

    # 주기적 스캔 타이머
    local last_scan=0

    # 메인 루프
    while true; do
        # 하트비트
        send_heartbeat

        # 주기적 스캔
        local now=$(date +%s)
        if [ $((now - last_scan)) -ge ${SCAN_INTERVAL} ]; then
            log_info "Running periodic scan..."
            run_all_collectors
            last_scan=$now
        fi

        sleep ${HEARTBEAT_INTERVAL}
    done
}

# 종료 핸들러
cleanup() {
    log_info "Agent shutting down..."
    [ -n "$DOCKER_WATCH_PID" ] && kill $DOCKER_WATCH_PID 2>/dev/null
    exit 0
}

trap cleanup SIGTERM SIGINT

main

