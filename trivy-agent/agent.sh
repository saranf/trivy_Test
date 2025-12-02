#!/bin/bash
# 🤖 Trivy Agent - Main Script
# 확장 가능한 보안 스캐너 에이전트 + HTTP API 서버

# set -e 제거 - 작은 오류에도 스크립트가 종료되지 않도록

# ========================================
# 설정
# ========================================
CENTRAL_API_URL="${CENTRAL_API_URL:-}"
AGENT_TOKEN="${AGENT_TOKEN:-default-agent-token-change-me}"
# AGENT_ID는 hostname 기반으로 고정 (재시작해도 동일하게 유지)
AGENT_ID="${AGENT_ID:-$(hostname | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')}"
HEARTBEAT_INTERVAL="${HEARTBEAT_INTERVAL:-60}"
SCAN_INTERVAL="${SCAN_INTERVAL:-300}"
COLLECTORS="${COLLECTORS:-trivy}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
API_PORT="${API_PORT:-8888}"
MODE="${MODE:-api}"  # api = HTTP API 서버만, push = Central 서버에 푸시, both = 둘 다

AGENT_DIR="/opt/agent"
DATA_DIR="${AGENT_DIR}/data"
LOG_FILE="${AGENT_DIR}/logs/agent.log"

# 환경변수 내보내기 (Python에서 사용)
export AGENT_TOKEN AGENT_ID API_PORT

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
# HTTP API 서버 시작
# ========================================
start_api_server() {
    log_info "Starting HTTP API server on port ${API_PORT}..."
    cd /opt/agent

    # 기존 프로세스 종료
    pkill -f "python3 api_server.py" 2>/dev/null || true
    pkill -f "gunicorn" 2>/dev/null || true
    sleep 1

    # gunicorn으로 안정적으로 실행 (워커 2개, 타임아웃 300초)
    gunicorn -w 2 -b 0.0.0.0:${API_PORT} --timeout 300 --access-logfile - --error-logfile - api_server:app &
    API_SERVER_PID=$!
    log_info "API server started with gunicorn (PID: ${API_SERVER_PID})"
}

# ========================================
# 메인 루프
# ========================================
main() {
    log_info "=========================================="
    log_info "Trivy Agent Starting..."
    log_info "Agent ID: ${AGENT_ID}"
    log_info "Mode: ${MODE}"
    log_info "API Port: ${API_PORT}"
    log_info "Central API: ${CENTRAL_API_URL:-not configured}"
    log_info "Collectors: ${COLLECTORS}"
    log_info "=========================================="

    # HTTP API 서버 시작 (api 또는 both 모드)
    if [ "$MODE" = "api" ] || [ "$MODE" = "both" ]; then
        start_api_server
        sleep 2
    fi

    # push 또는 both 모드일 때만 Central 서버에 등록
    if [ "$MODE" = "push" ] || [ "$MODE" = "both" ]; then
        if [ -n "$CENTRAL_API_URL" ]; then
            # 에이전트 등록 (재시도)
            local retry=0
            while ! register_agent; do
                retry=$((retry + 1))
                if [ $retry -ge 10 ]; then
                    log_error "Failed to register after 10 attempts."
                    break
                fi
                log_warn "Registration failed. Retrying in 30s... (${retry}/10)"
                sleep 30
            done

            # Docker 이벤트 감시 (백그라운드)
            watch_docker_events &
            DOCKER_WATCH_PID=$!

            # 주기적 스캔 타이머
            local last_scan=0

            # 메인 루프 (푸시 모드)
            while true; do
                send_heartbeat
                local now=$(date +%s)
                if [ $((now - last_scan)) -ge ${SCAN_INTERVAL} ]; then
                    log_info "Running periodic scan..."
                    run_all_collectors
                    last_scan=$now
                fi
                sleep ${HEARTBEAT_INTERVAL}
            done
        else
            log_warn "CENTRAL_API_URL not set, push mode disabled"
        fi
    fi

    # API 모드일 때는 무한 대기
    if [ "$MODE" = "api" ]; then
        log_info "Running in API-only mode. Waiting for requests..."
        while true; do
            sleep 60
            # API 서버 헬스체크
            if ! curl -sf http://localhost:${API_PORT}/health > /dev/null 2>&1; then
                log_warn "API server not responding, restarting..."
                start_api_server
            fi
        done
    fi
}

# 종료 핸들러
cleanup() {
    log_info "Agent shutting down..."
    [ -n "$DOCKER_WATCH_PID" ] && kill $DOCKER_WATCH_PID 2>/dev/null
    [ -n "$API_SERVER_PID" ] && kill $API_SERVER_PID 2>/dev/null
    exit 0
}

trap cleanup SIGTERM SIGINT

main

