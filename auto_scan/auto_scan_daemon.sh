#!/bin/bash
# Docker 컨테이너 시작 이벤트 감시 및 자동 스캔 (컨테이너 버전)

API_URL="${API_URL:-http://webserver:80/auto_scan.php}"
SCHEDULED_SCAN_URL="${SCHEDULED_SCAN_URL:-http://webserver:80/run_scheduled_scans_api.php}"
LOG_FILE="/var/log/auto_scan.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting Docker container auto-scan daemon..."
log "API URL: $API_URL"
log "Scheduled Scan URL: $SCHEDULED_SCAN_URL"

# webserver가 준비될 때까지 대기
sleep 10

# 주기적 스캔 체크 (백그라운드에서 1분마다 실행)
check_scheduled_scans() {
    while true; do
        log "Checking scheduled scans..."
        RESPONSE=$(curl -s "$SCHEDULED_SCAN_URL" 2>/dev/null)
        if [ -n "$RESPONSE" ]; then
            log "Scheduled scan result: $RESPONSE"
        fi
        sleep 60
    done
}

# 백그라운드에서 주기적 스캔 체크 시작
check_scheduled_scans &

# Docker 이벤트 감시 (컨테이너 시작 이벤트만)
docker events --filter 'event=start' --filter 'type=container' --format '{{.Actor.Attributes.image}}' | while read IMAGE; do
    if [ -n "$IMAGE" ]; then
        log "Container started with image: $IMAGE"

        # 5초 대기 (컨테이너가 완전히 시작될 때까지)
        sleep 5

        # 자동 스캔 API 호출
        RESPONSE=$(curl -s "${API_URL}?action=scan_image&image=$(echo $IMAGE | sed 's/ /%20/g')")
        log "Scan result: $RESPONSE"
    fi
done

