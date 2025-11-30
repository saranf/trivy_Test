#!/bin/bash
# Docker 컨테이너 시작 이벤트 감시 및 자동 스캔 (컨테이너 버전)

API_URL="${API_URL:-http://webserver:80/auto_scan.php}"
LOG_FILE="/var/log/auto_scan.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting Docker container auto-scan daemon..."
log "API URL: $API_URL"

# webserver가 준비될 때까지 대기
sleep 10

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

