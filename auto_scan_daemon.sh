#!/bin/bash
# Docker 컨테이너 시작 이벤트 감시 및 자동 스캔
# 사용법: ./auto_scan_daemon.sh

API_URL="http://localhost:6987/auto_scan.php"
LOG_FILE="/var/log/trivy_auto_scan.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting Docker container auto-scan daemon..."

# Docker 이벤트 감시 (컨테이너 시작 이벤트만)
docker events --filter 'event=start' --filter 'type=container' --format '{{.Actor.Attributes.image}}' | while read IMAGE; do
    if [ -n "$IMAGE" ]; then
        log "Container started with image: $IMAGE"
        
        # 5초 대기 (컨테이너가 완전히 시작될 때까지)
        sleep 5
        
        # 자동 스캔 API 호출
        RESPONSE=$(curl -s "${API_URL}?action=scan_image&image=${IMAGE}")
        log "Scan result: $RESPONSE"
    fi
done

