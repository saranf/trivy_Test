#!/bin/bash
# Docker 컨테이너 시작 이벤트 감시 및 자동 스캔
# 호스트에서 실행: ./auto_scan_daemon.sh
#
# 주의: webserver 컨테이너 내부에서 trivy 스캔 실행

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/auto_scan.log"
CONTAINER_NAME="trivy_test_webserver_1"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting Docker container auto-scan daemon..."
log "Log file: $LOG_FILE"

# Docker 이벤트 감시 (컨테이너 시작 이벤트만)
docker events --filter 'event=start' --filter 'type=container' --format '{{.Actor.Attributes.image}}' | while read IMAGE; do
    if [ -n "$IMAGE" ]; then
        log "Container started with image: $IMAGE"

        # 5초 대기 (컨테이너가 완전히 시작될 때까지)
        sleep 5

        # webserver 컨테이너 내부에서 PHP 스크립트 직접 실행
        RESPONSE=$(docker exec $CONTAINER_NAME php -r "
            require_once '/var/www/html/db_functions.php';

            \$image = '${IMAGE}';
            \$conn = getDbConnection();
            if (!\$conn) { echo json_encode(['success'=>false,'message'=>'DB error']); exit; }

            initDatabase(\$conn);

            // Trivy 스캔
            \$cmd = 'trivy image --no-progress --severity HIGH,CRITICAL --format json ' . escapeshellarg(\$image) . ' 2>/dev/null';
            exec(\$cmd, \$output);
            \$data = json_decode(implode('', \$output), true);

            if (\$data) {
                \$scanId = saveScanResult(\$conn, \$image, \$data);
                echo json_encode(['success'=>true,'scanId'=>\$scanId,'image'=>\$image]);
            } else {
                echo json_encode(['success'=>false,'message'=>'Scan failed']);
            }
        ")

        log "Scan result: $RESPONSE"
    fi
done

