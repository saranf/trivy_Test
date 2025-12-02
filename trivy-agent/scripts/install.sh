#!/bin/bash
# 🚀 Trivy Agent 설치 스크립트
#
# 사용법:
#   curl -sSL https://your-server.com/install-agent.sh | bash -s -- \
#     --api-url https://your-server.com/api/agent.php \
#     --token your-agent-token
#
# 또는:
#   ./install.sh --api-url https://... --token xxx

set -e

# 기본값
CENTRAL_API_URL=""
AGENT_TOKEN=""
AGENT_ID=""
COLLECTORS="trivy,system,docker"
INSTALL_DIR="/opt/trivy-agent"
USE_DOCKER=true

# 색상
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 인자 파싱
while [[ $# -gt 0 ]]; do
    case $1 in
        --api-url)
            CENTRAL_API_URL="$2"
            shift 2
            ;;
        --token)
            AGENT_TOKEN="$2"
            shift 2
            ;;
        --agent-id)
            AGENT_ID="$2"
            shift 2
            ;;
        --collectors)
            COLLECTORS="$2"
            shift 2
            ;;
        --no-docker)
            USE_DOCKER=false
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# 필수 인자 확인
if [ -z "$CENTRAL_API_URL" ]; then
    log_error "--api-url is required"
    echo "Usage: $0 --api-url <URL> --token <TOKEN>"
    exit 1
fi

if [ -z "$AGENT_TOKEN" ]; then
    log_error "--token is required"
    exit 1
fi

# Agent ID 생성
if [ -z "$AGENT_ID" ]; then
    AGENT_ID="$(hostname)-$(cat /proc/sys/kernel/random/uuid 2>/dev/null | cut -d'-' -f1 || date +%s)"
fi

log_info "=========================================="
log_info "Trivy Agent Installer"
log_info "=========================================="
log_info "Central API: ${CENTRAL_API_URL}"
log_info "Agent ID: ${AGENT_ID}"
log_info "Collectors: ${COLLECTORS}"
log_info "=========================================="

if [ "$USE_DOCKER" = true ]; then
    # Docker 설치 확인
    if ! command -v docker &> /dev/null; then
        log_error "Docker is required but not installed"
        exit 1
    fi

    log_info "Installing Trivy Agent using Docker..."

    # 기존 컨테이너 제거
    docker rm -f trivy-agent 2>/dev/null || true

    # 컨테이너 실행
    docker run -d \
        --name trivy-agent \
        --restart unless-stopped \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -e CENTRAL_API_URL="${CENTRAL_API_URL}" \
        -e AGENT_TOKEN="${AGENT_TOKEN}" \
        -e AGENT_ID="${AGENT_ID}" \
        -e COLLECTORS="${COLLECTORS}" \
        -e HEARTBEAT_INTERVAL=60 \
        -e SCAN_INTERVAL=300 \
        trivy-agent:latest

    log_info "Trivy Agent installed successfully!"
    log_info "View logs: docker logs -f trivy-agent"
else
    log_info "Installing Trivy Agent natively..."
    
    # 디렉토리 생성
    mkdir -p "${INSTALL_DIR}/collectors" "${INSTALL_DIR}/logs" "${INSTALL_DIR}/data"
    
    # 스크립트 다운로드 (실제 서버에서 가져오거나 로컬 복사)
    log_warn "Native installation requires manual script copy"
    log_info "Copy agent.sh and collectors/*.sh to ${INSTALL_DIR}"
    
    # systemd 서비스 생성
    cat > /etc/systemd/system/trivy-agent.service << EOF
[Unit]
Description=Trivy Security Agent
After=network.target docker.service

[Service]
Type=simple
Environment="CENTRAL_API_URL=${CENTRAL_API_URL}"
Environment="AGENT_TOKEN=${AGENT_TOKEN}"
Environment="AGENT_ID=${AGENT_ID}"
Environment="COLLECTORS=${COLLECTORS}"
ExecStart=${INSTALL_DIR}/agent.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable trivy-agent
    systemctl start trivy-agent

    log_info "Trivy Agent service installed!"
    log_info "Check status: systemctl status trivy-agent"
fi

log_info "=========================================="
log_info "Installation complete!"
log_info "=========================================="

