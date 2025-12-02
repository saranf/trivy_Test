# 🤖 Trivy Agent - 경량 보안 스캐너 에이전트
#
# 빌드: docker build -t trivy-agent .
# 실행: docker run -d --name trivy-agent \
#         -v /var/run/docker.sock:/var/run/docker.sock \
#         -e AGENT_TOKEN=your-token \
#         -p 8888:8888 \
#         trivy-agent

FROM alpine:3.19

LABEL maintainer="Trivy Agent"
LABEL description="Lightweight security scanner agent with HTTP API"

# 필수 패키지 설치
RUN apk add --no-cache \
    bash \
    curl \
    jq \
    docker-cli \
    procps \
    iptables \
    net-tools \
    coreutils \
    util-linux \
    python3 \
    py3-pip

# Flask 설치 (경량 HTTP 서버)
RUN pip3 install --no-cache-dir --break-system-packages flask gunicorn

# Trivy 설치 (v0.29.2 - 안정 버전)
ENV TRIVY_VERSION=0.29.2
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

# 에이전트 디렉토리 구조
RUN mkdir -p /opt/agent/collectors /opt/agent/data /opt/agent/logs

# 에이전트 스크립트 복사
COPY agent.sh /opt/agent/
COPY api_server.py /opt/agent/
COPY collectors/ /opt/agent/collectors/

RUN chmod +x /opt/agent/agent.sh /opt/agent/collectors/*.sh 2>/dev/null || true

WORKDIR /opt/agent

# 환경 변수
ENV CENTRAL_API_URL=""
ENV AGENT_TOKEN=""
ENV AGENT_ID=""
ENV HEARTBEAT_INTERVAL=60
ENV SCAN_INTERVAL=300
ENV COLLECTORS="trivy"
ENV LOG_LEVEL=INFO
ENV API_PORT=8888

# HTTP API 포트
EXPOSE 8888

# 헬스체크
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8888/health || exit 1

ENTRYPOINT ["/opt/agent/agent.sh"]

