#!/bin/bash
# 🐳 Docker Collector - Docker 정보 수집
# 수집 항목: 컨테이너, 이미지, 볼륨, 네트워크

# Docker 사용 가능 여부
if ! docker info &> /dev/null; then
    echo '{"error": "Docker not available", "collected_at": "'$(date -Iseconds)'"}'
    exit 0
fi

# Docker 버전
docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")

# 실행 중인 컨테이너
running_containers=$(docker ps --format json 2>/dev/null | jq -s '.' || echo "[]")

# 모든 컨테이너 (중지된 것 포함)
all_containers=$(docker ps -a --format json 2>/dev/null | jq -s '.' || echo "[]")

# 이미지 목록
images=$(docker images --format json 2>/dev/null | jq -s '.' || echo "[]")

# 볼륨 목록
volumes=$(docker volume ls --format json 2>/dev/null | jq -s '.' || echo "[]")

# 네트워크 목록
networks=$(docker network ls --format json 2>/dev/null | jq -s '.' || echo "[]")

# 요약 통계
container_count=$(docker ps -q 2>/dev/null | wc -l)
image_count=$(docker images -q 2>/dev/null | wc -l)
volume_count=$(docker volume ls -q 2>/dev/null | wc -l)

cat <<EOF
{
    "docker_version": "${docker_version}",
    "summary": {
        "running_containers": ${container_count},
        "total_images": ${image_count},
        "total_volumes": ${volume_count}
    },
    "running_containers": ${running_containers},
    "all_containers": ${all_containers},
    "images": ${images},
    "volumes": ${volumes},
    "networks": ${networks},
    "collected_at": "$(date -Iseconds)"
}
EOF

