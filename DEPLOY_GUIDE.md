# Trivy Security Scanner 배포 가이드

## 1. 사전 요구사항

```bash
# Docker 설치
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Docker Compose 설치
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

## 2. 프로젝트 복사

```bash
# 서버로 파일 전송 (로컬에서 실행)
scp -r /path/to/trivy_Test user@server:/path/to/destination

# 또는 Git 사용
git clone <repository-url>
cd trivy_Test
```

## 3. 설정 파일 수정

### docker-compose.yml 수정

```bash
vi docker-compose.yml
```

**수정할 항목:**
```yaml
# 네이버 SMTP 설정 (30-32행)
- SMTP_USER=your_naver_id@naver.com      # 본인 네이버 아이디
- SMTP_PASS=your_password                 # 본인 네이버 비밀번호
- FROM_EMAIL=your_naver_id@naver.com     # SMTP_USER와 동일하게

# Grafana 비밀번호 변경 (권장)
- GF_SECURITY_ADMIN_PASSWORD=your_secure_password
```

## 4. 권한 설정

```bash
chmod +x webserver/entrypoint.sh
chmod +x auto_scan/auto_scan_daemon.sh
```

## 5. 실행

```bash
docker-compose up -d --build
```

## 6. 접속 확인

| 서비스 | 포트 | URL |
|--------|------|-----|
| Trivy 스캐너 | 6987 | http://서버IP:6987 |
| Grafana | 3000 | http://서버IP:3000 |
| Prometheus | 9090 | http://서버IP:9090 |
| cAdvisor | 8080 | http://서버IP:8080 |

## 7. Grafana 초기 설정

1. http://서버IP:3000 접속
2. 로그인: admin / (설정한 비밀번호)
3. 좌측 메뉴 → Dashboards → Browse
4. "Trivy Security Scanner" 또는 "Container Monitor" 선택

## 8. 방화벽 설정 (필요시)

```bash
# Ubuntu/Debian
sudo ufw allow 6987/tcp  # Trivy Web
sudo ufw allow 3000/tcp  # Grafana
sudo ufw allow 9090/tcp  # Prometheus (내부용이면 생략)
sudo ufw allow 8080/tcp  # cAdvisor (내부용이면 생략)
```

## 9. 로그 확인

```bash
# 전체 로그
docker-compose logs -f

# 개별 서비스
docker logs -f trivy_test_webserver_1
docker logs -f trivy_test_auto_scan_1
docker logs -f trivy_test_grafana_1
```

## 10. 문제 해결

### 이메일 발송 실패
- SMTP_USER와 FROM_EMAIL이 동일한지 확인
- 네이버 메일 설정에서 SMTP 사용 허용 확인

### 자동 스캔 안됨
- Docker 소켓 권한 확인: `ls -la /var/run/docker.sock`
- auto_scan 로그 확인: `docker logs trivy_test_auto_scan_1`

### Grafana 데이터 없음
- Prometheus 타겟 확인: http://서버IP:9090/targets
- metrics.php 접속 확인: http://서버IP:6987/metrics.php

