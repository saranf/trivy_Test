# Trivy Security Scanner 배포 가이드

---

## 📋 별도 서버 배포 체크리스트

### ✅ Step 1: 사전 요구사항

```bash
# Docker 설치
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# 재로그인 필요

# Docker Compose 설치
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

---

### ✅ Step 2: 프로젝트 복사

```bash
# 방법 1: SCP로 전송 (로컬에서 실행)
scp -r ./trivy_Test user@서버IP:/home/user/

# 방법 2: Git 사용
git clone <repository-url>
cd trivy_Test
```

---

### ✅ Step 3: 설정 파일 수정

```bash
vi docker-compose.yml
```

**수정할 항목 (30~32행):**
```yaml
- SMTP_USER=본인네이버아이디@naver.com
- SMTP_PASS=본인비밀번호
- FROM_EMAIL=본인네이버아이디@naver.com  # ⚠️ SMTP_USER와 동일해야 함!
```

**Grafana 비밀번호 변경 (선택, 80행):**
```yaml
- GF_SECURITY_ADMIN_PASSWORD=원하는비밀번호
```

---

### ✅ Step 4: 권한 설정

```bash
chmod +x webserver/entrypoint.sh
chmod +x auto_scan/auto_scan_daemon.sh
```

---

### ✅ Step 5: 실행

```bash
docker-compose up -d --build
```

---

### ✅ Step 6: 방화벽 설정

```bash
# Ubuntu/Debian
sudo ufw allow 6987/tcp   # Trivy Web UI
sudo ufw allow 3000/tcp   # Grafana
# 아래는 내부용이면 생략 가능
sudo ufw allow 9090/tcp   # Prometheus
sudo ufw allow 8080/tcp   # cAdvisor
```

---

## 🌐 접속 URL

| 서비스 | 포트 | URL | 계정 |
|--------|------|-----|------|
| **Trivy Web** | 6987 | http://monitor.rmstudio.co.kr:6987 | - |
| **Grafana** | 3000 | http://monitor.rmstudio.co.kr:3000 | admin / admin123 |
| **Prometheus** | 9090 | http://monitor.rmstudio.co.kr:9090 | - |
| **cAdvisor** | 8080 | http://monitor.rmstudio.co.kr:8080 | - |

---

## 📊 Grafana 사용법

### 대시보드 접속
1. http://서버IP:3000 접속
2. 로그인: `admin` / `admin123` (또는 설정한 비밀번호)
3. 좌측 메뉴 → **Dashboards** → **Trivy Security Scanner**

### 컨테이너/이미지 필터
대시보드 상단에서 선택 가능:
- **Container**: 모니터링할 컨테이너 선택 (전체/개별)
- **Image**: 취약점 볼 이미지 선택 (전체/개별)

### 웹 UI에서 Grafana 연결
- **index.php**: 전체 대시보드 링크
- **container_scan.php**: 스캔 후 해당 컨테이너 Grafana 링크 표시

---

## 🔧 문제 해결

### 이메일 발송 실패
```bash
# 확인사항
# 1. SMTP_USER와 FROM_EMAIL이 동일한지
# 2. 네이버 메일 설정 > POP3/SMTP 사용 허용
```

### 자동 스캔 안됨
```bash
# Docker 소켓 권한 확인
ls -la /var/run/docker.sock

# auto_scan 로그 확인
docker logs trivy_test_auto_scan_1
```

### Grafana 데이터 없음
```bash
# Prometheus 타겟 확인
curl http://localhost:9090/api/v1/targets

# metrics.php 확인
curl http://localhost:6987/metrics.php
```

### 로그 확인
```bash
docker-compose logs -f              # 전체
docker logs -f trivy_test_nginx_1   # 개별
```

