# Trivy CSOP — 컨테이너 보안 운영 플랫폼

> 🇺🇸 **English: [README.md](README.md)**

[Trivy](https://github.com/aquasecurity/trivy) 기반의 **셀프호스팅 컨테이너 보안 운영 플랫폼(Container Security Operations Platform)** 입니다. 컨테이너 이미지와 인프라의 취약점·설정 오류를 상시 스캔하고, 원격 호스트에 배포하는 경량 **에이전트(자빅스 스타일)** 를 중앙에서 관리하며, 관측성 스택(Prometheus + Grafana + Loki)과 이메일/Slack 알림, AI 조치 가이드까지 하나로 묶었습니다.

모든 구성 요소는 하나의 `docker-compose.yml` 로 실행됩니다.

---

## 목차

- [아키텍처](#아키텍처)
- [기능 개요](#기능-개요)
- [구성 요소](#구성-요소)
- [에이전트 시스템](#에이전트-시스템)
- [빠른 시작](#빠른-시작)
- [접속 정보 및 계정](#접속-정보-및-계정)
- [기술 스택](#기술-스택)
- [보안 주의사항](#보안-주의사항)

---

## 아키텍처

```
                        ┌─────────────────────────────────────────────┐
   원격 호스트           │                중앙 서버                     │
   ┌───────────┐        │                                             │
   │ 에이전트 A │──push──▶│  nginx :6987 ──▶ PHP-FPM (webserver)        │
   │ 에이전트 B │  HTTP   │        │              │                     │
   │ 에이전트 C │ +토큰   │        │              ▼                     │
   └───────────┘        │        │           MySQL (trivy_db)         │
                        │        │                                    │
   Docker 이벤트         │   trivy-agent :8888 (로컬 스캔 마이크로서비스)│
   ┌───────────┐        │   auto_scan 데몬 (이벤트/스케줄 트리거)       │
   │ auto_scan │────────▶│                                            │
   └───────────┘        └───────────────┬─────────────────────────────┘
                                        │  /metrics.php, 컨테이너 로그
                                        ▼
                        Prometheus + cAdvisor ─▶ Grafana ◀─ Loki ◀─ Promtail
                                        │
                                        ▼
                        알림: 이메일(Postfix) · Slack · Google Sheets · Gemini AI
```

**흐름:** 에이전트/스캐너가 Trivy 실행 → 결과를 PHP 앱이 MySQL에 저장 → 앱이 메트릭/로그 노출 → 모니터링 스택이 시각화 → Critical/High 발견 시 알림 발송.

---

## 기능 개요

### 스캔
- **이미지 취약점 스캔** — Trivy `--security-checks vuln,config,secret` (v0.29.2).
- **설정 오류 / IaC 스캔** — Dockerfile, Kubernetes, Terraform 컴플라이언스 점검.
- **시크릿 탐지** — 이미지에 포함된 자격증명 검출.
- **SBOM 내보내기** — CycloneDX, SPDX / SPDX-JSON.
- **3가지 스캔 트리거:** 수동(UI/API), **스케줄**(5분마다 cron), **이벤트 기반**(컨테이너 start/restart 시 자동).

### 리포팅 & 인텔리전스
- **Diff 기반 리포트** — 스캔 간 발견 항목을 `NEW` / `FIXED` / `PERSISTENT` / `EXCEPTED` 로 분류.
- **MTTR 지표** — 취약점 수명주기 테이블로 평균 조치 소요시간 추적.
- **CISA KEV 연동** — 실제 악용 알려진 취약점(Known-Exploited)을 우선순위 표시.
- **Gemini AI 조치 가이드** — CVE별 AI 수정 가이드 생성, DB 캐싱.
- **일일 리포트** — 어제 대비 오늘 비교 결과를 Slack·Google Sheets로 전송.
- **Prometheus 메트릭** — 스캔 KPI를 `/metrics.php` 로 노출.

### 위험 관리
- **예외 / 위험 수용 관리** — 특정 CVE를 사유·만료일과 함께 예외 처리.
- **RBAC** — 4단계: `viewer` < `demo` < `operator` < `admin`, 역할별/사용자별 세분화 권한.
- **감사 로그** — 모든 파괴적·권한 작업 기록.
- **데모 모드** — 데이터 마스킹, 저장 시뮬레이션, 매일 자정(KST) 초기화.

### 관측성
- **Grafana 대시보드** — Trivy 메트릭, Loki 로그, 보안 로그, Falco 런타임.
- **Loki + Promtail** — 컨테이너 로그 중앙 집계 (7일 보관).
- **cAdvisor** — 컨테이너별 CPU/메모리/네트워크 메트릭.
- **Falco** *(선택, Linux 전용)* — 런타임 시스템콜 위협 탐지 → Loki.

### 알림
- **이메일** — Postfix 메일 컨테이너(msmtp).
- **Slack** — 다중 웹훅 지원, `ALERT_ON_CRITICAL` / `ALERT_THRESHOLD` 기준.
- **Google Sheets** — 일일 리포트 동기화.

---

## 구성 요소

| 서비스 | 이미지 | 포트 | 역할 |
|---|---|---|---|
| **nginx** | `nginx:latest` | `6987:80` | 리버스 프록시 / 웹 UI 진입점 |
| **webserver** | 커스텀 PHP 8-FPM | `9555:9000` | 핵심 앱: 스캔·리포트·RBAC·API |
| **mysql** | `mysql:8.0` | `9756:3306` | 데이터베이스 (`trivy_db`) |
| **trivy-agent** | `./trivy-agent` | 내부 `8888` | 로컬 스캔 마이크로서비스 (HTTP API) |
| **auto_scan** | `./auto_scan` | — | Docker 이벤트·스케줄 스캔 트리거 |
| **prometheus** | `prom/prometheus` | `9090` | 메트릭 TSDB |
| **grafana** | `grafana/grafana` | `3000` | 대시보드 |
| **cadvisor** | `cadvisor` | `8080` | 컨테이너 리소스 메트릭 |
| **loki** | `grafana/loki:2.9.0` | `3100` | 로그 저장소 |
| **promtail** | `grafana/promtail:2.9.0` | — | 로그 수집기 |
| **mailserver** | `boky/postfix` | — | 이메일 알림용 SMTP 릴레이 |
| **falco** *(비활성)* | `falcosecurity/falco` | — | 런타임 위협 탐지 (Linux 전용) |

모든 서비스는 `app-network` 브리지와 `Asia/Seoul` 타임존을 공유합니다. 영속 볼륨: `mysql_data`, `prometheus_data`, `grafana_data`, `loki_data`.

---

## 에이전트 시스템

이 플랫폼은 원격 호스트에 배포해 스캔·텔레메트리를 수집하는 **분산 에이전트**를 제공합니다. 자빅스 에이전트와 비슷하지만, 컨테이너 보안에 특화되어 있습니다.

### 두 가지 구현
- **`agent.sh`** (셸, 풀 기능) — 기본 에이전트. 중앙 서버에 등록, 하트비트 전송, Trivy 스캔 스케줄 실행, Docker 이벤트 감시, 서버가 내려보낸 명령 실행.
- **`simple_agent.py`** (파이썬, 표준 라이브러리만) — 최소 호스트용 경량 시스템 정보 리포터 (Trivy 미포함).

### 동작 모드 (`MODE` 환경변수)
- `api` — `:8888` 에 HTTP 스캔 API만 노출 (Pull 방식).
- `push` — 등록 + 하트비트 + 스캔/텔레메트리를 중앙 서버로 전송 (Push 방식).
- `both` — 둘 다.

### 동작 방식 (push 모드)
1. **등록** → `X-Agent-Token` 헤더로 `POST ?action=register`; 에이전트가 온라인 표시됨.
2. **하트비트** `HEARTBEAT_INTERVAL`(기본 60초)마다 전송; 서버가 대기 명령을 함께 전달.
3. **스케줄 스캔** `SCAN_INTERVAL`(기본 300초)마다 실행 중인 모든 컨테이너 이미지를 Trivy 스캔.
4. **이벤트 기반 스캔** — `docker events` 를 추적해 새로 시작된 이미지를 스캔.
5. **명령** — 서버가 `scan_image`, `scan_all`, `collect` 를 내려보낼 수 있고, 결과를 회신.

### 컬렉터 (플러그형, JSON 출력)
`system` · `docker` · `processes` · `network` · `iptables` — 그리고 `trivy` 스캔 컬렉터. 커스텀 컬렉터는 stdout으로 JSON만 출력하면 됩니다.

### HTTP API (`api_server.py`, `:8888` 에서 Flask + gunicorn)
`/health` 외 모든 경로는 `X-Agent-Token` 헤더 필요.

| 메서드 | 경로 | 용도 |
|---|---|---|
| GET | `/health` | 생존 확인 + 에이전트 ID |
| POST | `/scan/image` | Trivy 취약점+설정 스캔 (HIGH/CRITICAL) |
| POST | `/scan/sbom` | SBOM (CycloneDX / SPDX) |
| POST | `/scan/config` | 설정 오류 스캔 |
| GET | `/docker/images` | 이미지 목록 |
| GET | `/docker/containers` | 컨테이너 목록 |

### 원격 호스트 설치
```bash
# Docker (권장) — 호스트 컨테이너 스캔을 위해 docker.sock 마운트
./trivy-agent/scripts/install.sh \
  --api-url https://your-server:6987/api/agent.php \
  --token   YOUR_AGENT_TOKEN \
  --collectors trivy,system,docker

# 네이티브(systemd) 대안
./trivy-agent/scripts/install.sh --api-url ... --token ... --no-docker
```

에이전트 전체 레퍼런스(커스텀 컬렉터, 자산 태깅, 명령 흐름, 보안 강화)는 **[AGENT_GUIDE.md](AGENT_GUIDE.md)** 참고.

---

## 빠른 시작

```bash
# 1. 사전 준비: Docker + Docker Compose 설치
# 2. docker-compose.yml 에서 알림 환경변수 설정 (SMTP, Slack 등)
# 3. 스크립트 실행 권한 부여
chmod +x webserver/entrypoint.sh auto_scan/auto_scan_daemon.sh

# 4. 실행
docker-compose up -d --build
```

방화벽에서 **6987**(웹 UI), **3000**(Grafana) 포트를 열고, 필요 시 **9090** / **8080** 도 개방.

전체 배포 절차: **[DEPLOY_GUIDE.md](DEPLOY_GUIDE.md)** · 시스템 레퍼런스: **[docs/SYSTEM_GUIDE.md](docs/SYSTEM_GUIDE.md)**

---

## 접속 정보 및 계정

| 서비스 | URL | 계정 |
|---|---|---|
| Trivy 웹 UI | `http://<host>:6987` | `admin` / `admin123` |
| 데모(읽기 전용) | 동일 | `demo` / `demo123` |
| Grafana | `http://<host>:3000` | `admin` / `admin123` |
| Prometheus | `http://<host>:9090` | — |
| cAdvisor | `http://<host>:8080` | — |

---

## 기술 스택

- **백엔드:** PHP 8 (FPM) + Nginx, MySQL 8.0
- **스캐너:** Trivy v0.29.2 (버전 고정)
- **에이전트:** Bash + Python (Flask/gunicorn), Alpine (~50 MB 이미지)
- **모니터링:** Prometheus, Grafana, Loki, Promtail, cAdvisor, Falco
- **연동:** Slack, Postfix 이메일, Google Sheets, Google Gemini AI, CISA KEV 카탈로그

---

## 보안 주의사항

본 프로젝트는 **포트폴리오 / 실습용** 입니다. 실제 배포 전 반드시 점검하세요.

- 🔴 DB 자격증명과 기본 `admin`/`demo` 비밀번호가 소스에 하드코딩되어 있습니다 — 반드시 교체.
- 🔴 기본 에이전트 토큰 `default-agent-token-change-me` 를 변경해야 합니다.
- 🟠 에이전트 HTTP API는 `shell=True` 로 명령을 실행하며 입력 검증이 최소한이므로, 네트워크 노출을 제한하고 강력한 토큰을 사용하세요.
- 🟠 Grafana는 기본적으로 익명 Viewer 접근을 허용합니다.
- 🟠 에이전트와 웹서버가 `/var/run/docker.sock` 을 마운트합니다 — 사실상 호스트 root 권한이므로 컨테이너 격리에 유의하세요.

권장 강화책(AGENT_GUIDE 참고): 토큰 정기 교체, API 앞단 TLS 종단, 에이전트 IP 화이트리스트, 최소 권한 capability + 읽기 전용 파일시스템 운영.
