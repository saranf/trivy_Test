# Container Security Operations Platform

## 📋 시스템 개요

**Project Name**: Automated Container Security Operations Platform  
**Core Objective**: Docker 환경의 보안 위협을 실시간 탐지하고, 운영 효율성을 극대화하며, 사용자 행위 감사(Audit)를 통해 내부 통제를 강화

---

## 🔐 계정 정보

### 기본 관리자 계정
| 항목 | 값 |
|------|-----|
| **Username** | `admin` |
| **Password** | `admin123` |
| **Role** | Admin |

### RBAC (Role-Based Access Control) - 3-Tier 구조

| Tier | Role | 권한 |
|------|------|------|
| **Tier 1** | Viewer | Dashboard 조회, 스캔 기록 열람, 이메일 리포트 수신 |
| **Tier 2** | Operator | Viewer + 수동 스캔, Diff 분석, 예외 처리 관리 |
| **Tier 3** | Admin | Operator + 사용자 관리, 감사 로그 조회, 시스템 설정 |

---

## 🌐 주요 URL

| 기능 | URL | 최소 권한 |
|------|-----|----------|
| 로그인 | `/login.php` | - |
| 메인 대시보드 | `/index.php` | Viewer |
| 스캔 기록 | `/scan_history.php` | Viewer |
| 컨테이너 스캔 | `/container_scan.php` | Operator |
| 예외 처리 관리 | `/exceptions.php` | Operator |
| Diff 리포트 | `/send_diff_report.php` | Operator |
| 사용자 관리 | `/users.php` | Admin |
| 감사 로그 | `/audit_logs.php` | Admin |
| Grafana Dashboard | `:3000/d/trivy-security/` | - |
| Prometheus Metrics | `/metrics.php` | - |

---

## ⚙️ 주요 기능

### 1. 지능형 리포팅 (Diff 기반)
- **이전 스캔 vs 현재 스캔** 자동 비교
- **분류**:
  - `NEW`: 신규 발견 취약점 (가장 중요)
  - `FIXED`: 조치 완료 취약점
  - `PERSISTENT`: 잔존 취약점
  - `EXCEPTED`: 예외 처리된 취약점
- **이메일 제목 예시**: `[보안알림] nginx - 신규 3건 (Critical 1건) / 조치 5건`
- **첨부**: 전체 내역 CSV

### 2. 예외 처리 시스템 (Risk Acceptance)
- 오탐/비즈니스 사유로 취약점 예외 처리
- 만료일 필수 지정 (직접 선택)
- 만료 후 자동 재표시
- CSV, Diff 리포트, Grafana에 반영

### 3. 이벤트 기반 자동화
- Docker Socket 모니터링 (`/var/run/docker.sock`)
- 컨테이너 Start/Restart 감지 → 자동 Trivy 스캔
- Critical 발견 시 즉시 이메일 알림 (환경변수 설정)

### 4. 계층형 Grafana 대시보드
- 전체 취약점 현황, 심각도별 분포
- 예외 처리 통계 (Active/Expired)
- 컨테이너별 상세 필터링

---

## 🔍 감사 로그 (Audit Log)

모든 중요 행위가 자동 기록됩니다:

| Action | 설명 |
|--------|------|
| `LOGIN` | 로그인 |
| `LOGOUT` | 로그아웃 |
| `MANUAL_SCAN` | 수동 스캔 |
| `BULK_SCAN` | 일괄 스캔 |
| `ADD_EXCEPTION` | 예외 처리 등록 |
| `DELETE_EXCEPTION` | 예외 처리 삭제 |
| `DELETE_SCAN` | 스캔 기록 삭제 |
| `SEND_DIFF_REPORT` | Diff 리포트 발송 |
| `CREATE_USER` | 사용자 생성 |
| `UPDATE_USER_ROLE` | 역할 변경 |
| `DELETE_USER` | 사용자 삭제 |

---

## 📁 파일 구조

```
trivy_Test/
├── docker-compose.yml        # 전체 서비스 구성
├── webserver/
│   └── src/
│       ├── index.php         # 메인 페이지
│       ├── login.php         # 로그인
│       ├── logout.php        # 로그아웃
│       ├── auth.php          # 인증 헬퍼
│       ├── db_functions.php  # DB 함수
│       ├── container_scan.php    # 수동 스캔
│       ├── scan_history.php      # 스캔 기록
│       ├── exceptions.php        # 예외 관리
│       ├── exception_api.php     # 예외 API
│       ├── send_diff_report.php  # Diff 리포트
│       ├── auto_scan.php         # 자동 스캔 API
│       ├── users.php             # 사용자 관리
│       ├── audit_logs.php        # 감사 로그
│       └── metrics.php           # Prometheus 메트릭
├── grafana/
│   └── provisioning/
│       └── dashboards/
│           └── trivy-dashboard.json
├── prometheus/
│   └── prometheus.yml
└── auto_scan/
    └── auto_scan_daemon.sh   # Docker 이벤트 감시
```

---

## 🚀 실행 방법

```bash
# 시작
docker-compose up -d --build

# 중지
docker-compose down

# Grafana 초기화 후 재시작
docker-compose down
docker volume rm trivy_test_grafana_data
docker-compose up -d --build
```

---

## 📧 환경변수 설정 (docker-compose.yml)

```yaml
environment:
  - ALERT_EMAIL=admin@example.com    # Critical 알림 수신
  - ALERT_ON_CRITICAL=true           # Critical 알림 활성화
  - FROM_EMAIL=trivy@example.com     # 발신 이메일
  - FROM_NAME=Trivy Scanner          # 발신자명
```

---

## 📊 CSV 출력 형식

스캔 기록 CSV 다운로드 시 예외 처리 정보 포함:

| Column | 설명 |
|--------|------|
| Library | 라이브러리명 |
| Vulnerability ID | CVE ID |
| Severity | 심각도 |
| Installed Version | 설치 버전 |
| Fixed Version | 수정 버전 |
| Title | 취약점 제목 |
| Exception Status | 예외 상태 (EXCEPTED 또는 공백) |
| Exception Reason | 예외 사유 |
| Exception Expires | 예외 만료일 |

