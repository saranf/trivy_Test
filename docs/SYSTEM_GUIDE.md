# Container Security Operations Platform

## 📋 시스템 개요

**Project Name**: Automated Container Security Operations Platform  
**Core Objective**: Docker 환경의 보안 위협을 실시간 탐지하고, 운영 효율성을 극대화하며, 사용자 행위 감사(Audit)를 통해 내부 통제를 강화

---

## 🔐 계정 정보

### 기본 계정
| 계정 | Username | Password | Role | 용도 |
|------|----------|----------|------|------|
| **관리자** | `admin` | `admin123` | Admin | 전체 시스템 관리 |
| **면접관** | `demo` | `demo123` | Demo | 기능 체험 (읽기 전용) |

### 🎓 면접관 체험 모드 (Demo Mode)

**demo** 계정으로 로그인하면:
- ✅ 모든 기능을 안전하게 체험할 수 있음
- 🔒 실제 데이터(이미지명 등)는 마스킹되어 표시
- 💾 저장/메일 발송은 시뮬레이션 (실제 동작 안함)
- 📊 실제 스캔 실행 및 결과 확인 가능

### RBAC (Role-Based Access Control) - 4-Tier 구조

| Tier | Role | 권한 |
|------|------|------|
| **Tier 1** | Viewer | Dashboard 조회, 스캔 기록 열람 |
| **Tier 2** | Demo | Viewer + 스캔/분석 (저장/발송 시뮬레이션) |
| **Tier 3** | Operator | Demo + 실제 저장/발송, 예외 처리 관리 |
| **Tier 4** | Admin | Operator + 사용자 관리, 감사 로그 조회, 시스템 설정 |

---

## 🌐 주요 URL

| 기능 | URL | 최소 권한 |
|------|-----|----------|
| 로그인 | `/login.php` | - |
| 메인 대시보드 | `/index.php` | Viewer |
| 스캔 기록 | `/scan_history.php` | Viewer |
| 컨테이너 스캔 | `/container_scan.php` | Demo |
| **컴플라이언스 스캔** | `/config_scan.php` | Demo |
| 예외 처리 관리 | `/exceptions.php` | Demo |
| Diff 리포트 | `/send_diff_report.php` | Demo |
| **주기적 스캔 설정** | `/scheduled_scans.php` | Admin |
| 사용자 관리 | `/users.php` | Admin |
| 감사 로그 | `/audit_logs.php` | Admin |
| Grafana Dashboard | `:3000/d/trivy-security/` | - |
| Prometheus Metrics | `/metrics.php` | - |

---

## ⚙️ 주요 기능

### 1. 지능형 리포팅 (Diff 기반)
- **화면 미리보기**: 스캔 선택 시 Diff 결과를 화면에서 바로 확인
- **이전 스캔 vs 현재 스캔** 자동 비교
- **분류**:
  - `NEW`: 신규 발견 취약점 (가장 중요)
  - `FIXED`: 조치 완료 취약점
  - `PERSISTENT`: 잔존 취약점
  - `EXCEPTED`: 예외 처리된 취약점
- **이메일 발송**: 화면에서 확인 후 선택적으로 이메일 발송 가능
- **이메일 제목 예시**: `[보안알림] nginx - 신규 3건 (Critical 1건) / 조치 5건`
- **첨부**: 전체 내역 CSV

### 2. 예외 처리 시스템 (Risk Acceptance)
- 오탐/비즈니스 사유로 취약점 예외 처리
- 만료일 필수 지정 (직접 선택)
- 만료 후 자동 재표시
- **모든 곳에서 일관된 예외 처리 표시**:
  - ✅ 스캔 상세 보기: 🛡️ 예외 뱃지 + 파란색 배경
  - ✅ 실시간 스캔: 상태 컬럼에 🛡️예외 표시
  - ✅ CSV 다운로드: Exception Status/Reason/Expires 컬럼
  - ✅ Diff 리포트: EXCEPTED 분류 및 별도 테이블
  - ✅ Grafana: 예외 수 카드 + 심각도별 파이차트

### 3. 이벤트 기반 자동화
- Docker Socket 모니터링 (`/var/run/docker.sock`)
- 컨테이너 Start/Restart 감지 → 자동 Trivy 스캔
- Critical 발견 시 즉시 이메일 알림 (환경변수 설정)

### 4. 주기적 스캔 설정 (Admin 전용)
- 특정 이미지/컨테이너를 정해진 주기로 자동 스캔
- **스케줄 타입**:
  - `hourly`: 매시간 (분 지정)
  - `daily`: 매일 (시간 지정)
  - `weekly`: 매주 (요일 + 시간 지정)
- 스캔 결과는 MySQL에 자동 저장 (`scan_source = 'scheduled'`)
- 활성화/비활성화 토글 가능
- 마지막 실행 시간 및 다음 실행 시간 표시

### 5. 👮 컴플라이언스 진단 (Compliance Check)
- **전용 컴플라이언스 스캔 페이지** (`config_scan.php`)
- **이미지 스캔**: Docker 이미지 내 소프트웨어 취약점(CVE) 탐지
- **설정 스캔**: Dockerfile, Kubernetes, Terraform 등 IaC 파일 보안 설정 오류 탐지
- **주요 탐지 대상**:
  - 📋 Dockerfile: USER 미지정, 불필요한 권한, 보안 모범 사례 위반
  - ☸️ Kubernetes: privileged 모드, hostPath 마운트, securityContext 설정
  - 🏗️ Terraform/CloudFormation: 퍼블릭 버킷, 암호화 미설정, 보안 그룹 규칙
- **사용 방법**:
  1. 메인 페이지 → "👮 컴플라이언스 스캔" 클릭
  2. 스캔할 경로 입력 (예: `/var/www/html`, `/app`)
  3. 스캔 실행 → 결과 확인 및 저장
- 스캔 기록에서 `👮설정` 태그로 구분

### 6. 📊 운영 성과 지표 (KPI) - MTTR
- **MTTR (Mean Time To Remediate)**: 평균 조치 기간
- 취약점이 **최초 발견된 날(First Seen)**과 **조치 완료된 날(Fixed At)** 추적
- Grafana 대시보드에 **"평균 조치 기간: X.X일"** 표시
- **추가 지표**:
  - 조치 완료된 취약점 수
  - 현재 미조치(Open) 취약점 수
  - 예외 처리된 취약점 수
- **어필 포인트**: "보안 운영의 성과를 측정하기 위해 정량적 지표(KPI) 시스템을 도입"

### 7. 계층형 Grafana 대시보드
- **Row 1 (통계)**: Total Scans, 24h Scans, Vulns, Critical, High, Excepted, MTTR, Misconfig
- **Row 2 (분포)**: 심각도별 파이차트, 스캔 소스, 예외 심각도, 설정오류 심각도
- **Row 3 (이미지별)**: 이미지별 취약점, 이미지별 Critical, KPI Summary
- **Row 4-5 (리소스)**: 컨테이너 CPU/Memory/Network

---

## 🔍 감사 로그 (Audit Log)

모든 중요 행위가 자동 기록됩니다:

| Action | 설명 |
|--------|------|
| `LOGIN` | 로그인 |
| `LOGOUT` | 로그아웃 |
| `MANUAL_SCAN` | 수동 스캔 |
| `BULK_SCAN` | 일괄 스캔 |
| `SCHEDULED_SCAN` | 주기적 스캔 실행 |
| `ADD_SCHEDULED_SCAN` | 주기적 스캔 등록 |
| `UPDATE_SCHEDULED_SCAN` | 주기적 스캔 수정 |
| `DELETE_SCHEDULED_SCAN` | 주기적 스캔 삭제 |
| `TOGGLE_SCHEDULED_SCAN` | 주기적 스캔 활성화/비활성화 |
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
│       ├── scheduled_scans.php   # 주기적 스캔 설정 (Admin)
│       ├── run_scheduled_scans_api.php  # 주기적 스캔 실행 API
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

---

## 📈 Prometheus 메트릭

| 메트릭 | 설명 |
|--------|------|
| `trivy_total_scans` | 전체 스캔 횟수 |
| `trivy_scans_24h` | 24시간 내 스캔 횟수 |
| `trivy_vulnerabilities_total` | 전체 취약점 수 |
| `trivy_vulnerabilities_by_severity` | 심각도별 취약점 수 |
| `trivy_exceptions_active` | 활성 예외 처리 수 |
| `trivy_mttr_days` | **평균 조치 기간 (일)** |
| `trivy_vulnerabilities_fixed` | **조치 완료 취약점 수** |
| `trivy_vulnerabilities_open` | **미조치 취약점 수** |
| `trivy_misconfigurations_total` | **설정 오류 총 개수** |
| `trivy_misconfigurations_by_severity` | **심각도별 설정 오류** |
