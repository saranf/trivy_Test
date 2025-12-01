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
- ⏰ **데모 환경은 매일 자정(KST)에 자동 초기화**

### 🔄 데모 환경 자동 초기화

매일 자정(00:00 KST)에 자동 실행되는 초기화 작업:

| 항목 | 동작 |
|------|------|
| 스캔 기록 | 7일 이상 된 스캔 데이터 삭제 |
| 감사 로그 | 30일 이상 된 로그 삭제 |
| 예외 처리 | 만료된 예외 처리 비활성화 |
| 스케줄 | 30일 이상 비활성 스케줄 삭제 |
| demo 계정 | 비밀번호 초기화 (demo123) |

**수동 실행** (Admin):
```bash
# 컨테이너 내부에서
php /var/www/html/reset_demo.php

# 외부에서 API 호출
curl "http://localhost:6987/reset_demo.php?key=trivy_demo_reset_2024"
```

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
| **보안 검사 & 설정 오류** | `/config_scan.php` | Demo |
| 예외 처리 관리 | `/exceptions.php` | Demo |
| Diff 리포트 | `/send_diff_report.php` | Demo |
| **주기적 스캔 설정** | `/scheduled_scans.php` | Admin |
| 사용자 관리 | `/users.php` | Admin |
| 감사 로그 | `/audit_logs.php` | Admin |
| Grafana 메트릭 대시보드 | `:3000/d/trivy-security/` | - |
| **Loki 로그 대시보드** | `:3000/d/loki-logs/` | - |
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

### 3-1. 🔐 시크릿 탐지 (Secret Detection)
- 이미지 스캔 시 하드코딩된 비밀정보 자동 탐지
- **탐지 대상**: API 키, 비밀번호, 토큰, 인증서 등
- Trivy `--security-checks secret` 옵션 활용 (v0.29.2 호환)
- 스캔 결과에 별도 섹션으로 표시

### ⚠️ Trivy 버전 호환성
- **현재 사용 버전**: Trivy v0.29.2
- **명령어 옵션**:
  - `--security-checks vuln,config,secret` (v0.29.2)
  - `--scanners vuln,misconfig,secret` (v0.50+ 신버전)
- Docker 이미지 빌드 시 Dockerfile에서 버전 고정됨

### 3-2. 📦 SBOM 다운로드 (Software Bill of Materials)
- 스캔 완료 후 SBOM 다운로드 버튼 표시
- 스캔 기록 페이지에서도 SBOM 다운로드 가능
- **지원 포맷**:
  - **CycloneDX**: `.cdx.json` (OWASP 표준)
  - **SPDX**: `.spdx.json` (Linux Foundation 표준)
- 소프트웨어 공급망 보안 및 컴플라이언스 대응

### 3-3. 📊 스캔 후 모니터링 링크
스캔 완료 시 해당 컨테이너의 Grafana 링크 표시:
- **🐳 이 컨테이너 메트릭**: CPU/Memory/Network 메트릭 대시보드
- **📋 이 컨테이너 로그**: Loki 로그 대시보드 (해당 컨테이너 필터)

### 4. 주기적 스캔 설정 (Admin 전용)
- 특정 이미지/컨테이너를 정해진 주기로 자동 스캔
- **스케줄 타입**:
  - `hourly`: 매시간 (분 지정)
  - `daily`: 매일 (시간 지정)
  - `weekly`: 매주 (요일 + 시간 지정)
- 스캔 결과는 MySQL에 자동 저장 (`scan_source = 'scheduled'`)
- 활성화/비활성화 토글 가능
- 마지막 실행 시간 및 다음 실행 시간 표시

### 5. 👮 보안 검사 & 설정 오류 스캔 (config_scan.php)

#### � 이미지 보안 검사
Docker 이미지 내 보안 설정 오류와 민감 정보를 탐지:

| 검사 유형 | 설명 |
|-----------|------|
| 🛡️ **보안 모범사례 검사** | Dockerfile, 설정파일 보안 검사 (Misconfig + Secret) |
| 🔐 **시크릿 탐지 전용** | API키, 비밀번호, 토큰 등 민감정보 집중 탐지 |
| 📋 **종합 보안 스캔** | 취약점 + 설정오류 + 시크릿 전체 검사 |

#### ⚙️ 설정 오류 스캔 (Misconfig)
IaC 파일의 보안 설정 오류 탐지:
- 📋 **Dockerfile**: USER 미지정, 불필요한 권한, 보안 모범 사례 위반
- ☸️ **Kubernetes**: privileged 모드, hostPath 마운트, securityContext 설정
- 🏗️ **Terraform/CloudFormation**: 퍼블릭 버킷, 암호화 미설정, 보안 그룹 규칙

#### 사용 방법
1. 메인 페이지 → "👮 보안 검사" 클릭
2. **보안 검사 탭**: 검사 유형 선택 → 이미지 선택 → 검사 실행
3. **설정 오류 스캔 탭**: 경로 입력 → 스캔 실행
4. 스캔 기록에서 `👮설정` 태그로 구분

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

### 8. 🛡️ 보안 진단 대시보드
4대 컨테이너 보안 영역별 커버리지 현황 표시:

| 영역 | 커버리지 | 구현 항목 |
|------|----------|----------|
| **① 이미지 보안** | 85% | CVE 스캔 ✅, 시크릿 탐지 ✅ |
| **② 인프라 보안** | 70% | Misconfig ✅, CIS Benchmark ✅ |
| **③ 런타임 보안** | 50% | 리소스 모니터링 ✅, 권한 감사 ✅ |
| **④ Compliance** | 60% | Docker CIS ✅ |

### 9. 🔒 런타임 보안 감사 (`runtime_audit.php`)
실행 중인 컨테이너의 보안 설정 점검:
- **Privileged 모드**: 특권 컨테이너 감지
- **User**: root 사용자 실행 감지
- **Network Mode**: Host 네트워크 사용 감지
- **마운트**: Docker 소켓, 호스트 루트 마운트 감지
- **Capabilities**: SYS_ADMIN 등 위험 권한 감지
- 각 컨테이너별 보안 점수 산출

#### 검색/필터 기능
- **드롭다운 선택**: 특정 컨테이너만 선택하여 조회
- **텍스트 검색**: 컨테이너명 또는 이미지명으로 검색
- **통계 표시**: 전체/정상/이슈 컨테이너 수, 평균 보안 점수

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

## 🤖 AI 취약점 조치 추천 (Gemini API)

Google Gemini AI를 활용하여 취약점에 대한 조치 방법을 자동으로 추천받을 수 있습니다.

### 기능

| 기능 | 설명 |
|------|------|
| **컨테이너 전체 분석** | 스캔 결과에서 🤖AI 버튼 클릭 → 전체 취약점 우선순위 및 조치 방법 제안 |
| **개별 CVE 분석** | 상세 화면에서 각 CVE의 🤖 버튼 클릭 → 해당 CVE 조치 방법 제안 |
| **결과 캐싱** | AI 분석 결과는 DB에 저장되어 재사용 (API 비용 절감) |
| **다시 분석** | "🔄 다시 분석" 버튼으로 최신 정보 반영 |

### 설정 방법

1. Google AI Studio에서 API Key 발급: https://aistudio.google.com/apikey
2. `.env` 파일 또는 환경변수 설정:
```bash
export GEMINI_API_KEY=your-api-key-here
```

3. docker-compose 재시작:
```bash
docker-compose down
docker-compose up -d
```

### AI 분석 내용

**컨테이너 전체 분석:**
- 🔴 즉시 조치 필요 (CRITICAL 취약점)
- 🟠 우선 조치 권장 (HIGH 취약점)
- 📋 종합 권장사항
- ⚡ 빠른 조치 명령어

**개별 CVE 분석:**
- 조치 방법 (업그레이드 경로)
- 임시 완화 방법
- 위험도 설명

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
│       ├── metrics.php           # Prometheus 메트릭
│       ├── sbom_download.php     # 📦 SBOM 다운로드 API
│       ├── security_dashboard.php # 🛡️ 보안 진단 대시보드
│       ├── runtime_audit.php     # 🔒 런타임 보안 감사
│       ├── reset_demo.php        # 🔄 데모 환경 초기화 스크립트
│       ├── ai_analysis.php       # 🤖 AI 취약점 분석 API
│       └── gemini_api.php        # 🤖 Gemini API 연동
├── grafana/
│   └── provisioning/
│       ├── datasources/
│       │   └── datasource.yml  # Prometheus + Loki 설정
│       └── dashboards/
│           ├── trivy-dashboard.json      # 📊 메트릭 대시보드
│           └── loki-logs-dashboard.json  # 🔭 로그 대시보드
├── prometheus/
│   └── prometheus.yml
├── loki/
│   └── loki-config.yml       # 🔭 Loki 로그 저장소 설정
├── promtail/
│   └── promtail-config.yml   # 🔭 Promtail 로그 수집 설정
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

## 🗄️ 데이터 영구 저장 (Persistence)

Docker 볼륨으로 데이터가 영구 저장됩니다:

| 볼륨 | 설명 |
|------|------|
| `mysql_data` | MySQL 스캔 기록, 사용자, 예외 처리 등 |
| `grafana_data` | Grafana 대시보드 설정 |
| `prometheus_data` | Prometheus 메트릭 데이터 |
| `loki_data` | Loki 로그 데이터 |

```bash
# 볼륨 확인
docker volume ls | grep trivy

# ⚠️ 주의: 볼륨 삭제 시 데이터 영구 삭제
docker volume rm trivy_test_mysql_data
```

---

## 🔭 Observability: 통합 로깅 (Loki + Promtail)

모든 컨테이너 로그를 Grafana에서 통합 조회 가능합니다.

### Loki 로그 대시보드

**URL**: `http://localhost:3000/d/loki-logs/container-logs-loki`

| 패널 | 설명 |
|------|------|
| 📊 로그 볼륨 | 시간대별 로그 발생량 (컨테이너별) |
| ⚠️ 에러 로그 볼륨 | error, fail, exception 키워드 |
| 🔴 Critical/Fatal 볼륨 | critical, fatal 키워드 |
| 📋 전체 로그 | 선택된 컨테이너의 실시간 로그 |
| ⚠️ 에러 로그만 | 에러 관련 로그만 필터링 |
| 🐳 컨테이너별 로그 수 | Top 10 컨테이너 |
| 🔴 에러 로그 수 | 컨테이너별 에러 발생량 |

### 변수 필터링 (Grafana와 동일)

| 변수 | 설명 |
|------|------|
| `$container` | 특정 컨테이너만 필터링 |
| `$service` | Docker Compose 서비스별 필터링 |
| `$search` | 텍스트 검색 |

### 접근 방법

1. **메인 페이지** → "🔭 Loki 로그 대시보드" 클릭
2. **스캔 완료 후** → "📋 이 컨테이너 로그" 클릭 (해당 컨테이너만)
3. **직접 접근**: Grafana → Dashboards → "Container Logs (Loki)"

### LogQL 쿼리 예시
```
{container="trivy_test-webserver-1"}
{service="webserver"} |= "error"
{container=~"trivy.*"} |~ "(?i)(error|fail|exception)"
```

---

## 🕒 Timezone 설정 (KST)

모든 컨테이너에 `TZ=Asia/Seoul` 설정 적용:
- 로그 시간이 한국 시간으로 표시
- 스캔 기록 시간도 KST로 저장

### PHP/DB Timezone 동기화
- **PHP**: `entrypoint.sh`에서 `/usr/local/etc/php/conf.d/timezone.ini` 생성
- **MySQL**: `getDbConnection()`에서 `SET time_zone = '+09:00'` 실행
- 웹 화면과 DB 시간이 항상 일치

---

## 🔄 안정성 설정

### MySQL 연결 재시도 (Race Condition 방지)
컨테이너 시작 시 MySQL이 준비되지 않았을 때를 대비한 재시도 로직:

```php
// db_functions.php
function getDbConnection($maxRetries = 5, $retryDelay = 3) {
    for ($i = 0; $i < $maxRetries; $i++) {
        try {
            $conn = new mysqli(...);
            if (!$conn->connect_error) return $conn;
        } catch (mysqli_sql_exception $e) {
            if ($i < $maxRetries - 1) sleep($retryDelay);
        }
    }
    return null;
}
```

### Promtail 로그 수집 권한
Docker 로그 파일 읽기를 위해 `user: root` 설정:

```yaml
# docker-compose.yml
promtail:
  user: root  # /var/lib/docker/containers 접근 권한
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

---

## 🔔 Slack Webhook 알림

### 다중 채널 지원

여러 Slack 채널에 동시에 알림을 보낼 수 있습니다.

**.env 설정:**
```bash
# 단일 채널
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz

# 다중 채널 (쉼표로 구분)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz,https://hooks.slack.com/services/aaa/bbb/ccc
```

### 알림 발송 시점

| 이벤트 | 발송 조건 |
|--------|----------|
| 자동 스캔 | ALERT_THRESHOLD 이상 취약점 발견 시 |
| 일괄 스캔 | Critical 또는 High 취약점 발견 시 |
| 이메일 발송 | 스캔 리포트 이메일 발송 시 함께 |
| Diff 리포트 | 신규 취약점 발견 시 |
| 일일 보고서 | 보고서 생성 시 요약 발송 |

### Slack 메시지 예시
```
🚨 *취약점 발견 알림*
📦 nginx:alpine
🔴 CRITICAL: 3
🟠 HIGH: 7
📊 총 취약점: 15
📋 스캔 유형: 자동 스캔
```

---

## 📊 일일 보안 보고서

매일 전체 컨테이너를 스캔하여 Before/After 비교 보고서를 생성합니다.

### 보고서 내용

| 항목 | 설명 |
|------|------|
| 전체 요약 | 총 이미지 수, 심각도별 취약점 합계 |
| 전일 대비 | Critical/High 변화량 |
| 신규 취약점 | 오늘 새로 발견된 취약점 |
| 조치된 취약점 | 어제 대비 해결된 취약점 |
| 신규 이미지 | 새로 스캔된 이미지 |

### 실행 방법

**웹 UI (Admin):**
- 메인 화면 → 📊 일일 보고서 → "보고서 생성" 클릭

**CLI:**
```bash
docker exec trivy_test-webserver-1 php /var/www/html/daily_report.php generate
```

**Cron (자동 실행):**
```bash
# 매일 오전 9시에 일일 보고서 생성
0 9 * * * docker exec trivy_test-webserver-1 php /var/www/html/daily_report.php generate
```

### Google Spreadsheet 연동

보고서를 자동으로 Google Spreadsheet에 저장합니다.

**설정 방법:**
1. [Google Cloud Console](https://console.cloud.google.com/)에서 프로젝트 생성
2. Sheets API 활성화
3. 서비스 계정 생성 및 JSON 키 다운로드
4. 스프레드시트 생성 후 서비스 계정 이메일에 편집 권한 부여
5. 시트에 "Daily Report" 탭 생성 (헤더: 날짜, 이미지, Critical, High, Medium, Low, 총계, Critical변화, High변화, 상태)

**.env 설정:**
```bash
GOOGLE_SHEET_ID=1abc123def456...  # 스프레드시트 URL의 ID 부분
```

**google-credentials.json 파일:**
```bash
# webserver/src/ 디렉토리에 배치
cp your-service-account-key.json webserver/src/google-credentials.json
```

---

## 🚨 보안 & 에러 로그 대시보드

Loki를 통해 수집된 로그 중 보안/에러 관련 로그만 필터링하여 보여주는 대시보드입니다.

**Grafana URL:** `http://[서버주소]:3000/d/security-logs/`

### 패널 구성

| 패널 | 설명 |
|------|------|
| 에러 발생 추이 | 시간대별 에러 로그 발생량 그래프 |
| 경고 발생 추이 | 시간대별 경고 로그 발생량 그래프 |
| 로그 레벨 분포 | ERROR/WARN/INFO 비율 파이차트 |
| Critical/Fatal 로그 | 치명적 에러 로그 실시간 목록 |
| Error 로그 | 에러 로그 실시간 목록 |
| 인증/권한 관련 | 로그인, 권한 거부 등 보안 로그 |
| 보안 이벤트 | CVE, Trivy, 취약점 관련 로그 |
| 네트워크/연결 이슈 | 연결 거부, 타임아웃 등 |
| 데이터베이스 에러 | MySQL, SQL 관련 에러 |
| 시간별 에러 히트맵 | 에러 발생 패턴 시각화 |

### 로그 필터 키워드

```
# 에러 패턴
error|exception|fatal|panic|critical

# 인증 패턴
auth|login|logout|permission|denied|unauthorized|forbidden

# 보안 패턴
CVE-|vulnerability|trivy|scan|security|exploit

# 네트워크 패턴
connection refused|timeout|unreachable|network

# DB 패턴
mysql|database|sql|query|deadlock
```

---

## 🤖 AI 취약점 조치 추천 (Gemini API)

Google Gemini AI를 활용하여 CVE 취약점에 대한 조치 방법을 추천합니다.

### 설정

**.env 파일:**
```bash
GEMINI_API_KEY=AIzaSy...your-api-key
```

**API 키 발급:** [Google AI Studio](https://aistudio.google.com/apikey)

### 기능

| 기능 | 설명 |
|------|------|
| 컨테이너 전체 분석 | 스캔 기록의 🤖AI 버튼 → 우선순위 및 종합 조치 방안 |
| 개별 CVE 분석 | 상세 화면의 각 CVE 옆 🤖 버튼 → 해당 CVE 조치 방법 |
| 결과 캐싱 | AI 분석 결과는 DB에 저장되어 재사용 (비용 절감) |

### 무료 한도

- 분당 15회 요청
- 일 1,500회 요청
- 분석 결과 캐싱으로 실제 API 호출 최소화

---

## 📁 환경변수 전체 목록

| 변수명 | 설명 | 예시 |
|--------|------|------|
| `GEMINI_API_KEY` | Google Gemini API 키 | `AIzaSy...` |
| `SLACK_WEBHOOK_URL` | Slack Webhook URL (쉼표로 다중) | `https://hooks.slack.com/...` |
| `GOOGLE_SHEET_ID` | Google Spreadsheet ID | `1abc123def456...` |
| `ALERT_EMAIL` | 알림 수신 이메일 | `admin@example.com` |
| `ALERT_ON_CRITICAL` | Critical 알림 활성화 | `true` / `false` |
| `ALERT_THRESHOLD` | 알림 기준 심각도 | `CRITICAL` / `HIGH` |
| `FROM_EMAIL` | 발신자 이메일 | `scanner@example.com` |
| `FROM_NAME` | 발신자 이름 | `Trivy Scanner` |
| `TZ` | 타임존 | `Asia/Seoul` |

---

## 🚨 CISA KEV - 실제 악용 취약점 탐지

**KEV (Known Exploited Vulnerabilities)**는 미국 CISA에서 관리하는 "실제 공격에 악용되고 있는 취약점" 목록입니다.

### 기능

| 기능 | 설명 |
|------|------|
| CVE 매칭 | 스캔 결과의 CVE를 KEV 목록과 자동 매칭 |
| 우선순위 표시 | KEV 취약점을 최상단에 표시, 🚨 뱃지 추가 |
| 랜섬웨어 표시 | 랜섬웨어 캠페인에 사용된 취약점 🦠 표시 |
| 상세 정보 | 조치 기한, 필요 조치 사항 등 CISA 권고 표시 |

### UI 표시

스캔 결과 상세보기에서:
- **🚨 KEV** 뱃지: 실제 공격에 사용 중인 취약점
- **🦠** 뱃지: 랜섬웨어 캠페인 연관 취약점
- 클릭 시 CISA 권고 상세 정보 표시

### API 엔드포인트

```bash
# KEV 통계 조회
curl "http://localhost:6987/cisa_kev.php?action=stats"

# 특정 CVE가 KEV인지 확인
curl "http://localhost:6987/cisa_kev.php?action=check&cve=CVE-2021-44228"

# 스캔 결과에서 KEV 매칭
curl "http://localhost:6987/cisa_kev.php?action=match&scan_id=123"

# KEV 데이터 새로고침 (24시간 캐시)
curl "http://localhost:6987/cisa_kev.php?action=refresh"
```

### 데이터 소스

- **URL**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **업데이트**: 24시간 캐시, 자동 갱신
- **현재 등록 취약점**: 약 1,100개+

---

## 🦅 Falco - 런타임 위협 탐지

Falco는 컨테이너/호스트에서 발생하는 **런타임 보안 위협**을 실시간으로 탐지합니다.

### ⚠️ 제한사항

| 환경 | 지원 여부 |
|------|----------|
| Linux 서버 | ✅ 완전 지원 |
| Docker Desktop (Mac) | ❌ 미지원 (커널 모듈 필요) |
| Docker Desktop (Windows) | ❌ 미지원 (커널 모듈 필요) |
| Kubernetes | ✅ DaemonSet으로 배포 |

### 탐지 가능한 위협

| 위협 유형 | 예시 |
|----------|------|
| 🐚 쉘 실행 | 컨테이너 내부에서 bash/sh 실행 |
| 📁 민감 파일 접근 | /etc/shadow, /etc/passwd 읽기 |
| 🔑 권한 상승 | setuid, capability 변경 |
| 🌐 네트워크 이상 | 예상치 못한 외부 연결 |
| 📦 패키지 설치 | 런타임에 apt/yum 실행 |

### Linux 서버에서 활성화

```bash
# 1. docker-compose.yml에서 falco 서비스 주석 해제
# 2. 서비스 시작
docker-compose up -d falco falco-sidekick

# 3. 로그 확인
docker-compose logs -f falco
```

### Grafana 대시보드

**URL**: `http://[서버주소]:3000/d/falco-runtime/`

| 패널 | 설명 |
|------|------|
| 런타임 위협 이벤트 추이 | 시간대별 위협 발생량 |
| 위협 유형 분포 | 쉘/파일/네트워크/권한상승 비율 |
| Critical/Warning 이벤트 | 심각한 위협 로그 목록 |
| 쉘 실행 감지 | 컨테이너 내 쉘 실행 감지 |
| 민감 파일 접근 | 보안 파일 접근 감지 |

---

## 🚫 Admission Controller (K8s 전용)

**현재 환경: Docker Compose → 구현 불가**

Admission Controller는 Kubernetes 환경에서 **취약한 이미지의 배포를 사전에 차단**하는 기능입니다.

### 개념

```
[개발자] → [kubectl apply] → [Admission Controller] → 취약점 있으면 거부!
                                    ↓
                              [Trivy 스캔]
                                    ↓
                              Critical 있으면 → ❌ 배포 거부
                              없으면 → ✅ 배포 허용
```

### Kubernetes에서 구현 방법

**1. Kyverno 사용 (권장)**

```yaml
# kyverno-policy.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: check-vulnerabilities
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-trivy-scan
      match:
        resources:
          kinds:
            - Pod
      validate:
        message: "이미지에 Critical 취약점이 있습니다. 배포가 거부되었습니다."
        deny:
          conditions:
            - key: "{{ images.*.vulnerabilities.critical }}"
              operator: GreaterThan
              value: 0
```

**2. OPA Gatekeeper 사용**

```rego
# constraint.rego
package kubernetes.admission

deny[msg] {
  input.request.kind.kind == "Pod"
  container := input.request.object.spec.containers[_]
  trivy_scan := external_data("trivy", container.image)
  trivy_scan.critical > 0
  msg := sprintf("Image %v has %v critical vulnerabilities", [container.image, trivy_scan.critical])
}
```

### Docker 환경에서의 대안

| 방법 | 설명 |
|------|------|
| CI/CD 파이프라인 | GitHub Actions/GitLab CI에서 배포 전 Trivy 스캔 |
| Pre-push Hook | Docker push 전에 로컬에서 스캔 |
| 자동 스캔 알림 | 현재 구현된 방식 - 배포 후 스캔 및 알림 |

```bash
# CI/CD 예시 (GitHub Actions)
- name: Trivy scan
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'myapp:latest'
    exit-code: '1'  # Critical 있으면 빌드 실패
    severity: 'CRITICAL'
```

---

## 📊 보안 아키텍처 요약

```
┌─────────────────────────────────────────────────────────────────┐
│                    Container Security Platform                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   [정적 분석]              [동적 분석]           [위협 인텔]     │
│   ┌─────────┐             ┌─────────┐          ┌─────────┐      │
│   │  Trivy  │             │  Falco  │          │CISA KEV │      │
│   │ Scanner │             │ Runtime │          │ Catalog │      │
│   └────┬────┘             └────┬────┘          └────┬────┘      │
│        │                       │                    │           │
│        ▼                       ▼                    ▼           │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                        Loki                              │   │
│   │                    (Log Storage)                         │   │
│   └──────────────────────────┬──────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                       Grafana                            │   │
│   │              (Visualization & Alerting)                  │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│   [알림 채널]                                                    │
│   📧 Email  │  💬 Slack  │  📊 Google Sheets  │  🤖 AI (Gemini) │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

Future Roadmap (1-Year Plan)

Phase 1: 확장성 확보 (Scalability & Multi-Target)
"어디서든, 무엇이든 스캔하는 분산 아키텍처"

[ ] Agent 아키텍처 도입: 중앙 서버와 실행 유닛(Scanner) 분리

csop-agent: 원격 서버에서 독립적으로 스캔 수행 후 결과 전송

방화벽 내부/외부망 통합 관제 지원

[ ] AWS 클라우드 자산 연동

AWS ECR (이미지 레지스트리) 자동 스캔

EC2 인스턴스 및 Security Group 보안 점검

IAM Role 기반의 안전한 권한 위임

Phase 2: 인프라 대전환 (Kubernetes Native)
"컨테이너 오케스트레이션 표준 준수"

[ ] Kubernetes 마이그레이션

Docker Compose → K8s Manifest (Deployment, StatefulSet) 변환

Helm Chart 패키징을 통한 원클릭 배포 지원

[ ] GitOps 파이프라인 구축

ArgoCD 도입으로 선언적(Declarative) 인프라 관리

코드 변경 시 자동 배포 및 동기화 구현

Phase 3: 심층 방어 및 리포팅 (Deep Security)
"탐지를 넘어 방어와 감시로"

[ ] Admission Controller 통합 (Kyverno)

K8s 배포 시 CSOP 스캔 결과를 조회하여 위험한 파드 생성 차단

"Shift-Left" 보안의 완성

[ ] 커스텀 리포팅 엔진 개발

경영진 보고용 PDF/HTML 리포트 생성기

주간/월간 보안 트렌드 분석 리포트 자동화