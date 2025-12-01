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
│       └── reset_demo.php        # 🔄 데모 환경 초기화 스크립트
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
