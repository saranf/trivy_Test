# Trivy Agent Lab for MORI-SOC

MORI-SOC를 위한 경량 Trivy 기반 스캐너 에이전트 실험장입니다.
원격 호스트에서 컨테이너 이미지 취약점·SBOM·설정 오류 결과를 수집하고, 정규화한 결과를 중앙 보안운영 API로 push 합니다.

> **이 저장소는 에이전트 / 연동 실험장이며, 독립 실행형 프로덕션 보안 플랫폼이 아닙니다.**

> 🇺🇸 **English: [README.md](README.md)**

---

## 이 프로젝트의 위치

이 실험장은 독립 제품이 아니라 **MORI-SOC의 Phase 3~4 실험**입니다. 더 큰 보안운영 스토리에 끼워 넣는 조각이에요:

```
Zabbix          → 호스트 가용성 / 인프라 장애
Trivy Agent     → 컨테이너 이미지 취약점 발견        ← 이 저장소
MORI-SOC        → triage / 리스크 레지스터 / 감사 증적
AI              → remediation 초안 (중앙에서, 정규화 이후)
```

### 엔드투엔드 예시 시나리오

```
1. Zabbix에서 특정 호스트 장애 발생
2. MORI가 해당 호스트를 high-risk asset으로 표시
3. Trivy Agent가 그 호스트의 컨테이너 이미지에서 CVE 발견
4. MORI가 해당 자산의 CVE 리스크 점수 상승
5. AI가 remediation 초안 생성
6. 담당자가 accept / mitigate / exception 결정
7. CSV / PDF 증적 내보내기
```

---

## 설계 원칙

> **에이전트는 가볍고 결정론적으로(deterministic) 유지한다. AI 기반 remediation은 결과가 정규화·저장된 이후 중앙에서 실행한다.**

에이전트는 의도적으로 read-only이고 단순하게 둡니다. 지능은 중앙에 있습니다.

| 에이전트 (이 저장소) | MORI-SOC / API (중앙) |
|---|---|
| 스캔 (Trivy image / fs / config) | 자산 전반의 CVE 중복 제거 |
| 수집 (docker 이미지 목록, SBOM) | 자산 중요도(criticality) 매핑 |
| 결과를 JSON으로 정규화 | 리스크 점수 계산 |
| 중앙 API로 push | AI remediation 초안 생성 |
| heartbeat | 감사 증적 저장·내보내기 |

이렇게 하면 에이전트를 광범위하게 배포해도 안전하고(시크릿·AI 키 없음, 영향 범위 최소화), 정책·AI 로직은 통제 가능한 중앙에 집중됩니다.

---

## 에이전트 MVP 범위

앞으로의 작업은 의도적으로 작게 잡습니다:

1. 에이전트 등록
2. Heartbeat
3. 로컬 Docker 이미지 목록 수집
4. `trivy image` 스캔 실행
5. 안정적인 JSON 스키마로 결과 정규화
6. MORI API로 push
7. *(선택)* AI remediation 요약 — **에이전트가 아니라 중앙에서**

---

## 구조

```
trivy_Test/
├── agent/
│   ├── trivy_agent.py             # 에이전트: scan → normalize → push (stdlib only)
│   ├── config.example.yaml
│   └── systemd/trivy-agent.service
├── server_mock/
│   └── receive_findings.py        # MORI API의 로컬 대체용
├── docs/
│   ├── AGENT_PROTOCOL.md          # register / heartbeat / findings 전송 포맷
│   ├── MORI_INTEGRATION.md        # findings가 MORI 리스크/증적에 매핑되는 방식
│   └── SECURITY_MODEL.md          # 에이전트를 read-only·결정론적으로 두는 이유
└── README.md
```

## 로컬에서 실행해보기

```bash
# 터미널 1 — 목 중앙 API (MORI-SOC 대체)
python3 server_mock/receive_findings.py --port 8080 --token change-me-agent-token

# 터미널 2 — 에이전트 1회 실행 (docker + trivy 필요)
cp agent/config.example.yaml agent/config.yaml
MORI_AGENT_TOKEN=change-me-agent-token \
  python3 agent/trivy_agent.py --config agent/config.yaml --once
```

수신된 envelope은 `server_mock/received/` 에 저장됩니다. `--dry-run` 을 쓰면
push 없이 정규화된 envelope을 출력만 합니다.

### 컨테이너로 실행

```bash
docker build -t trivy-agent-lab agent/

docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/agent/config.yaml":/opt/agent/config.yaml:ro \
  --add-host host.docker.internal:host-gateway \
  -e MORI_SERVER_URL=http://host.docker.internal:8080 \
  -e MORI_AGENT_TOKEN=change-me-agent-token \
  trivy-agent-lab --once
```

이미지는 공식 `aquasec/trivy` 베이스에 Trivy + docker-cli를 번들합니다. 소켓
마운트로 호스트 이미지를 열거·스캔하며, 에이전트는 소켓을 읽기만 합니다.

전체 실행 가이드 (native / container / systemd, 플래그, config, 트러블슈팅):
**[docs/RUNNING_THE_AGENT.md](docs/RUNNING_THE_AGENT.md)**

---

## 로드맵

| 주차 | 목표 | |
|---|---|---|
| 1주차 | README 재정의: *아카이브된 CSOP → MORI Trivy Agent Lab* | ✅ |
| 2주차 | 에이전트 등록 + heartbeat | ✅ |
| 3주차 | `trivy image` 스캔 + 정규화 JSON push | ✅ |
| 4주차 | MORI API 연동 문서 | ✅ |

MVP는 [agent/](agent/) 에 구현되어 있고, 중앙 API의 로컬 대체는
[server_mock/](server_mock/), 전송 규약은
[docs/AGENT_PROTOCOL.md](docs/AGENT_PROTOCOL.md) 에 있습니다.

우선순위 참고: 이 실험장은 **현재 최우선이 아닙니다** — 지금 가장 강한 흐름은 Zabbix 기여(업스트림 PR 대기 중)입니다. 이 저장소는 천천히, 신중하게 진행합니다.

---

## 하지 않을 것 (Non-goals)

포트폴리오를 산만하지 않게 유지하기 위해, 이 실험장은 다음을 명시적으로 피합니다:

- ❌ 또 다른 대형 웹 UI 제작
- ❌ RBAC 재구현
- ❌ Grafana / Loki / Prometheus 스택 전체 재구축
- ❌ AI를 전면에 내세우기
- ❌ "프로덕션급 보안 플랫폼"이라고 표현하기

---

## CSOP Legacy UI 샌드박스

이 저장소의 이전 버전은 완전한 **컨테이너 보안 운영 플랫폼(CSOP)** 으로 커졌습니다: PHP 대시보드, MySQL, RBAC, 에이전트 플릿 관리, Slack/이메일/Google Sheets 알림, Gemini AI 분석, Prometheus/Grafana/Loki 모니터링 스택 — 전부 `docker-compose` 로.

그 코드는 **버리지 않습니다** — MORI-SOC 기능(스캔 diff, finding 라이프사이클, remediation 초안, 증적 export)을 MORI에 넣기 전에 UI에서 먼저 실험하는 **샌드박스**로 유지합니다.

> CSOP Legacy UI는 버리지 않고, Trivy scan diff / 조치 상태 / 증적 export를 MORI에 붙이기 전 검증하는 샌드박스로 유지합니다. 이는 **제품 방향이 아니며 프로덕션용도 아닙니다**. 프로덕션 지향 신규 작업은 `agent/`, `server_mock/`, `docs/` 에 있습니다.

**포지션: MORI-SOC가 제품 · `trivy_Test`가 실험실 · CSOP가 UI 샌드박스.**

Legacy CSOP 샌드박스 디렉터리 (UI 프로토타이핑·기록용 보존):
`webserver/` · `auto_scan/` · `grafana/` · `loki/` · `prometheus/` · `promtail/` · `falco/`

- **여기서 실험해도 되는 것 / 안 되는 것:** [docs/CSOP_LAB_SCOPE.md](docs/CSOP_LAB_SCOPE.md)
- **Scan Diff V2 + MORI evidence export** (구현됨): `csop_scan_diff.php` — 조치 전/후 CVE 분류, JSON/CSV 내보내기
- **Finding Lifecycle** (구현됨): `csop_finding_lifecycle.php` — CVE 상태(open/accepted_risk/…), 조치 결정 + 증적 필드
- **테스트 계획** (로컬 + MORI 연결): [docs/TEST_SCENARIOS.md](docs/TEST_SCENARIOS.md)
- 이전 플랫폼 참고: [AGENT_GUIDE.md](AGENT_GUIDE.md) · [DEPLOY_GUIDE.md](DEPLOY_GUIDE.md) · [docs/SYSTEM_GUIDE.md](docs/SYSTEM_GUIDE.md)
- 이 실험장이 기반으로 삼는 기존 셸/파이썬 에이전트: [trivy-agent/](trivy-agent/)
