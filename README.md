# Trivy Agent Lab for MORI-SOC

A lightweight Trivy-based scanner agent experiment for MORI-SOC.
It collects container image vulnerabilities, SBOMs, and misconfiguration findings from remote hosts and pushes normalized results to a central security-operations API.

> **This repository is an agent / integration lab, not a standalone production security platform.**

> 🇰🇷 **한국어 문서: [README.ko.md](README.ko.md)**

---

## Where this fits

This lab is **Phase 3–4 experimentation for MORI-SOC** — not an independent product. It plugs into a larger security-operations story:

```
Zabbix          → host availability / infrastructure problems
Trivy Agent     → container image vulnerability findings   ← this repo
MORI-SOC        → triage / risk register / audit evidence
AI              → remediation drafts (central, post-normalization)
```

### Example end-to-end scenario

```
1. Zabbix raises a host problem
2. MORI marks the host as a high-risk asset
3. Trivy Agent finds CVEs in that host's container images
4. MORI raises the CVE risk score for the asset
5. AI generates a remediation draft
6. An operator decides: accept / mitigate / exception
7. Evidence is exported as CSV / PDF
```

---

## Design principle

> **The agent remains lightweight and deterministic. AI-assisted remediation runs centrally after findings are normalized and stored.**

The agent is intentionally read-only and dumb. Intelligence lives in the center.

| Agent (this repo) | MORI-SOC / API (central) |
|---|---|
| scan (Trivy image / fs / config) | deduplicate CVEs across assets |
| collect (docker image list, SBOM) | map asset criticality |
| normalize findings to JSON | calculate risk score |
| push to central API | generate AI remediation draft |
| heartbeat | store & export audit evidence |

This keeps the agent safe to deploy widely (no secrets, no AI keys, minimal blast radius) and concentrates policy/AI logic where it can be governed.

---

## Agent MVP scope

The forward work is deliberately small:

1. Agent registration
2. Heartbeat
3. Local Docker image list collection
4. `trivy image` scan execution
5. Result normalization to a stable JSON schema
6. Push to the MORI API
7. *(optional)* AI remediation summary — **central, not in the agent**

---

## Target structure (planned)

```
trivy_Test/
├── agent/
│   ├── trivy_agent.py
│   ├── config.example.yaml
│   └── systemd/trivy-agent.service
├── server_mock/
│   └── receive_findings.py        # local stand-in for the MORI API
├── docs/
│   ├── AGENT_PROTOCOL.md          # register / heartbeat / findings wire format
│   ├── MORI_INTEGRATION.md        # how findings map into MORI risk/evidence
│   └── SECURITY_MODEL.md          # why the agent stays read-only & deterministic
└── README.md
```

---

## Roadmap

| Week | Goal |
|---|---|
| 1 | Reposition README: *archived CSOP → MORI Trivy Agent Lab* ✅ |
| 2 | Agent registration + heartbeat |
| 3 | `trivy image` scan + normalized JSON push |
| 4 | MORI API integration docs |

Priority note: this lab is **not** the current top priority — the active thread is Zabbix contribution (upstream PR pending). This repo advances slowly and deliberately.

---

## Non-goals

To keep the portfolio focused, this lab explicitly avoids:

- ❌ Building another large web UI
- ❌ Rebuilding RBAC
- ❌ Standing up the full Grafana / Loki / Prometheus stack again
- ❌ Putting AI front-and-center
- ❌ Describing itself as a "production-ready security platform"

---

## Background — archived CSOP prototype

An earlier iteration of this repo grew into a full **Container Security Operations Platform**: a PHP dashboard, MySQL, RBAC, agent fleet management, Slack/email/Google-Sheets alerting, Gemini AI analysis, and a Prometheus/Grafana/Loki monitoring stack — all via `docker-compose`.

That code still lives in this repository (`webserver/`, `auto_scan/`, `grafana/`, `loki/`, `prometheus/`, `promtail/`, `falco/`) and remains useful as reference, but **it is not the direction going forward**. The project is being scoped down to the agent + integration lab described above.

- Prior platform reference: [AGENT_GUIDE.md](AGENT_GUIDE.md) · [DEPLOY_GUIDE.md](DEPLOY_GUIDE.md) · [docs/SYSTEM_GUIDE.md](docs/SYSTEM_GUIDE.md)
- The existing shell/Python agent this lab builds on: [trivy-agent/](trivy-agent/)
