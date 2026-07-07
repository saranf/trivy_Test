# Trivy CSOP — Container Security Operations Platform

> 🇰🇷 **한국어 문서: [README.ko.md](README.ko.md)**

A self-hosted **container security operations platform** built around [Trivy](https://github.com/aquasecurity/trivy). It continuously scans container images and infrastructure for vulnerabilities and misconfigurations, manages a fleet of lightweight **Zabbix-style agents** across remote hosts, and ships everything into a full observability stack (Prometheus + Grafana + Loki) with email/Slack alerting and AI-assisted remediation.

Everything runs from a single `docker-compose.yml`.

---

## Table of Contents

- [Architecture](#architecture)
- [Feature Overview](#feature-overview)
- [Components](#components)
- [The Agent System](#the-agent-system)
- [Quick Start](#quick-start)
- [Access & Accounts](#access--accounts)
- [Tech Stack](#tech-stack)
- [Security Notes](#security-notes)

---

## Architecture

```
                        ┌─────────────────────────────────────────────┐
   Remote Hosts         │              Central Server                 │
   ┌───────────┐        │                                             │
   │  Agent A  │──push──▶│  nginx :6987 ──▶ PHP-FPM (webserver)        │
   │  Agent B  │  HTTP   │        │              │                     │
   │  Agent C  │  +token │        │              ▼                     │
   └───────────┘        │        │           MySQL (trivy_db)         │
                        │        │                                    │
   Docker events        │   trivy-agent :8888 (local scan micro-svc)  │
   ┌───────────┐        │   auto_scan daemon (event/scheduled trigger)│
   │ auto_scan │────────▶│                                            │
   └───────────┘        └───────────────┬─────────────────────────────┘
                                        │  /metrics.php, container logs
                                        ▼
                        Prometheus + cAdvisor ─▶ Grafana ◀─ Loki ◀─ Promtail
                                        │
                                        ▼
                        Alerts: Email (Postfix) · Slack · Google Sheets · Gemini AI
```

**Flow:** Agents & scanners run Trivy → results persist to MySQL via the PHP app → the app exposes metrics/logs → the monitoring stack visualizes them → alerts fan out on Critical/High findings.

---

## Feature Overview

### Scanning
- **Image vulnerability scanning** — Trivy `--security-checks vuln,config,secret` (v0.29.2).
- **Misconfiguration / IaC scanning** — Dockerfile, Kubernetes, and Terraform compliance checks.
- **Secret detection** — embedded credentials in images.
- **SBOM export** — CycloneDX and SPDX / SPDX-JSON.
- **Three scan triggers:** on-demand (UI/API), **scheduled** (cron every 5 min), and **event-driven** (Docker container start/restart).

### Reporting & Intelligence
- **Diff-based reports** — classifies findings as `NEW` / `FIXED` / `PERSISTENT` / `EXCEPTED` between scans.
- **MTTR KPI** — mean-time-to-remediate tracked via a vulnerability lifecycle table.
- **CISA KEV enrichment** — flags Known-Exploited Vulnerabilities for prioritization.
- **Gemini AI remediation** — AI-generated fix guidance per CVE, cached in the DB.
- **Daily reports** — yesterday-vs-today comparison pushed to Slack and Google Sheets.
- **Prometheus metrics** — scan KPIs exposed at `/metrics.php`.

### Risk Management
- **Exception / risk-acceptance system** — accept specific CVEs with reason + expiry.
- **RBAC** — four tiers: `viewer` < `demo` < `operator` < `admin`, with fine-grained per-role/per-user permissions.
- **Audit logging** — all destructive and privileged actions recorded.
- **Demo mode** — masked data, simulated saves, daily midnight (KST) reset.

### Observability
- **Grafana dashboards** — Trivy metrics, Loki logs, security logs, Falco runtime.
- **Loki + Promtail** — centralized container log aggregation (7-day retention).
- **cAdvisor** — per-container CPU/memory/network metrics.
- **Falco** *(optional, Linux only)* — runtime syscall threat detection → Loki.

### Alerting
- **Email** via Postfix mail container (msmtp).
- **Slack** multi-webhook support, gated by `ALERT_ON_CRITICAL` / `ALERT_THRESHOLD`.
- **Google Sheets** daily report sync.

---

## Components

| Service | Image | Port | Role |
|---|---|---|---|
| **nginx** | `nginx:latest` | `6987:80` | Reverse proxy / web UI entry point |
| **webserver** | custom PHP 8-FPM | `9555:9000` | Core app: scanning, reports, RBAC, APIs |
| **mysql** | `mysql:8.0` | `9756:3306` | Database (`trivy_db`) |
| **trivy-agent** | `./trivy-agent` | internal `8888` | Local scan microservice (HTTP API) |
| **auto_scan** | `./auto_scan` | — | Docker-event & scheduled scan trigger |
| **prometheus** | `prom/prometheus` | `9090` | Metrics TSDB |
| **grafana** | `grafana/grafana` | `3000` | Dashboards |
| **cadvisor** | `cadvisor` | `8080` | Container resource metrics |
| **loki** | `grafana/loki:2.9.0` | `3100` | Log storage |
| **promtail** | `grafana/promtail:2.9.0` | — | Log shipper |
| **mailserver** | `boky/postfix` | — | SMTP relay for email alerts |
| **falco** *(disabled)* | `falcosecurity/falco` | — | Runtime threat detection (Linux only) |

All services share the `app-network` bridge and `Asia/Seoul` timezone. Persistent volumes: `mysql_data`, `prometheus_data`, `grafana_data`, `loki_data`.

---

## The Agent System

The platform ships a **distributed agent** you deploy on remote hosts to scan and collect telemetry — much like a Zabbix agent, but for container security.

### Two agent implementations
- **`agent.sh`** (shell, full-featured) — the primary agent. Registers with the central server, sends heartbeats, runs Trivy scans on a schedule, watches Docker events, and executes commands pushed from the server.
- **`simple_agent.py`** (Python, stdlib-only) — lightweight system-info reporter for minimal hosts (no Trivy).

### Operating modes (`MODE` env var)
- `api` — expose an HTTP scan API on `:8888` only (pull model).
- `push` — register + heartbeat + push scans/telemetry to the central server (push model).
- `both` — do both.

### What it does (push mode)
1. **Register** → `POST ?action=register` with `X-Agent-Token`; agent shows up online.
2. **Heartbeat** every `HEARTBEAT_INTERVAL` (default 60s); server piggybacks queued commands.
3. **Scheduled scans** every `SCAN_INTERVAL` (default 300s) — Trivy-scans every running container image.
4. **Event-driven scans** — tails `docker events`, scans newly started images.
5. **Commands** — server can push `scan_image`, `scan_all`, `collect`; results reported back.

### Collectors (pluggable, emit JSON)
`system` · `docker` · `processes` · `network` · `iptables` — plus the `trivy` scan collector. Custom collectors just need to print JSON to stdout.

### HTTP API (`api_server.py`, Flask + gunicorn on `:8888`)
All routes except `/health` require the `X-Agent-Token` header.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness + agent ID |
| POST | `/scan/image` | Trivy vuln+config scan (HIGH/CRITICAL) |
| POST | `/scan/sbom` | SBOM (CycloneDX / SPDX) |
| POST | `/scan/config` | Misconfig scan |
| GET | `/docker/images` | List images |
| GET | `/docker/containers` | List containers |

### Install on a remote host
```bash
# Docker (recommended) — mounts docker.sock to scan host containers
./trivy-agent/scripts/install.sh \
  --api-url https://your-server:6987/api/agent.php \
  --token   YOUR_AGENT_TOKEN \
  --collectors trivy,system,docker

# Native (systemd) alternative
./trivy-agent/scripts/install.sh --api-url ... --token ... --no-docker
```

See **[AGENT_GUIDE.md](AGENT_GUIDE.md)** for the full agent reference (custom collectors, asset tagging, command flow, security hardening).

---

## Quick Start

```bash
# 1. Prerequisites: Docker + Docker Compose installed
# 2. Configure alerting env vars in docker-compose.yml (SMTP, Slack, etc.)
# 3. Make scripts executable
chmod +x webserver/entrypoint.sh auto_scan/auto_scan_daemon.sh

# 4. Launch
docker-compose up -d --build
```

Open firewall ports **6987** (Web UI) and **3000** (Grafana); optionally **9090** / **8080**.

Full instructions: **[DEPLOY_GUIDE.md](DEPLOY_GUIDE.md)** · System reference: **[docs/SYSTEM_GUIDE.md](docs/SYSTEM_GUIDE.md)**

---

## Access & Accounts

| Service | URL | Credentials |
|---|---|---|
| Trivy Web UI | `http://<host>:6987` | `admin` / `admin123` |
| Demo (read-only) | same | `demo` / `demo123` |
| Grafana | `http://<host>:3000` | `admin` / `admin123` |
| Prometheus | `http://<host>:9090` | — |
| cAdvisor | `http://<host>:8080` | — |

---

## Tech Stack

- **Backend:** PHP 8 (FPM) + Nginx, MySQL 8.0
- **Scanner:** Trivy v0.29.2 (pinned)
- **Agent:** Bash + Python (Flask/gunicorn), Alpine (~50 MB image)
- **Monitoring:** Prometheus, Grafana, Loki, Promtail, cAdvisor, Falco
- **Integrations:** Slack, Postfix email, Google Sheets, Google Gemini AI, CISA KEV catalog

---

## Security Notes

This is a **portfolio / lab project**. Before any real deployment, review:

- 🔴 Hardcoded DB credentials and default `admin`/`demo` passwords are committed in source — rotate them.
- 🔴 Default agent token `default-agent-token-change-me` must be changed.
- 🟠 The agent HTTP API runs commands with `shell=True` and minimal input sanitization — restrict network exposure and use a strong token.
- 🟠 Grafana allows anonymous Viewer access by default.
- 🟠 The agent and webserver mount `/var/run/docker.sock` — equivalent to host root; keep containers isolated.

Recommended hardening (per AGENT_GUIDE): rotate tokens, terminate TLS in front of the API, IP-allowlist agents, run agents with least-privilege capabilities and read-only filesystems.
