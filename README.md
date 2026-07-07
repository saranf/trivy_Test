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

## Structure

```
trivy_Test/
├── agent/
│   ├── trivy_agent.py             # the agent: scan → normalize → push (stdlib only)
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

## Try it locally

```bash
# terminal 1 — mock central API (stands in for MORI-SOC)
python3 server_mock/receive_findings.py --port 8080 --token change-me-agent-token

# terminal 2 — one agent cycle (needs docker + trivy on PATH)
cp agent/config.example.yaml agent/config.yaml
MORI_AGENT_TOKEN=change-me-agent-token \
  python3 agent/trivy_agent.py --config agent/config.yaml --once
```

Received envelopes are written to `server_mock/received/`. Use `--dry-run` to
print normalized envelopes without pushing.

### As a container

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

The image bundles Trivy + docker-cli on the official `aquasec/trivy` base. The
socket mount lets it enumerate/scan host images; the agent only reads through it.

Full run guide (native / container / systemd, flags, config, troubleshooting):
**[docs/RUNNING_THE_AGENT.md](docs/RUNNING_THE_AGENT.md)**

---

## Roadmap

| Week | Goal | |
|---|---|---|
| 1 | Reposition README: *archived CSOP → MORI Trivy Agent Lab* | ✅ |
| 2 | Agent registration + heartbeat | ✅ |
| 3 | `trivy image` scan + normalized JSON push | ✅ |
| 4 | MORI API integration docs | ✅ |

The MVP is implemented in [agent/](agent/), with a local stand-in for the
central API in [server_mock/](server_mock/) and the wire contract in
[docs/AGENT_PROTOCOL.md](docs/AGENT_PROTOCOL.md).

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

## CSOP Legacy UI Sandbox

An earlier iteration of this repo grew into a full **Container Security Operations Platform**: a PHP dashboard, MySQL, RBAC, agent fleet management, Slack/email/Google-Sheets alerting, Gemini AI analysis, and a Prometheus/Grafana/Loki monitoring stack — all via `docker-compose`.

That code is **not thrown away** — it's kept as an **experimental UI sandbox** for prototyping MORI-SOC features (scan diff, finding lifecycle, remediation drafts, evidence export) before the stable ones move into MORI.

> CSOP Legacy UI is retained as a sandbox for testing Trivy scan diff, remediation workflow, and evidence export before integrating stable features into MORI-SOC. It is **not** the product direction and is **not** production-ready. New production-oriented work lives in `agent/`, `server_mock/`, and `docs/`.

**Positioning: MORI-SOC is the product · `trivy_Test` is the lab · CSOP is the UI sandbox.**

Legacy CSOP sandbox directories (retained for UI prototyping and historical reference):
`webserver/` · `auto_scan/` · `grafana/` · `loki/` · `prometheus/` · `promtail/` · `falco/`

- **What may be prototyped here, and what may not:** [docs/CSOP_LAB_SCOPE.md](docs/CSOP_LAB_SCOPE.md)
- **Scan Diff V2 + MORI evidence export** (built): `csop_scan_diff.php` — before/after CVE classification, JSON/CSV export
- **Finding Lifecycle** (built): `csop_finding_lifecycle.php` — CVE state (open/accepted_risk/…), risk decision + evidence fields
- **Zabbix Host Context + Host↔Image mapping** (built): `csop_zabbix_context.php` — maps Zabbix hosts to Trivy images, auto-links each host to its latest diff; exposes mapping JSON for MORI
- **Test plan** (local + MORI connection): [docs/TEST_SCENARIOS.md](docs/TEST_SCENARIOS.md)
- Prior platform reference: [AGENT_GUIDE.md](AGENT_GUIDE.md) · [DEPLOY_GUIDE.md](DEPLOY_GUIDE.md) · [docs/SYSTEM_GUIDE.md](docs/SYSTEM_GUIDE.md)
- The existing shell/Python agent this lab builds on: [trivy-agent/](trivy-agent/)
