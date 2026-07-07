# MORI-SOC Integration

How Trivy Agent findings become risk and audit evidence inside MORI-SOC, and
where AI fits. The dividing line is deliberate:

> **The agent is lightweight and deterministic. AI-assisted remediation runs
> centrally after findings are normalized and stored.**

---

## Responsibility split

| Trivy Agent (edge) | MORI-SOC (central) |
|---|---|
| Enumerate local images | Ingest & validate envelopes |
| Run `trivy image` | Deduplicate findings by `id` across scans/assets |
| Normalize to schema `1.0` | Map target → asset & criticality |
| Push envelope | Compute risk score |
| Heartbeat | Generate AI remediation draft |
| — | Store as immutable audit evidence |
| — | Human decision: accept / mitigate / exception |

The agent carries no policy, no asset inventory, and no secrets beyond its own
push token. Everything that requires context or judgement is central.

---

## Ingestion pipeline (central side)

```
POST /api/v1/findings
      │
      ▼
1. Validate envelope (schema_version, required fields)
2. Dedup: upsert each finding by id = vuln|package|target
      → NEW vs PERSISTENT vs FIXED (finding absent this scan) vs EXCEPTED
3. Asset mapping: scan.target + agent_id/hostname → asset record + criticality
4. Risk scoring: severity × CVSS × asset criticality × exploit signals (e.g. CISA KEV)
5. AI remediation draft (async, cached per vulnerability_id + package)
6. Persist as audit evidence (append-only); expose CSV/PDF export
```

Steps 2 and 4 are why the agent's `id` and deterministic ordering matter: stable
keys make dedup and diffing cheap and correct.

---

## The Zabbix ↔ Trivy ↔ MORI ↔ AI story

The agent is one input in a larger correlation:

```
Zabbix        host availability / infra problem   ── raises host as impacted
Trivy Agent   CVEs in that host's container images ── this repo
MORI-SOC      correlates host + findings → risk, incident, evidence
AI            remediation draft for the operator to accept / mitigate / except
```

Worked example:
1. Zabbix reports a problem on `host01`.
2. MORI marks `host01` as a high-criticality asset.
3. Trivy Agent on `host01` pushes CVEs for its images.
4. MORI raises the risk score for those findings (criticality-weighted).
5. AI produces a remediation draft (upgrade path, config change).
6. Operator decides; the decision + evidence are exported for audit.

---

## Mapping envelope → MORI entities

| Envelope field | MORI entity |
|---|---|
| `agent_id`, `hostname` | Agent / Host asset |
| `scan.target` | Scanned artifact (container image) |
| `finding.id` | Finding primary key (dedup) |
| `finding.vulnerability_id` | CVE record (join to CISA KEV, NVD) |
| `finding.severity`, `cvss_score` | Base risk inputs |
| `scan.started_at/completed_at` | Evidence timestamps (MTTR lifecycle) |

---

## Local development against the mock

`server_mock/receive_findings.py` implements the same endpoints so the agent can
be exercised without MORI:

```bash
# terminal 1 — mock central API
python3 server_mock/receive_findings.py --port 8080 --token change-me-agent-token

# terminal 2 — one agent cycle against the mock
MORI_AGENT_TOKEN=change-me-agent-token \
  python3 agent/trivy_agent.py --config agent/config.yaml --once
```

Received envelopes land in `server_mock/received/`. The mock only validates and
stores — it intentionally does none of the triage/risk/AI work above.
