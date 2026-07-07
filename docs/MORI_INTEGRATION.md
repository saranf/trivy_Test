# MORI-SOC Integration

How Trivy findings become risk and audit evidence inside MORI-SOC, and where AI
fits. The dividing line is deliberate:

> **The agent is lightweight and deterministic. AI-assisted remediation runs
> centrally after findings are normalized and stored.**

---

## Responsibility split

| Trivy Agent / CSOP (edge) | MORI-SOC (central) |
|---|---|
| Enumerate images, run `trivy` | Ingest & normalize Trivy reports |
| Ship the raw report / diff export | Deduplicate, map assets & criticality |
| Prototype diff & lifecycle in CSOP | Compute risk score |
| — | Generate AI remediation draft |
| — | Store append-only audit evidence |
| — | Human decision: accept / mitigate / exception |

---

## Real MORI API (as of MORI SOC API v0.2.0)

MORI already exposes the endpoints we integrate against (default `http://<host>:18000`):

### Vulnerability ingest — `POST /ingest/trivy`

**This is the ingest contract.** It takes a **raw Trivy JSON report** (a dict
with a `Results` key, normally also `ArtifactName`) — *not* our normalized
envelope. MORI normalizes internally (`TrivyCollector` → `EnvelopeEntityMapper`)
and loads into PostgreSQL.

- **Auth:** if `MORI_INGEST_TOKEN` is set → `Authorization: Bearer <token>` **or**
  `X-MORI-Token: <token>`. If unset → a logged-in session is required.
- **Requires** `MORI_DATABASE_URL` (postgres) or returns `503`.
- **Body check:** missing `Results` → `400`. Wrong/absent token → `401`.
- **Returns:** `{ ok, records_collected, entities_saved, artifact }`.

- **Host binding:** `?hostname=<host>` (also `X-MORI-Hostname` header or body
  `hostname`/`host_id`) → MORI binds findings to that host instead of deriving
  `host_id` from `ArtifactName`. Backward-compatible (omit → old behavior).

```bash
trivy image --format json nginx:1.25 > report.json
curl -X POST "http://<host>:18000/ingest/trivy?hostname=server-db01" \
     -H "X-MORI-Token: $MORI_INGEST_TOKEN" \
     -H "Content-Type: application/json" \
     --data-binary @report.json
```

The agent does this in `push.mode: mori_raw` with `push.hostname` set.

### Evidence ingest — `POST /ingest/evidence`

Accepts the CSOP **diff-aware envelope** (`mori.trivy.findings.v1`, with
`delta_type`) as flexible JSONB — a single envelope or `{"events":[...]}` batch.
Same token auth as `/ingest/trivy`. Stored in `ui_evidence_events`.
`GET /evidence` reads them (admin·security only). CSOP pushes here via
`api/scan_diff_export.php?dest=mori` (the **⬆ MORI로 전송** button).

### Read / triage endpoints

| Endpoint | Use |
|---|---|
| `GET /trivy/vulnerabilities` | Ingested Trivy findings, by host |
| `GET /vulnerabilities/risk-summary` | Risk matrix + per-CVE scores/levels |
| `GET /vulnerabilities/{id}/risk` · `PUT` | Read / set risk assessment |
| `GET /vulnerabilities/{id}/action` | Recommended action |
| `PUT /vulnerabilities/{id}/plan` | Remediation plan |
| `PUT,DELETE /vulnerabilities/{id}/exception` | Risk acceptance |
| `GET /zabbix/hosts` · `GET /fleet/hosts` · `GET /assets` | Host/asset context for correlation |

---

## Two integration paths (don't conflate them)

**1. Vulnerability ingest** — get CVEs into MORI so it can score & triage.
Ship the **raw Trivy report** to `POST /ingest/trivy`. The agent or a CSOP job
can do this. MORI owns normalization.

**2. Evidence import** — the before/after remediation story. CSOP builds a
**diff-aware** envelope (`mori.trivy.findings.v1`, with `delta_type` per finding)
and POSTs it to MORI **`POST /ingest/evidence`** (not `/ingest/trivy`, which only
takes raw reports). It can also still be downloaded (JSON/CSV) for offline audit.

> **Agent push modes** (`push.mode` in `agent/config.yaml`):
> - `mock` (default) → normalized envelope to `server_mock` `POST /api/v1/findings`.
> - `mori_raw` → **raw Trivy report** straight to MORI `POST /ingest/trivy`
>   (Bearer token; MORI normalizes). Register/heartbeat are skipped (MORI has no
>   such endpoints). This closes the agent→MORI path — verified against
>   `server_mock` (which now also emulates `/ingest/trivy`).

### CSOP → MORI rollout (all wired)

1. **Download** evidence JSON/CSV from CSOP (`api/scan_diff_export.php`).
2. **Validate** against `server_mock` (emulates `/ingest/trivy` + `/ingest/evidence`).
3. **POST to MORI** — raw reports via agent `mori_raw` → `/ingest/trivy`;
   diff evidence via CSOP **⬆ MORI로 전송** → `/ingest/evidence`. Auth: the shared
   `MORI_INGEST_TOKEN` (token → session fallback).

---

## Diff-aware evidence envelope (`mori.trivy.findings.v1`)

Produced by CSOP Scan Diff V2 (`buildMoriEvidenceEnvelope` →
`api/scan_diff_export.php?format=json`):

```json
{
  "schema_version": "mori.trivy.findings.v1",
  "source": "trivy-agent",
  "agent_id": "agent-host-001",
  "hostname": "agent-host-001",
  "scan_run_id": "scan-42",
  "target": "nginx:1.25",
  "generated_at": "2026-07-07T09:05:12+00:00",
  "summary": { "new": 2, "fixed": 8, "unchanged": 10,
               "severity_changed": 1, "version_changed": 1, "reopened": 0,
               "critical": 1, "high": 4 },
  "findings": [
    { "vulnerability_id": "CVE-2026-XXXX", "package_name": "openssl",
      "installed_version": "1.1.1", "fixed_version": "1.1.1x",
      "severity": "HIGH", "delta_type": "new" }
  ]
}
```

`delta_type ∈ { new, fixed, unchanged, severity_changed, version_changed, reopened }`.
Dedupe key is `vulnerability_id | package` — the same composite key the agent
emits (see [AGENT_PROTOCOL.md](AGENT_PROTOCOL.md)); keying on the CVE alone would
collapse a CVE that appears in multiple packages.

---

## Host ↔ Image mapping

MORI derives `host_id` from the Trivy `ArtifactName` (e.g. `alpine:3.19` →
`server-alpine-3.19`), so an image scan is **not** tied to a real Zabbix host —
which is why host-grouped `GET /trivy/vulnerabilities` can show `count: 0` for
ingested image findings.

CSOP solves this with an explicit **`host_image_mapping`** table
(`hostname ↔ image_name`, + optional `agent_id` / `zabbix_hostid`), managed in
`csop_zabbix_context.php`. For each Zabbix host, mapped images auto-show their
latest before/after diff (New / Fixed / Still-open) and link into Scan Diff V2.

The mapping is exposed as JSON so **MORI can consume it** instead of (or in
addition to) ArtifactName derivation:

```
GET /csop_zabbix_context.php?action=mappings
[ { "hostname": "web-server-01", "image_name": "nginx:demo",
    "agent_id": "agent-demo", "zabbix_hostid": "h-web-01" }, ... ]
```

Two ways to close the host↔image gap (complementary):
1. **CSOP mapping table** (implemented) — CSOP owns the mapping, exposes JSON.
2. **Hostname in the ingest payload** (MORI side) — the agent/report carries the
   real hostname so MORI binds findings to the host directly.

### CSOP → MORI auth

`moriApiGet()` authenticates to MORI: **token first** (`MORI_INGEST_TOKEN` →
`X-MORI-Token` / `Bearer`), then **session-login fallback**
(`MORI_USER` / `MORI_PASSWORD` → `POST /auth/login`, cookie reused). So CSOP
works whether MORI uses token or session auth. Configure via `docker-compose.yml`
webserver env.

## The Zabbix ↔ Trivy ↔ MORI ↔ AI story

```
Zabbix        host availability / infra problem   ── raises host as impacted
Trivy Agent   CVEs in that host's container images ── this repo
MORI-SOC      correlates host + findings → risk, incident, evidence
AI            remediation draft for the operator to accept / mitigate / except
```

Worked example:
1. Zabbix reports a problem on `host01` (`GET /zabbix/hosts`).
2. MORI marks `host01` high-criticality (`GET /assets`).
3. Trivy scans that host's images; the raw report goes to `/ingest/trivy`.
4. MORI raises risk (`GET /vulnerabilities/risk-summary`).
5. AI drafts remediation; operator sets `/vulnerabilities/{id}/plan` or
   `/exception`.
6. CSOP diff export provides before/after evidence for the audit report.

---

## Local development against the mock

`server_mock/receive_findings.py` implements the **normalized** agent protocol
(`/api/v1/agents/register`, `/heartbeat`, `/api/v1/findings`) so the agent can be
exercised without MORI. It validates and stores only — no triage/risk/AI. For a
**real MORI** round-trip, use `/ingest/trivy` as shown above. End-to-end steps
are in [TEST_SCENARIOS.md](TEST_SCENARIOS.md).
