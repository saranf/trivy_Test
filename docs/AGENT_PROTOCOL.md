# Agent Protocol

The wire contract between the **Trivy Agent** and the central **MORI-SOC API**
(`server_mock/receive_findings.py` is a local stand-in that implements it).

The agent is a client only. It never listens for inbound connections and never
receives commands — it registers, heartbeats, and pushes normalized findings.

- **Transport:** HTTP/HTTPS, JSON bodies (`Content-Type: application/json`)
- **Auth:** `Authorization: Bearer <agent_token>` on every request
- **Versioning:** the findings envelope carries `schema_version` (currently `1.0`)

---

## Endpoints

### `POST /api/v1/agents/register`

Announce the agent and its capabilities. Idempotent — safe to call on every start.

Request:
```json
{
  "agent_id": "agent-host01",
  "hostname": "host01",
  "ip_address": "10.0.0.12",
  "os": "Linux 6.5.0",
  "agent_version": "0.1.0",
  "capabilities": ["image_scan", "docker_image_list", "sbom"]
}
```
Response `201`:
```json
{ "status": "registered", "agent_id": "agent-host01", "server_time": "2026-07-07T09:00:00Z" }
```

### `POST /api/v1/agents/heartbeat`

Liveness signal, sent every `intervals.heartbeat_seconds`.

Request:
```json
{ "agent_id": "agent-host01", "status": "online", "ts": "2026-07-07T09:01:00Z" }
```
Response `200`:
```json
{ "status": "ok", "server_time": "2026-07-07T09:01:00Z" }
```

### `POST /api/v1/findings`

Push one **normalized findings envelope** per scanned target.

Response `202`:
```json
{ "status": "accepted", "batch_id": "batch-00001", "received": 3 }
```
Errors: `401` (bad token), `400` (bad JSON), `422` (schema validation — missing
envelope or finding fields).

---

## Findings envelope (`schema_version: 1.0`)

This is the stable contract. Fields the agent guarantees:

```json
{
  "schema_version": "1.0",
  "agent_id": "agent-host01",
  "hostname": "host01",
  "scan": {
    "target": "nginx:1.25",
    "target_type": "container_image",
    "scanner": "trivy",
    "scanner_version": "0.29.2",
    "started_at": "2026-07-07T09:05:00Z",
    "completed_at": "2026-07-07T09:05:12Z"
  },
  "findings": [
    {
      "id": "CVE-2023-1234|libssl3|nginx:1.25",
      "vulnerability_id": "CVE-2023-1234",
      "package": "libssl3",
      "installed_version": "3.0.2-0ubuntu1.10",
      "fixed_version": "3.0.2-0ubuntu1.12",
      "severity": "HIGH",
      "title": "openssl: X.509 verification ...",
      "primary_url": "https://avd.aquasec.com/nvd/cve-2023-1234",
      "target": "nginx:1.25",
      "class": "os-pkgs",
      "cvss_score": 7.5
    }
  ],
  "summary": { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "total": 1 }
}
```

### The `id` (dedupe key)

`id = vulnerability_id | package | target`

The same CVE can appear in multiple packages of one image; keying on the CVE
alone would collapse them. MORI relies on this composite key for cross-scan and
cross-asset dedup, and it matches the key the platform's diff logic uses. The
agent also emits findings in a deterministic order (severity, then `id`) so two
identical scans produce byte-identical envelopes.

### Field notes
- `severity` ∈ `CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN` (upper-cased).
- `fixed_version` empty string ⇒ no fix available yet.
- `cvss_score` prefers NVD, then Red Hat, then any vendor V3 base score; `null` if none.
- `class` is Trivy's result class (`os-pkgs`, `lang-pkgs`, ...).

---

## What the agent does NOT do

- No triage, dedup across assets, or risk scoring — MORI's responsibility.
- No AI calls — remediation drafts are generated centrally.
- No inbound listener, no remote command execution.

See [MORI_INTEGRATION.md](MORI_INTEGRATION.md) and [SECURITY_MODEL.md](SECURITY_MODEL.md).
