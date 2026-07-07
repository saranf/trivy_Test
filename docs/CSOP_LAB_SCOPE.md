# CSOP Lab Scope

The **CSOP Legacy UI** (`webserver/`, `auto_scan/`, `grafana/`, `loki/`,
`prometheus/`, `promtail/`, `falco/`) is **not** the product direction and is not
production-ready. It is retained as a **sandbox** to prototype features in a UI
before the stable ones are moved into MORI-SOC.

> CSOP Legacy UI is kept as an experimental sandbox for MORI-SOC features.
> It is not the product direction and is not production-ready.
> New production-oriented work focuses on the lightweight Trivy Agent
> (`agent/`) and MORI integration (`server_mock/`, `docs/`).

Positioning: **MORI-SOC is the product. `trivy_Test` is the lab. CSOP is the UI sandbox.**

---

## Allowed experiments

- Trivy scan history
- **Scan diff** (New / Fixed / Unchanged / Reopened / Severity-changed …)
- CVE / finding lifecycle state
- AI remediation **draft** (human-approved, central-only)
- Evidence CSV export
- MORI import/export adapter

## Non-goals

- Production RBAC
- Production deployment
- Rebuilding the MORI UI
- Storing real secrets
- Remote command execution
- **Agent-side AI** (AI runs centrally in MORI, never in the agent)

---

## Priority order

1. This scope doc ✅
2. Keep/clean the **Scan Run History** screen in the CSOP UI
3. **Trivy Scan Diff V2** feature ✅ — `csop_scan_diff.php` + `calculateScanDiffV2`
4. Diff → **CSV export** ✅ — `api/scan_diff_export.php?format=csv`
5. Build the **MORI evidence envelope** ✅ — `buildMoriEvidenceEnvelope` (`mori.trivy.findings.v1`)
6. Wire to MORI — **raw report → `POST /ingest/trivy`** (MORI normalizes; see
   [MORI_INTEGRATION.md](MORI_INTEGRATION.md)). Not `/api/v1/findings` (that's the
   server_mock dev protocol).
7. Finding **lifecycle** states ✅ — `csop_finding_lifecycle.php` + `finding_lifecycle`
   table (`open/reviewing/mitigated/accepted_risk/false_positive/fixed/reopened`,
   risk_decision + owner + evidence fields)
8. Zabbix-triggered scenario ✅ (context view) — `csop_zabbix_context.php`
   pulls MORI `/zabbix/hosts` + `/vulnerabilities/risk-summary` and correlates
   with CSOP Trivy scans. (Next: explicit host↔image mapping for auto-linking.)

Test plan for all of the above: [TEST_SCENARIOS.md](TEST_SCENARIOS.md).

---

## Feature 1 (priority): Trivy Scan Diff

Compare two scans of the same target and classify each finding:

```
Scan A vs Scan B
- New CVEs
- Fixed CVEs
- Unchanged CVEs
- Reopened / Reintroduced CVEs
- Severity changed
- Fixed version changed
- Package version changed
```

Example:

```
nginx:1.25
Previous scan: 18 CVEs
Current scan:  12 CVEs

New: 2 · Fixed: 8 · Still open: 10 · Critical still open: 1
```

This maps directly onto MORI:

```
Trivy diff → risk score change → remediation progress → audit evidence
           → "before/after remediation" report
```

It fits ISMS-P / ISO 27001 evidence well: *there was a vulnerability, it was
remediated, the count went down.*

> Consistency note: the diff key is `vulnerability_id | package | target`. The
> same CVE can appear in multiple packages of one image; keying on the CVE alone
> collapses them. This is the same composite key the agent emits
> (`docs/AGENT_PROTOCOL.md`) and the same bug fixed in `calculateScanDiff`.

---

## Feature 2: Finding Lifecycle

Experiment with CVE state transitions in the CSOP UI, then carry the model into MORI:

```
open → reviewing → mitigated → fixed
                 → accepted_risk
                 → false_positive
open ← reopened (regression)
```

`accepted_risk` is the most valuable state for audits — *why it was not fixed*
is itself evidence. Suggested fields:

```
risk_decision : mitigate / accept / transfer / avoid
decision_reason
owner
due_date
review_date
evidence_note
```

Maps cleanly onto MORI's risk register.

---

## Feature 3: CVE Diff Evidence Export

Start with JSON/CSV (PDF later). Columns:

```
scan_diff_2026-07-07.csv
image, package, cve, previous_status, current_status,
severity, fixed_version, evidence_time
```

Flow: `CSOP diff export → MORI evidence import → audit report section`.
High portfolio value for low implementation cost.

---

## Feature 4: AI Remediation Draft (central-only)

Prototype in the CSOP UI, but AI **only drafts** — never auto-remediates:

```
CVE + package + image + fixed_version
  → remediation draft
  → human accept / edit / reject
  → stored as a MORI evidence note
```

The operator makes the final call. No AI keys in the agent.

---

## Feature 5: Zabbix-triggered Trivy Scan

```
1. Zabbix raises a host problem
2. MORI marks the host high-risk
3. Trivy Agent scans that host's container images
4. CSOP UI shows the scan result / diff
5. MORI reflects risk + evidence
```

This is where Zabbix + Trivy + MORI read as one story.

---

## Minimal DB model (for diff experiments)

```sql
scan_runs
  id, agent_id, hostname, target, image_name, image_digest,
  started_at, finished_at, trivy_version, status

findings
  id, scan_run_id, vulnerability_id, package_name,
  installed_version, fixed_version, severity, cvss_score,
  target, primary_url

finding_deltas
  id, previous_scan_run_id, current_scan_run_id,
  vulnerability_id, package_name, delta_type,
  previous_severity, current_severity
```

`delta_type ∈ { new, fixed, unchanged, severity_changed, version_changed, reopened }`

This is enough to experiment before wiring MORI. (The current CSOP schema in
`webserver/src/db_functions.php` uses `scan_history` / `scan_vulnerabilities`;
`scan_runs` / `findings` / `finding_deltas` is the target shape to converge on.)

---

## MORI import envelope

The envelope CSOP hands to MORI (a diff-aware superset of the agent envelope):

```json
{
  "schema_version": "mori.trivy.findings.v1",
  "source": "trivy-agent",
  "agent_id": "agent-host-001",
  "hostname": "demo-linux-01",
  "scan_run_id": "scan-20260707-001",
  "target": "nginx:1.25",
  "summary": { "new": 2, "fixed": 8, "unchanged": 10, "critical": 1, "high": 4 },
  "findings": [
    {
      "vulnerability_id": "CVE-2026-XXXX",
      "package_name": "openssl",
      "installed_version": "1.1.1",
      "fixed_version": "1.1.1x",
      "severity": "HIGH",
      "delta_type": "new"
    }
  ]
}
```

MORI reflects this into `vulnerabilities`, `risk_register`, `evidence_events`,
and `asset_security_summary`.

---

## Hard don'ts (even while keeping CSOP)

- Describe CSOP as a main product on par with MORI
- Rebuild large CSOP RBAC
- Revive Slack / Email / Google-Sheets alerting as a headline
- Bring back the full Grafana / Loki / Prometheus stack as the main thing
- Regress the agent to a **central-command** model — the agent stays
  **outbound push only** (see `docs/SECURITY_MODEL.md`)
- Put AI / Gemini keys inside the agent
