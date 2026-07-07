# Test Scenarios

End-to-end test plan for the Trivy Agent Lab: what to test **locally** (no MORI),
and how to test the **MORI-SOC connection**. Grounded in the real MORI API
(`POST /ingest/trivy`, verified live).

Legend: **[verified]** = confirmed in this repo's environment · **[run]** = you
execute it · **⚠ writes** = mutates real MORI/postgres data.

---

## Part A — Local tests (no MORI)

### A1. Agent unit / normalization [verified]

Pure-logic checks (no docker/trivy needed): config parse, deterministic
normalization, composite dedupe key, mock register/heartbeat/findings + auth.

```bash
python3 <scratch>/smoke.py     # or re-create from agent/ functions
```
Expected: minimal-YAML parse OK · same CVE in two packages kept separate ·
identical scans → byte-identical envelopes · bad token → 401 · malformed
envelope → 422.

### A2. Agent → server_mock, native [run]

```bash
# terminal 1
python3 server_mock/receive_findings.py --port 8080 --token testtok
# terminal 2
cp agent/config.example.yaml agent/config.yaml       # targets: ["alpine:3.19"]
MORI_AGENT_TOKEN=testtok python3 agent/trivy_agent.py --config agent/config.yaml --once
```
Pass: `registered …` → `pushed N findings …`; a file appears in
`server_mock/received/`. Needs `trivy` + `docker` on PATH.

### A3. Agent → server_mock, container [verified]

```bash
docker build -t trivy-agent-lab agent/
# start the mock on the host first (A2 terminal 1), then:
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/agent/config.yaml":/opt/agent/config.yaml:ro \
  --add-host host.docker.internal:host-gateway \
  -e MORI_SERVER_URL=http://host.docker.internal:8080 \
  -e MORI_AGENT_TOKEN=testtok \
  trivy-agent-lab --once
```
Verified result: `pushed 10 findings for alpine:3.19 (batch batch-00001)` →
`202 accepted`, envelope persisted. Full run notes: [RUNNING_THE_AGENT.md](RUNNING_THE_AGENT.md).

### A4. Diff correctness — composite key [verified]

The bug that keying by CVE alone collapses a CVE present in multiple packages.
Real data confirms it: scanning `alpine:3.19`, `CVE-2026-40200` appears in **both**
`musl` and `musl-utils` and both survive as
`CVE-2026-40200|musl|…` and `CVE-2026-40200|musl-utils|…`.

CSOP backend (`calculateScanDiffV2`) verified against MySQL with data covering
every delta type:
```
counts: new=3 fixed=1 unchanged=1 severity_changed=1 version_changed=1 reopened=1
CVE-DUP in two packages → not collapsed ✓ · severity MEDIUM→HIGH carried ✓
```

### A5. CSOP sandbox — Scan Diff V2 UI [run ⚠ heavy]

Bring up the CSOP stack and exercise the diff/export UI.

```bash
docker-compose up -d --build mysql webserver nginx
# open http://localhost:6987/csop_scan_diff.php  (login admin/admin123 if gated)
```
Steps:
1. Scan the same image twice (`container_scan.php`) so it has ≥2 scans.
2. Open **Scan Diff V2**, pick the image → before/after selects auto-compare.
3. Check count cards: New / Reopened / Fixed / Sev Δ / Ver Δ / Unchanged.
4. Toggle the **Critical/High** and **변경분만** filters.
5. Click **⬇ MORI Evidence JSON** → downloads `mori_trivy_findings_*.json`
   (`schema_version: mori.trivy.findings.v1`).
6. Click **⬇ CSV** → downloads `scan_diff_*.csv`.

Export API directly:
`GET /api/scan_diff_export.php?old=<id>&new=<id>&format=json|csv`.

---

## Part B — MORI-SOC connection tests

MORI ingests a **raw Trivy report** at `POST /ingest/trivy` (it normalizes
internally). See [MORI_INTEGRATION.md](MORI_INTEGRATION.md).

Base URL used here: `http://127.0.0.1:18000` (adjust to your MORI).

### B1. Contract / reachability [verified]

```bash
curl -s http://127.0.0.1:18000/health
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18000/trivy/vulnerabilities   # 200
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:18000/ingest/trivy \
     -H 'Content-Type: application/json' -d '{"Results":[]}'                             # 401 (auth gate)
```
Verified: GET reads → `200`; unauth ingest → `401`.

### B2. Enable an ingest token [run — MORI config]

The running MORI has `MORI_INGEST_TOKEN` **unset** (so ingest needs a login
session). For agent/automation, set a token and restart MORI's api:

```bash
# in the MORI-SOC compose: add to the api service env, then recreate it
MORI_INGEST_TOKEN=lab-ingest-token
docker compose up -d mori-api      # (from the mori-soc project)
```
`MORI_DATABASE_URL` is already set (postgres reachable), so ingest can persist.

Alternative without a token: `POST /auth/login` and reuse the session cookie.

### B3. Raw Trivy ingest [run ⚠ writes to MORI postgres]

Use a throwaway image so you can identify/clean the test data.

```bash
trivy image --format json alpine:3.19 > /tmp/report.json
curl -s -X POST http://127.0.0.1:18000/ingest/trivy \
     -H "X-MORI-Token: lab-ingest-token" \
     -H "Content-Type: application/json" \
     --data-binary @/tmp/report.json | jq .
```
Pass: `{ "ok": true, "records_collected": N, "entities_saved": M, "artifact": "alpine:3.19" }`.
Failure modes to recognize: `401` (token), `503` (no `MORI_DATABASE_URL`),
`400` (body lacks `Results`).

### B4. Verify it landed [run]

```bash
curl -s http://127.0.0.1:18000/trivy/vulnerabilities | jq '.count, .by_host'
curl -s http://127.0.0.1:18000/vulnerabilities/risk-summary | jq '.by_level'
```
Pass: `count` / risk levels increased vs the B1 baseline.

### B5. Agent → MORI (the gap) [run]

The agent currently targets the **normalized** `/api/v1/findings` (server_mock),
which MORI does **not** expose. Two ways to close it:

- **Now (bridge):** pipe the agent's scan to MORI —
  `trivy image -f json <img> | curl -X POST …/ingest/trivy -H "X-MORI-Token: …" --data-binary @-`.
- **Next (code):** add a `push.mode: mori_raw` to the agent that POSTs the raw
  report to `/ingest/trivy`. Tracked as follow-up.

### B6. Zabbix correlation walkthrough [run]

```bash
curl -s http://127.0.0.1:18000/zabbix/hosts | jq '.hosts[0]'
curl -s http://127.0.0.1:18000/assets       | jq '.[0] // .'
```
Story: pick a host with a Zabbix problem → scan its image → ingest (B3) →
re-check `risk-summary` (B4) → set a plan/exception via
`PUT /vulnerabilities/{id}/plan|exception`.

### B7. Cleanup [run ⚠]

Ingest writes to the real MORI postgres. After testing, remove the throwaway
rows (e.g. by `ArtifactName = 'alpine:3.19'`) from the MORI DB, or run against a
disposable MORI instance. Prefer a dedicated test host/image label so cleanup is
unambiguous.

---

## Part C — Full story (manual acceptance)

Confirms the portfolio narrative end-to-end:

```
Zabbix problem on a host
  → MORI marks the host high-risk            (GET /zabbix/hosts, /assets)
  → Trivy Agent scans the host's image       (agent A2/A3)
  → CSOP Scan Diff V2 shows before/after      (A5)
  → export MORI evidence JSON                 (A5 step 5)
  → raw report ingested into MORI             (B3)
  → risk/plan/exception reflected in MORI     (B4, B6)
```

Each arrow maps to a scenario above; run them in order for a demo/interview walk.

---

## Status snapshot

| Area | State |
|---|---|
| Agent normalize / mock protocol | verified (A1–A3) |
| Composite-key diff (agent + CSOP) | verified (A4) |
| CSOP Scan Diff V2 + export | logic verified; UI needs stack up (A5) |
| MORI read + auth gate | verified (B1) |
| MORI raw ingest round-trip | ready to run (B3–B4) — writes real data |
| Agent → MORI direct | gap; bridge available (B5) |
