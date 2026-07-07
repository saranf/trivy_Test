# Running the Agent

Three ways to run the Trivy Agent (`agent/trivy_agent.py`). The agent is
outbound-push-only: it registers, heartbeats, scans, and pushes normalized
findings to a central API (MORI, or `server_mock/` in dev). See
[AGENT_PROTOCOL.md](AGENT_PROTOCOL.md) for the wire format.

## Prerequisites

- **Native run:** `python3` (3.9+), plus `trivy` and `docker` on `PATH` (the
  agent shells out to both). PyYAML optional — a built-in parser handles the
  shipped config if it's absent.
- **Container run:** just Docker. Trivy is bundled in the image.

---

## Method 1 — Python script (native)

```bash
# 1) config (edit server.url and scan.targets; keep the token out of the file)
cp agent/config.example.yaml agent/config.yaml

# 2) central API stand-in (MORI mock)
python3 server_mock/receive_findings.py --port 8080 --token testtok

# 3) one scan cycle
MORI_AGENT_TOKEN=testtok \
  python3 agent/trivy_agent.py --config agent/config.yaml --once
```

Flags:

| Flag | Effect |
|---|---|
| *(none)* | Run loop: heartbeat every `heartbeat_seconds`, scan every `scan_seconds` |
| `--once` | One heartbeat + scan cycle, then exit |
| `--register-only` | Register and exit (connectivity check) |
| `--dry-run` | Print normalized envelopes to stdout instead of pushing |

Env overrides (win over `config.yaml`, so secrets stay out of the file):
`MORI_SERVER_URL`, `MORI_AGENT_TOKEN`, `MORI_AGENT_ID`.

---

## Method 2 — Container (no local Trivy needed)

This is the verified path — the image bundles Trivy + docker-cli on the official
`aquasec/trivy` base.

```bash
docker build -t trivy-agent-lab agent/

docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/agent/config.yaml":/opt/agent/config.yaml:ro \
  --add-host host.docker.internal:host-gateway \
  -e MORI_SERVER_URL=http://host.docker.internal:8080 \
  -e MORI_AGENT_TOKEN=testtok \
  trivy-agent-lab --once
```

- `--add-host host.docker.internal:host-gateway` lets the container reach a mock
  server running on the host (needed on Linux; already present on Docker Desktop).
- The docker-socket mount lets the agent enumerate/scan host images. It only
  **reads** through the socket.
- Drop `--once` to run the agent as a long-lived loop.

Verified run (real Trivy):

```
[INFO] registered as agent-lab-test
[INFO] scan cycle: 1 image(s), trivy 0.50.1
[INFO] pushed 10 findings for alpine:3.19 (batch batch-00001)
```

---

## Method 3 — systemd (long-running host daemon)

For a real host, run natively under systemd with the shipped hardened unit.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin trivy-agent
sudo usermod -aG docker trivy-agent

sudo mkdir -p /opt/trivy-agent /etc/trivy-agent
sudo cp agent/trivy_agent.py /opt/trivy-agent/
sudo cp agent/config.example.yaml /etc/trivy-agent/config.yaml   # then edit
sudo cp agent/systemd/trivy-agent.service /etc/systemd/system/

# put the token in the environment, not the config file
echo 'MORI_AGENT_TOKEN=your-real-token' | sudo tee /etc/trivy-agent/agent.env
# then in the unit, swap Environment= for: EnvironmentFile=/etc/trivy-agent/agent.env

sudo systemctl daemon-reload
sudo systemctl enable --now trivy-agent
sudo systemctl status trivy-agent
journalctl -u trivy-agent -f
```

The unit already applies `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`, and restricts address families — see
[SECURITY_MODEL.md](SECURITY_MODEL.md).

---

## Config reference (`agent/config.example.yaml`)

```yaml
server:
  url: "http://localhost:8080"   # central API (MORI or server_mock)
  token: "change-me-agent-token" # prefer MORI_AGENT_TOKEN env instead
  verify_tls: true               # set false only for local/self-signed dev

agent:
  id: ""                         # empty → "agent-<hostname>"
  labels: { env: "lab", team: "mori-soc" }

scan:
  targets: "all_local"           # or an explicit list: ["nginx:1.25", "redis:7"]
  severity: ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
  max_images: 0                  # 0 = no cap

push:
  mode: "mock"                   # mock → server_mock /api/v1/findings
                                 # mori_raw → MORI /ingest/trivy (raw report; MORI normalizes)
  ingest_path: "/ingest/trivy"

intervals:
  heartbeat_seconds: 60
  scan_seconds: 900
```

**Feeding real MORI:** set `push.mode: mori_raw`, point `server.url` at MORI
(`http://<host>:18000`), and put the `MORI_INGEST_TOKEN` in `server.token` (sent
as Bearer). Register/heartbeat are skipped in this mode. See
[MORI_INTEGRATION.md](MORI_INTEGRATION.md).

> Scanning `all_local` on a busy host enumerates **every** local image and can be
> slow. Pin `scan.targets` to an explicit list (or set `max_images`) for tests.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `registration failed (0)` | Central API unreachable. Check `server.url`; from a container use `host.docker.internal`. |
| `401` on push | Token mismatch between agent and server (`MORI_AGENT_TOKEN` vs `--token`). |
| First scan is slow | Trivy downloads its vuln DB on first run (needs network). Subsequent scans are fast. |
| `docker images failed` / `command not found: docker` | Native run without docker-cli, or the socket isn't mounted in the container. |
| `command not found: trivy` (native) | Install Trivy, or use Method 2 (container bundles it). |
| Scans take forever | `targets: all_local` on a host with many images — pin `targets` / `max_images`. |
