# Security Model

Why the agent is intentionally small, read-only, and deterministic — and what
that buys operationally.

---

## Principles

1. **Read-only.** The agent only reads: it lists docker images and runs `trivy`
   (a read-only scanner). It never writes to the host, never mutates containers,
   never executes remote commands.
2. **Deterministic.** The same inputs produce the same normalized output —
   stable dedupe keys (`vuln|package|target`) and sorted findings. No timestamps
   or randomness leak into the finding identity. This makes central dedup/diff
   correct and makes the agent easy to test.
3. **No intelligence at the edge.** No AI keys, no policy, no asset inventory, no
   risk decisions. The only secret it holds is its own push token.
4. **Client-only.** No inbound listener. Nothing can be pushed *to* the agent, so
   there is no remote-command attack surface.

> The agent remains lightweight and deterministic. AI-assisted remediation runs
> centrally after findings are normalized and stored.

---

## Trust boundaries

```
   ┌─────────────── host (low trust) ───────────────┐
   │  trivy_agent.py  ──reads──▶ docker.sock, trivy  │
   │        │ push (Bearer token, TLS)               │
   └────────┼────────────────────────────────────────┘
            ▼
   ┌─────── MORI-SOC / central API (high trust) ─────┐
   │  auth · dedup · risk scoring · AI · evidence     │
   └──────────────────────────────────────────────────┘
```

A compromised agent can, at worst, submit bogus findings under its own token —
it cannot reach into the host or into MORI's decision logic. Central validation
(`schema_version`, required fields, per-agent token) contains that blast radius.

---

## Threats & mitigations

| Threat | Mitigation |
|---|---|
| Token theft from disk | Token via env var / root-only `EnvironmentFile`, not `config.yaml` (see `.gitignore`); rotate per agent |
| Findings tampering in transit | HTTPS + `verify_tls: true` (default); bearer auth |
| Rogue agent flooding findings | Per-agent token allows central rate-limit / revoke; envelope schema validation rejects malformed input |
| Agent used as a pivot | No inbound listener; `docker.sock` is read-only in practice (list/scan only); systemd hardening (below) |
| Supply-chain of the agent itself | Stdlib-only, tiny surface; pin the `trivy` version; review-friendly single file |

---

## Least-privilege deployment

The shipped `agent/systemd/trivy-agent.service` runs the agent as a dedicated
unprivileged `trivy-agent` user with:

- `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`
- `PrivateTmp=true`, `ProtectKernelTunables=true`, `ProtectControlGroups=true`
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`
- Only `docker` group membership (to read the socket) — no root.

Docker-socket note: mounting `docker.sock` is powerful (socket access ≈ host
root). The agent only *reads* through it, but the socket itself remains a
sensitive dependency — keep the agent host isolated and the token scoped. A
future hardening step is to front the socket with a read-only proxy
(e.g. `docker-socket-proxy`) exposing only `images`/`containers` list endpoints.

---

## Explicit non-goals

Consistent with the project's scope (see the repo README):

- No web UI, RBAC, or dashboards in the agent.
- No AI at the edge.
- Not marketed as a production-ready security platform — this is an agent /
  integration lab for MORI-SOC.
