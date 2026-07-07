#!/usr/bin/env python3
"""
server_mock/receive_findings.py — a local stand-in for the MORI-SOC central API.

It implements the agent-facing wire protocol (see docs/AGENT_PROTOCOL.md) so the
agent can be developed and tested without a real MORI backend. It deliberately
does NOT do triage, dedup, risk scoring, or AI — those are MORI's job. It only
validates the envelope, stores it, and acknowledges.

Stdlib only. Run:
    python3 server_mock/receive_findings.py --port 8080 --token change-me-agent-token
Data is written under ./server_mock/received/ (one file per findings batch).
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {
    "token": None,
    "outdir": None,
    "agents": {},      # agent_id -> last register/heartbeat info
    "batch_seq": 0,
}

REQUIRED_ENVELOPE = ("schema_version", "agent_id", "scan", "findings", "summary")
REQUIRED_FINDING = ("id", "vulnerability_id", "package", "severity", "target")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Handler(BaseHTTPRequestHandler):
    # quieter, structured logging
    def log_message(self, fmt, *a):
        sys.stderr.write("[%s] %s\n" % (now_iso(), fmt % a))

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth_ok(self):
        if not STATE["token"]:
            return True
        got = self.headers.get("Authorization", "")
        return got == "Bearer %s" % STATE["token"]

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw.decode("utf-8")) if raw else {}

    def do_POST(self):
        if not self._auth_ok():
            return self._json(401, {"error": "invalid or missing bearer token"})
        try:
            payload = self._read_json()
        except (ValueError, json.JSONDecodeError):
            return self._json(400, {"error": "invalid JSON body"})

        path = self.path.split("?", 1)[0]   # ignore query (e.g. ?hostname=)
        if path == "/api/v1/agents/register":
            return self._register(payload)
        if path == "/api/v1/agents/heartbeat":
            return self._heartbeat(payload)
        if path == "/api/v1/findings":
            return self._findings(payload)
        if path == "/ingest/trivy":
            return self._ingest_trivy(payload)
        if path == "/ingest/evidence":
            return self._ingest_evidence(payload)
        return self._json(404, {"error": "unknown endpoint: %s" % path})

    def do_GET(self):
        # tiny read-only introspection for humans/tests
        if self.path == "/api/v1/agents":
            return self._json(200, {"agents": STATE["agents"]})
        if self.path in ("/", "/health"):
            return self._json(200, {"status": "ok", "agents": len(STATE["agents"])})
        return self._json(404, {"error": "not found"})

    # --- handlers ------------------------------------------------------------
    def _register(self, p):
        aid = p.get("agent_id")
        if not aid:
            return self._json(400, {"error": "agent_id required"})
        STATE["agents"][aid] = {
            "hostname": p.get("hostname"),
            "ip_address": p.get("ip_address"),
            "os": p.get("os"),
            "agent_version": p.get("agent_version"),
            "capabilities": p.get("capabilities", []),
            "registered_at": now_iso(),
            "last_heartbeat": None,
        }
        self.log_message("registered agent %s (%s)", aid, p.get("hostname"))
        return self._json(201, {"status": "registered", "agent_id": aid, "server_time": now_iso()})

    def _heartbeat(self, p):
        aid = p.get("agent_id")
        if aid not in STATE["agents"]:
            # accept-and-track even if we missed the register (mock is lenient)
            STATE["agents"][aid] = {"registered_at": None}
        STATE["agents"][aid]["last_heartbeat"] = now_iso()
        return self._json(200, {"status": "ok", "server_time": now_iso()})

    def _findings(self, p):
        missing = [k for k in REQUIRED_ENVELOPE if k not in p]
        if missing:
            return self._json(422, {"error": "missing envelope fields: %s" % ", ".join(missing)})
        bad = _validate_findings(p.get("findings", []))
        if bad:
            return self._json(422, {"error": bad})

        STATE["batch_seq"] += 1
        batch_id = "batch-%05d" % STATE["batch_seq"]
        self._persist(batch_id, p)

        s = p["summary"]
        self.log_message(
            "findings %s from %s target=%s total=%s (C%s/H%s/M%s/L%s)",
            batch_id, p.get("agent_id"), p["scan"].get("target"),
            s.get("total"), s.get("CRITICAL", 0), s.get("HIGH", 0),
            s.get("MEDIUM", 0), s.get("LOW", 0),
        )
        return self._json(202, {"status": "accepted", "batch_id": batch_id,
                                "received": s.get("total", len(p["findings"]))})

    def _ingest_trivy(self, p):
        # Stand-in for MORI's POST /ingest/trivy: accepts a RAW Trivy report
        # (must have "Results") and mimics its response shape.
        if not isinstance(p, dict) or "Results" not in p:
            return self._json(400, {"error": "body must be a Trivy JSON report (with 'Results')"})
        nvulns = sum(len(r.get("Vulnerabilities") or []) for r in (p.get("Results") or []))
        STATE["batch_seq"] += 1
        batch_id = "ingest-%05d" % STATE["batch_seq"]
        self._persist(batch_id, p)
        self.log_message("ingest/trivy %s artifact=%s records=%s",
                         batch_id, p.get("ArtifactName"), nvulns)
        return self._json(200, {"ok": True, "records_collected": nvulns,
                                "entities_saved": nvulns, "artifact": p.get("ArtifactName")})

    def _ingest_evidence(self, p):
        # Stand-in for MORI's POST /ingest/evidence: accepts the CSOP diff
        # envelope (mori.trivy.findings.v1), single or {"events":[...]} batch.
        events = p.get("events") if isinstance(p, dict) and "events" in p else [p]
        stored = 0
        for ev in events:
            if not isinstance(ev, dict) or "findings" not in ev:
                return self._json(422, {"error": "evidence envelope must have 'findings'"})
            STATE["batch_seq"] += 1
            self._persist("evidence-%05d" % STATE["batch_seq"], ev)
            stored += 1
        self.log_message("ingest/evidence stored=%s (findings=%s)",
                         stored, sum(len(e.get("findings") or []) for e in events))
        return self._json(200, {"ok": True, "stored": stored})

    def _persist(self, batch_id, envelope):
        if not STATE["outdir"]:
            return
        # normalized envelope → scan.target; raw Trivy report → ArtifactName;
        # evidence envelope → top-level target
        target = (envelope.get("scan", {}) or {}).get("target") \
            or envelope.get("target") or envelope.get("ArtifactName") or "unknown"
        safe_target = str(target).replace("/", "_").replace(":", "_")
        fname = "%s_%s.json" % (batch_id, safe_target)
        with open(os.path.join(STATE["outdir"], fname), "w", encoding="utf-8") as fh:
            json.dump(envelope, fh, indent=2, ensure_ascii=False)


def _validate_findings(findings):
    if not isinstance(findings, list):
        return "findings must be a list"
    for i, f in enumerate(findings):
        for k in REQUIRED_FINDING:
            if k not in f:
                return "finding[%d] missing field: %s" % (i, k)
    return None


def main():
    ap = argparse.ArgumentParser(description="MORI-SOC findings mock server")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--token", default=os.environ.get("MORI_AGENT_TOKEN", ""),
                    help="expected bearer token ('' disables auth)")
    ap.add_argument("--outdir", default=os.path.join(os.path.dirname(__file__), "received"))
    args = ap.parse_args()

    STATE["token"] = args.token or None
    STATE["outdir"] = args.outdir
    os.makedirs(args.outdir, exist_ok=True)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    sys.stderr.write("[%s] mock MORI API on http://%s:%d (auth: %s, out: %s)\n"
                     % (now_iso(), args.host, args.port,
                        "on" if STATE["token"] else "off", args.outdir))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nshutting down\n")
        srv.shutdown()


if __name__ == "__main__":
    main()
