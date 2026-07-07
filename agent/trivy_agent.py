#!/usr/bin/env python3
"""
Trivy Agent Lab for MORI-SOC — lightweight scanner agent.

Design principle: the agent is read-only and deterministic.
It scans → collects → normalizes → pushes. It holds no AI keys and makes
no risk/triage decisions — that happens centrally in MORI/API after findings
are normalized and stored.

Stdlib only (Python 3.9+). PyYAML is used if available, otherwise a minimal
built-in loader parses the shipped config shape.

Usage:
    trivy_agent.py --config /etc/trivy-agent/config.yaml        # run loop
    trivy_agent.py --config config.yaml --once                  # one cycle, exit
    trivy_agent.py --config config.yaml --once --dry-run        # print, don't push
    trivy_agent.py --config config.yaml --register-only         # register + exit
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

AGENT_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0"
CAPABILITIES = ["image_scan", "docker_image_list", "sbom"]

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def log(level, msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print("[%s] %s %s" % (ts, level.ljust(5), msg), file=sys.stderr, flush=True)


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_cmd(args, timeout=600):
    """Run a read-only command, return (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except FileNotFoundError:
        return 127, "", "command not found: %s" % args[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %ss: %s" % (timeout, " ".join(args))


def local_ip():
    """Best-effort primary IP without touching the network for real."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# config loading (PyYAML if present, else a minimal indent-based loader)
# --------------------------------------------------------------------------- #
def _minimal_yaml(text):
    """Parse the subset of YAML this project's config uses:
    nested mappings by indentation, `key: value`, inline flow lists `[a, b]`,
    quoted/unquoted scalars, bool/int/null. For anything richer, install PyYAML.
    """
    root = {}
    stack = [(-1, root)]  # (indent, container)

    def coerce(v):
        v = v.strip()
        if v == "" or v == "~" or v.lower() == "null":
            return None
        if v.lower() in ("true", "false"):
            return v.lower() == "true"
        if (v[0], v[-1]) in (('"', '"'), ("'", "'")):
            return v[1:-1]
        if v.startswith("[") and v.endswith("]"):
            inner = v[1:-1].strip()
            if not inner:
                return []
            return [coerce(x) for x in inner.split(",")]
        try:
            return int(v)
        except ValueError:
            return v

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip() if "#" in raw and not _in_quotes(raw) else raw.rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        key, _, val = line.strip().partition(":")
        key = key.strip()
        if val.strip() == "":
            child = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = coerce(val)
    return root


def _in_quotes(line):
    # crude guard so a '#' inside a quoted scalar is not treated as a comment
    return line.count('"') % 2 == 1 or line.count("'") % 2 == 1


def load_config(path):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    try:
        import yaml  # type: ignore
        cfg = yaml.safe_load(text) or {}
    except ImportError:
        cfg = _minimal_yaml(text)
    return apply_env_overrides(cfg)


def apply_env_overrides(cfg):
    """Env vars win over the file so secrets can stay out of config.yaml."""
    cfg.setdefault("server", {})
    cfg.setdefault("agent", {})
    cfg.setdefault("scan", {})
    cfg.setdefault("intervals", {})
    if os.environ.get("MORI_SERVER_URL"):
        cfg["server"]["url"] = os.environ["MORI_SERVER_URL"]
    if os.environ.get("MORI_AGENT_TOKEN"):
        cfg["server"]["token"] = os.environ["MORI_AGENT_TOKEN"]
    if os.environ.get("MORI_AGENT_ID"):
        cfg["agent"]["id"] = os.environ["MORI_AGENT_ID"]
    return cfg


# --------------------------------------------------------------------------- #
# HTTP client (bearer-token, JSON)
# --------------------------------------------------------------------------- #
class ApiClient:
    def __init__(self, base_url, token, verify_tls=True):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.verify_tls = verify_tls

    def post(self, path, payload):
        url = self.base_url + path
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "trivy-agent-lab/%s" % AGENT_VERSION)
        if self.token:
            req.add_header("Authorization", "Bearer %s" % self.token)
        ctx = None
        if url.startswith("https") and not self.verify_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                data = resp.read().decode("utf-8", "replace")
                return resp.status, json.loads(data) if data.strip() else {}
        except urllib.error.HTTPError as e:
            return e.code, {"error": e.read().decode("utf-8", "replace")}
        except urllib.error.URLError as e:
            return 0, {"error": str(e.reason)}


# --------------------------------------------------------------------------- #
# collection + scanning (read-only)
# --------------------------------------------------------------------------- #
def list_local_images(max_images=0):
    """Enumerate local docker images as 'repo:tag', skipping <none>."""
    rc, out, err = run_cmd(["docker", "images", "--format", "{{json .}}"])
    if rc != 0:
        log("WARN", "docker images failed: %s" % err.strip())
        return []
    images = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        repo, tag = row.get("Repository", ""), row.get("Tag", "")
        if repo == "<none>" or tag == "<none>" or not repo:
            continue
        images.append("%s:%s" % (repo, tag))
    images = sorted(set(images))
    if max_images and max_images > 0:
        images = images[:max_images]
    return images


def trivy_version():
    rc, out, _ = run_cmd(["trivy", "--version"])
    if rc != 0:
        return "unknown"
    first = out.strip().splitlines()[0] if out.strip() else ""
    # "Version: 0.29.2" or "trivy version 0.29.2"
    for tok in first.replace(":", " ").split():
        if tok[0:1].isdigit() and "." in tok:
            return tok
    return "unknown"


def scan_image(image, severity):
    """Run trivy on one image, return raw parsed JSON or None."""
    sev = ",".join(severity) if severity else "CRITICAL,HIGH,MEDIUM,LOW"
    rc, out, err = run_cmd(
        ["trivy", "image", "--quiet", "--format", "json", "--severity", sev, image]
    )
    if rc != 0:
        log("WARN", "trivy scan failed for %s: %s" % (image, err.strip()[:200]))
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        log("WARN", "could not parse trivy output for %s" % image)
        return None


# --------------------------------------------------------------------------- #
# normalization — the stable contract with MORI
# --------------------------------------------------------------------------- #
def normalize(image, raw, agent_id, hostname, scanner_version, started, completed):
    """Convert trivy JSON into the stable findings envelope.

    Dedupe key is vulnerability|package|target — the same composite key the
    server uses so a CVE appearing in multiple packages is never collapsed.
    """
    findings = []
    for result in (raw or {}).get("Results", []) or []:
        target = result.get("Target", image)
        vclass = result.get("Class", "")
        for v in result.get("Vulnerabilities", []) or []:
            vid = v.get("VulnerabilityID", "")
            pkg = v.get("PkgName", "")
            severity = (v.get("Severity") or "UNKNOWN").upper()
            findings.append(
                {
                    "id": "%s|%s|%s" % (vid, pkg, image),
                    "vulnerability_id": vid,
                    "package": pkg,
                    "installed_version": v.get("InstalledVersion", ""),
                    "fixed_version": v.get("FixedVersion", ""),
                    "severity": severity,
                    "title": v.get("Title", ""),
                    "primary_url": v.get("PrimaryURL", ""),
                    "target": target,
                    "class": vclass,
                    "cvss_score": _extract_cvss(v),
                }
            )

    # deterministic ordering: severity, then id
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["id"]))

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    summary["total"] = len(findings)

    return {
        "schema_version": SCHEMA_VERSION,
        "agent_id": agent_id,
        "hostname": hostname,
        "scan": {
            "target": image,
            "target_type": "container_image",
            "scanner": "trivy",
            "scanner_version": scanner_version,
            "started_at": started,
            "completed_at": completed,
        },
        "findings": findings,
        "summary": summary,
    }


def _extract_cvss(v):
    """Prefer NVD, then Red Hat, then any vendor CVSS V3 base score."""
    cvss = v.get("CVSS") or {}
    for vendor in ("nvd", "redhat"):
        entry = cvss.get(vendor) or {}
        if "V3Score" in entry:
            return entry["V3Score"]
    for entry in cvss.values():
        if isinstance(entry, dict) and "V3Score" in entry:
            return entry["V3Score"]
    return None


# --------------------------------------------------------------------------- #
# agent lifecycle
# --------------------------------------------------------------------------- #
def resolve_agent_id(cfg, hostname):
    return cfg["agent"].get("id") or ("agent-%s" % hostname)


def register(client, agent_id, hostname):
    payload = {
        "agent_id": agent_id,
        "hostname": hostname,
        "ip_address": local_ip(),
        "os": "%s %s" % (os.uname().sysname, os.uname().release) if hasattr(os, "uname") else sys.platform,
        "agent_version": AGENT_VERSION,
        "capabilities": CAPABILITIES,
    }
    status, resp = client.post("/api/v1/agents/register", payload)
    if status in (200, 201):
        log("INFO", "registered as %s" % agent_id)
        return True
    log("ERROR", "registration failed (%s): %s" % (status, resp.get("error", resp)))
    return False


def heartbeat(client, agent_id):
    status, resp = client.post(
        "/api/v1/agents/heartbeat", {"agent_id": agent_id, "status": "online", "ts": now_iso()}
    )
    if status == 200:
        return True
    log("WARN", "heartbeat failed (%s)" % status)
    return False


def push_findings(client, envelope, dry_run=False):
    if dry_run:
        print(json.dumps(envelope, indent=2, ensure_ascii=False))
        return True
    status, resp = client.post("/api/v1/findings", envelope)
    if status in (200, 201, 202):
        log("INFO", "pushed %s findings for %s (batch %s)"
            % (envelope["summary"]["total"], envelope["scan"]["target"], resp.get("batch_id", "-")))
        return True
    log("ERROR", "push failed (%s): %s" % (status, resp.get("error", resp)))
    return False


def push_raw_to_mori(client, ingest_path, image, raw, dry_run=False):
    """mori_raw mode: POST the RAW Trivy report to MORI's /ingest/trivy.

    MORI normalizes internally. Auth is the Bearer token (MORI also accepts it
    as X-MORI-Token). See docs/MORI_INTEGRATION.md.
    """
    nvulns = sum(len(r.get("Vulnerabilities") or []) for r in (raw.get("Results") or []))
    if dry_run:
        log("INFO", "[dry-run] would POST raw report for %s (%d vulns) to %s"
            % (image, nvulns, ingest_path))
        return True
    status, resp = client.post(ingest_path, raw)
    if status in (200, 201, 202):
        log("INFO", "ingested %s to MORI: records=%s entities=%s"
            % (raw.get("ArtifactName", image), resp.get("records_collected", "?"),
               resp.get("entities_saved", "?")))
        return True
    log("ERROR", "MORI ingest failed (%s): %s" % (status, resp.get("error", resp)))
    return False


def run_scan_cycle(client, cfg, agent_id, hostname, dry_run=False):
    scan_cfg = cfg["scan"]
    severity = scan_cfg.get("severity") or ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    max_images = int(scan_cfg.get("max_images", 0) or 0)

    targets_cfg = scan_cfg.get("targets", "all_local")
    if isinstance(targets_cfg, list):
        images = sorted(set(targets_cfg))
    elif targets_cfg == "all_local":
        images = list_local_images(max_images)
    else:
        images = [str(targets_cfg)]

    if not images:
        log("INFO", "no images to scan")
        return

    push_cfg = cfg.get("push", {}) or {}
    mode = push_cfg.get("mode", "mock")
    ingest_path = push_cfg.get("ingest_path", "/ingest/trivy")

    sver = trivy_version()
    log("INFO", "scan cycle: %d image(s), trivy %s, push=%s" % (len(images), sver, mode))
    for image in images:
        started = now_iso()
        raw = scan_image(image, severity)
        completed = now_iso()
        if raw is None:
            continue
        if mode == "mori_raw":
            # ship the raw Trivy report straight to MORI; MORI normalizes
            push_raw_to_mori(client, ingest_path, image, raw, dry_run=dry_run)
        else:
            envelope = normalize(image, raw, agent_id, hostname, sver, started, completed)
            push_findings(client, envelope, dry_run=dry_run)


def main():
    ap = argparse.ArgumentParser(description="Trivy Agent Lab for MORI-SOC")
    ap.add_argument("--config", required=True, help="path to config.yaml")
    ap.add_argument("--once", action="store_true", help="run one scan cycle and exit")
    ap.add_argument("--register-only", action="store_true", help="register and exit")
    ap.add_argument("--dry-run", action="store_true", help="print envelopes instead of pushing")
    args = ap.parse_args()

    try:
        cfg = load_config(args.config)
    except OSError as e:
        log("ERROR", "cannot read config: %s" % e)
        return 2

    server = cfg.get("server", {})
    base_url = server.get("url")
    if not base_url:
        log("ERROR", "server.url is required")
        return 2

    hostname = socket.gethostname()
    agent_id = resolve_agent_id(cfg, hostname)
    client = ApiClient(base_url, server.get("token", ""), bool(server.get("verify_tls", True)))

    # register/heartbeat only exist in the mock/central protocol; MORI's
    # /ingest/trivy has neither, so skip them in mori_raw mode.
    mode = (cfg.get("push", {}) or {}).get("mode", "mock")
    uses_registry = (mode != "mori_raw")

    if uses_registry:
        if not register(client, agent_id, hostname):
            if args.once or args.register_only:
                return 1
    elif args.register_only:
        log("ERROR", "--register-only not supported in mori_raw mode (no registry)")
        return 2
    if args.register_only:
        return 0

    if args.once:
        if uses_registry:
            heartbeat(client, agent_id)
        run_scan_cycle(client, cfg, agent_id, hostname, dry_run=args.dry_run)
        return 0

    hb_interval = int(cfg["intervals"].get("heartbeat_seconds", 60))
    scan_interval = int(cfg["intervals"].get("scan_seconds", 900))
    log("INFO", "loop: heartbeat=%ss scan=%ss push=%s" % (hb_interval, scan_interval, mode))

    last_scan = 0.0
    registered = True
    while True:
        try:
            if uses_registry and not heartbeat(client, agent_id) and not registered:
                registered = register(client, agent_id, hostname)
            now = time.monotonic()
            if now - last_scan >= scan_interval:
                run_scan_cycle(client, cfg, agent_id, hostname, dry_run=args.dry_run)
                last_scan = now
            time.sleep(hb_interval)
        except KeyboardInterrupt:
            log("INFO", "shutting down")
            return 0
        except Exception as e:  # never let the loop die
            log("ERROR", "cycle error: %s" % e)
            time.sleep(hb_interval)


if __name__ == "__main__":
    sys.exit(main())
