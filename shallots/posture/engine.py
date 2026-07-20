"""Compact posture collectors and memory for small Shallots hubs.

This module favors bounded state over raw-log retention. It is deliberately
standalone from the async daemon so rollout risk stays low.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "data" / "posture.db"
SHALLOTS_DB = ROOT / "shallots.db"
INVENTORY_DB = ROOT / "data" / "inventory.db"
POLICY_PATH = ROOT / "data" / "posture_policy.yaml"
CARD_DIR = ROOT / "docs" / "posture_cards"
REPORT_PATH = ROOT / "docs" / "POSTURE_STATE.md"


DDL = """
CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS posture_findings (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  entity TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  evidence TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS sensor_coverage (
  entity TEXT NOT NULL,
  sensor TEXT NOT NULL,
  state TEXT NOT NULL,
  last_seen TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  PRIMARY KEY(entity, sensor)
);
CREATE TABLE IF NOT EXISTS telemetry_rates (
  stream TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  ewma REAL NOT NULL,
  last_count INTEGER NOT NULL,
  last_seen TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_baselines (
  host TEXT NOT NULL,
  proto TEXT NOT NULL,
  bind TEXT NOT NULL,
  port INTEGER NOT NULL,
  process TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  expected INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(host, proto, bind, port, process)
);
CREATE TABLE IF NOT EXISTS drift_snapshots (
  target TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  digest TEXT NOT NULL,
  detail TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_ledger (
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  digest TEXT NOT NULL,
  cmd_simhash TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(host, path, digest, cmd_simhash)
);
CREATE TABLE IF NOT EXISTS dns_memory (
  domain TEXT PRIMARY KEY,
  etld1 TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  dga_score REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS egress_memory (
  host TEXT NOT NULL,
  dst TEXT NOT NULL,
  port INTEGER NOT NULL,
  proto TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  mean_interval REAL NOT NULL DEFAULT 0,
  m2_interval REAL NOT NULL DEFAULT 0,
  last_epoch REAL NOT NULL DEFAULT 0,
  present_last INTEGER NOT NULL DEFAULT 0,
  reconnects INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(host, dst, port, proto)
);
CREATE TABLE IF NOT EXISTS rarity_counts (
  scope TEXT NOT NULL,
  item TEXT NOT NULL,
  count INTEGER NOT NULL,
  last_seen TEXT NOT NULL,
  PRIMARY KEY(scope, item)
);
CREATE TABLE IF NOT EXISTS alert_memory (
  simhash TEXT PRIMARY KEY,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  count INTEGER NOT NULL,
  exemplar_id TEXT NOT NULL,
  exemplar_title TEXT NOT NULL,
  verdict TEXT NOT NULL,
  provenance TEXT NOT NULL DEFAULT 'shallots'
);
CREATE TABLE IF NOT EXISTS suppression_hygiene (
  key TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  provenance TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  hits INTEGER NOT NULL,
  review_after TEXT NOT NULL,
  canary_exception INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS escalation_cards (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  alert_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  entity TEXT NOT NULL,
  card_json TEXT NOT NULL
);
"""


DEFAULT_POLICY: dict[str, Any] = {
    "home_cidr": "192.168.0.0/16",
    "scan": {
        "max_findings_per_run": 80,
        "stale_sensor_seconds": 900,
        "time_offset_warn_seconds": 5,
        "telemetry_spike_factor": 5.0,
        "retention_days": 60,
        "max_escalation_cards": 500,
    },
    # Map of hostname -> list of services you expect to be listening. A service
    # bound outside this list is surfaced as posture drift. Define your own hosts
    # in data/posture_policy.yaml (see data/posture_policy.example.yaml). Empty by
    # default so a fresh install does not flag your machine's real services.
    "expected_services": {},
    "drift_targets": [
        {"path": "config.yaml", "kind": "shallots_config"},
        {"path": "data/inventory_seed.yaml", "kind": "asset_policy"},
        {"path": "data/posture_policy.yaml", "kind": "posture_policy"},
        {"path": "/etc/argus/config.toml", "kind": "argus_config"},
        {"path": "/etc/ssh/sshd_config", "kind": "ssh_config"},
        {"path": "/etc/sudoers", "kind": "sudoers"},
        {"path": "/etc/crontab", "kind": "cron"},
    ],
    "canaries": {
        "enabled": True,
        "directory": "/var/lib/shallots/canaries",
        "files": ["fake-prod.env", "fake-backup-manifest.txt", "fake-ssh-key-marker"],
    },
    # Filesystem prefixes whose executables are expected/allowed (e.g. your app
    # virtualenvs). Override in data/posture_policy.yaml for your own paths.
    "execution_allow_prefixes": [],
    "honey_listener": {
        "enabled": True,
        "bind": "0.0.0.0",
        "port": 9922,
        "allow_cidrs": ["127.0.0.0/8"],
    },
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run(cmd: list[str], *, timeout: int = 8) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    if path.exists() and yaml is not None:
        with path.open() as fh:
            loaded = yaml.safe_load(fh) or {}
        return _deep_merge(DEFAULT_POLICY, loaded)
    return DEFAULT_POLICY


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def connect(path: Path = DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=20)
    con.row_factory = sqlite3.Row
    con.executescript(DDL)
    _migrate(con)
    con.commit()
    return con


def _migrate(con: sqlite3.Connection) -> None:
    """Additive column migrations for DBs created before newer columns existed."""
    have = {r["name"] for r in con.execute("PRAGMA table_info(egress_memory)")}
    if "present_last" not in have:
        con.execute("ALTER TABLE egress_memory ADD COLUMN present_last INTEGER NOT NULL DEFAULT 0")
    if "reconnects" not in have:
        con.execute("ALTER TABLE egress_memory ADD COLUMN reconnects INTEGER NOT NULL DEFAULT 0")


def stable_id(*parts: object) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(str(part).encode())
        h.update(b"\0")
    return h.hexdigest()[:24]


def add_finding(
    con: sqlite3.Connection,
    category: str,
    severity: str,
    title: str,
    detail: str,
    *,
    entity: str = "",
    evidence: dict[str, Any] | None = None,
) -> None:
    fid = stable_id(category, title, entity, detail)
    con.execute(
        """INSERT OR REPLACE INTO posture_findings
           (id, ts, category, severity, title, detail, entity, status, evidence)
           VALUES (?,?,?,?,?,?,?,'open',?)""",
        (fid, now_iso(), category, severity, title, detail, entity, json.dumps(evidence or {})),
    )


def get_kv(con: sqlite3.Connection, key: str, default: str = "") -> str:
    row = con.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    return str(row["value"]) if row else default


def set_kv(con: sqlite3.Connection, key: str, value: str) -> None:
    con.execute(
        "INSERT OR REPLACE INTO kv(key,value,updated_at) VALUES(?,?,?)",
        (key, value, now_iso()),
    )


def hostname() -> str:
    return run(["hostname"]).stdout.strip() or socket.gethostname()


def read_inventory() -> dict[str, dict[str, Any]]:
    if not INVENTORY_DB.exists():
        return {}
    con = sqlite3.connect(f"file:{INVENTORY_DB}?mode=ro", uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("SELECT * FROM devices").fetchall()
    except sqlite3.Error:
        return {}
    finally:
        con.close()
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        d = dict(r)
        for key in {d.get("ip"), d.get("hostname"), d.get("device_key")}:
            if key:
                out[str(key)] = d
    return out


def normalize_alert_text(row: sqlite3.Row | dict[str, Any]) -> str:
    def value(key: str) -> Any:
        if isinstance(row, dict):
            return row.get(key)
        return row[key] if key in row.keys() else ""

    text = " ".join(str(value(k) or "") for k in ("source", "severity", "title", "description", "src_ip", "dst_ip", "category"))
    text = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", text.lower())
    text = re.sub(r"\b\d+\b", "<num>", text)
    return re.sub(r"\s+", " ", text).strip()


def simhash(text: str, bits: int = 64) -> str:
    weights = [0] * bits
    tokens = re.findall(r"[a-z0-9_./:-]+", text.lower())
    for tok in tokens:
        digest = int(hashlib.blake2b(tok.encode(), digest_size=8).hexdigest(), 16)
        for i in range(bits):
            weights[i] += 1 if digest & (1 << i) else -1
    value = 0
    for i, weight in enumerate(weights):
        if weight >= 0:
            value |= 1 << i
    return f"{value:016x}"


def file_digest(path: Path) -> tuple[str, str]:
    h = hashlib.sha256()
    if path.is_dir():
        entries: list[str] = []
        for root, _dirs, files in os.walk(path):
            for name in sorted(files):
                p = Path(root) / name
                try:
                    rel = p.relative_to(path)
                    entries.append(f"{rel}:{p.stat().st_size}:{int(p.stat().st_mtime)}")
                except OSError:
                    pass
        blob = "\n".join(sorted(entries)).encode()
        h.update(blob)
        return h.hexdigest(), f"{len(entries)} files"
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest(), f"{path.stat().st_size} bytes"


def scan_asset_and_coverage(con: sqlite3.Connection, policy: dict[str, Any]) -> dict[str, Any]:
    ts = now_iso()
    stale = int(policy["scan"]["stale_sensor_seconds"])
    assets = read_inventory()
    for key, d in assets.items():
        con.execute(
            "INSERT OR REPLACE INTO sensor_coverage(entity,sensor,state,last_seen,detail,updated_at) VALUES(?,?,?,?,?,?)",
            (key, "inventory", "visible", d.get("last_seen", ""), d.get("role") or d.get("tier") or "", ts),
        )
    if SHALLOTS_DB.exists():
        db = sqlite3.connect(f"file:{SHALLOTS_DB}?mode=ro", uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            for r in db.execute("SELECT agent_name,last_seen,health FROM agent_heartbeats"):
                state = "visible"
                detail = ""
                try:
                    age = time.time() - datetime.fromisoformat(str(r["last_seen"]).replace("Z", "+00:00")).timestamp()
                    if age > stale:
                        state = "stale"
                        detail = f"age_sec={int(age)}"
                except Exception:
                    detail = "unparseable last_seen"
                con.execute(
                    "INSERT OR REPLACE INTO sensor_coverage(entity,sensor,state,last_seen,detail,updated_at) VALUES(?,?,?,?,?,?)",
                    (r["agent_name"], "argus", state, r["last_seen"], detail, ts),
                )
                if state == "stale":
                    add_finding(con, "coverage", "medium", f"Argus stale: {r['agent_name']}", detail, entity=r["agent_name"])
            sources = db.execute(
                "SELECT source, COUNT(*) c, MAX(COALESCE(ingested_at,timestamp)) last_seen FROM alerts WHERE COALESCE(ingested_at,timestamp) > datetime('now','-24 hours') GROUP BY source"
            ).fetchall()
            for r in sources:
                stream = f"alerts:{r['source']}"
                _update_rate(con, stream, int(r["c"]), str(r["last_seen"] or ""))
                con.execute(
                    "INSERT OR REPLACE INTO sensor_coverage(entity,sensor,state,last_seen,detail,updated_at) VALUES(?,?,?,?,?,?)",
                    ("fleet", str(r["source"]), "visible", str(r["last_seen"] or ""), f"24h_count={r['c']}", ts),
                )
        finally:
            db.close()
    return {"assets": len(assets)}


def _update_rate(con: sqlite3.Connection, stream: str, count: int, last_seen: str) -> None:
    ts = now_iso()
    row = con.execute("SELECT ewma,last_count FROM telemetry_rates WHERE stream=?", (stream,)).fetchone()
    if row is None:
        con.execute("INSERT INTO telemetry_rates VALUES(?,?,?,?,?,?)", (stream, count, float(count), count, last_seen, ts))
        return
    ewma = 0.7 * float(row["ewma"]) + 0.3 * float(count)
    con.execute(
        "UPDATE telemetry_rates SET count=?, ewma=?, last_count=?, last_seen=?, updated_at=? WHERE stream=?",
        (count, ewma, count, last_seen, ts, stream),
    )


def scan_time_integrity(con: sqlite3.Connection, policy: dict[str, Any]) -> dict[str, Any]:
    proc = run(["timedatectl", "show", "-p", "NTPSynchronized", "-p", "Timezone", "-p", "SystemClockSynchronized"])
    data = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k] = v
    if data.get("NTPSynchronized") not in {"yes", "true"} and data.get("SystemClockSynchronized") not in {"yes", "true"}:
        add_finding(con, "time", "medium", "Clock not synchronized", json.dumps(data), entity=hostname())
    con.execute(
        "INSERT OR REPLACE INTO sensor_coverage(entity,sensor,state,last_seen,detail,updated_at) VALUES(?,?,?,?,?,?)",
        (hostname(), "time", "visible", now_iso(), json.dumps(data), now_iso()),
    )
    return data


def parse_ss_listen() -> list[dict[str, Any]]:
    proc = run(["ss", "-H", "-lntu", "-p"], timeout=10)
    rows = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        local = parts[4]
        if ":" not in local:
            continue
        bind, port_s = local.rsplit(":", 1)
        bind = bind.strip("[]") or "0.0.0.0"
        if not port_s.isdigit():
            continue
        port = int(port_s)
        if proto == "udp" and port >= 32768:
            continue
        rows.append({"proto": proto, "bind": bind, "port": port, "process": parts[-1] if len(parts) > 5 else ""})
    return rows


def scan_services(con: sqlite3.Connection, policy: dict[str, Any]) -> dict[str, Any]:
    host = hostname()
    bootstrap = get_kv(con, "bootstrap_complete") != "1"
    expected = {
        (e["proto"], e["bind"], int(e["port"]))
        for e in policy.get("expected_services", {}).get(host, [])
    }
    seen = parse_ss_listen()
    ts = now_iso()
    for s in seen:
        key = (s["proto"], s["bind"], int(s["port"]))
        is_expected = key in expected
        row = con.execute(
            "SELECT 1 FROM service_baselines WHERE host=? AND proto=? AND bind=? AND port=? AND process=?",
            (host, s["proto"], s["bind"], s["port"], s["process"]),
        ).fetchone()
        con.execute(
            """INSERT OR REPLACE INTO service_baselines(host,proto,bind,port,process,first_seen,last_seen,expected)
               VALUES(?,?,?,?,?,COALESCE((SELECT first_seen FROM service_baselines WHERE host=? AND proto=? AND bind=? AND port=? AND process=?),?),?,?)""",
            (host, s["proto"], s["bind"], s["port"], s["process"], host, s["proto"], s["bind"], s["port"], s["process"], ts, ts, 1 if is_expected else 0),
        )
        if not bootstrap and row is None and not is_expected and s["bind"] not in {"127.0.0.1", "::1"}:
            add_finding(con, "exposure", "medium", f"New listener {s['proto']}:{s['port']}", f"{s['bind']} {s['process']}", entity=host, evidence=s)
    present_keys = {(s["proto"], s["bind"], s["port"]) for s in seen}
    for proto, bind, port in expected - present_keys:
        add_finding(con, "exposure", "low", f"Expected listener absent {proto}:{port}", bind, entity=host)
    return {"listeners": len(seen)}


def scan_drift(con: sqlite3.Connection, policy: dict[str, Any]) -> dict[str, Any]:
    ts = now_iso()
    changed = 0
    bootstrap = get_kv(con, "bootstrap_complete") != "1"
    for item in policy.get("drift_targets", []):
        p = Path(item["path"])
        if not p.is_absolute():
            p = ROOT / p
        if not p.exists():
            continue
        target = str(p)
        try:
            digest, detail = file_digest(p)
        except PermissionError:
            con.execute(
                "INSERT OR REPLACE INTO sensor_coverage(entity,sensor,state,last_seen,detail,updated_at) VALUES(?,?,?,?,?,?)",
                (hostname(), f"drift:{item.get('kind','config')}", "blind", "", f"{target} permission_denied", now_iso()),
            )
            continue
        row = con.execute("SELECT digest FROM drift_snapshots WHERE target=?", (target,)).fetchone()
        if not bootstrap and row and row["digest"] != digest:
            changed += 1
            add_finding(con, "drift", "medium", f"{item.get('kind','config')} changed", target, entity=hostname(), evidence={"old": row["digest"], "new": digest, "detail": detail})
        con.execute(
            """INSERT OR REPLACE INTO drift_snapshots(target,kind,digest,detail,first_seen,last_seen)
               VALUES(?,?,?,?,COALESCE((SELECT first_seen FROM drift_snapshots WHERE target=?),?),?)""",
            (target, item.get("kind", "config"), digest, detail, target, ts, ts),
        )
    return {"changed": changed}


def scan_execution(con: sqlite3.Connection, policy: dict[str, Any]) -> dict[str, Any]:
    host = hostname()
    bootstrap = get_kv(con, "bootstrap_complete") != "1"
    allowed_prefixes = tuple(policy.get("execution_allow_prefixes", []))
    proc = run(["ps", "-eo", "pid=,ppid=,comm=,args="], timeout=10)
    ts = now_iso()
    new_count = 0
    for line in proc.stdout.splitlines()[:400]:
        parts = line.strip().split(None, 3)
        if len(parts) < 4:
            continue
        cmdline = parts[3]
        exe = cmdline.split()[0]
        if not exe.startswith("/"):
            continue
        p = Path(exe)
        try:
            if not p.exists() or not p.is_file():
                continue
        except PermissionError:
            continue
        try:
            digest, _ = file_digest(p)
        except (OSError, PermissionError):
            continue
        ch = simhash(cmdline)
        row = con.execute("SELECT count FROM execution_ledger WHERE host=? AND path=? AND digest=? AND cmd_simhash=?", (host, str(p), digest, ch)).fetchone()
        if row is None:
            new_count += 1
            writable = str(p).startswith(("/tmp/", "/dev/shm/", str(Path.home())))
            allowed = str(p).startswith(allowed_prefixes)
            if not bootstrap and writable and not allowed:
                add_finding(con, "execution", "high", "First-seen executable in writable path", str(p), entity=host, evidence={"cmd_simhash": ch})
            con.execute("INSERT INTO execution_ledger VALUES(?,?,?,?,?,?,1)", (host, str(p), digest, ch, ts, ts))
        else:
            con.execute("UPDATE execution_ledger SET count=count+1,last_seen=? WHERE host=? AND path=? AND digest=? AND cmd_simhash=?", (ts, host, str(p), digest, ch))
    return {"new_execution_rows": new_count}


def scan_dns(con: sqlite3.Connection) -> dict[str, Any]:
    bootstrap = get_kv(con, "bootstrap_complete") != "1"
    paths = [Path("/var/log/pihole/pihole.log"), Path("/var/log/pihole.log")]
    src = next((p for p in paths if p.exists()), None)
    if not src:
        con.execute(
            "INSERT OR REPLACE INTO sensor_coverage(entity,sensor,state,last_seen,detail,updated_at) VALUES(?,?,?,?,?,?)",
            ("fleet", "dns", "blind", "", "Pi-hole log not present on hub", now_iso()),
        )
        return {"dns": "blind"}
    # Incremental offset-tracked read. The old code read only the last 500 lines,
    # which on a busy resolver (~250 log lines/sec) is a ~2-second window every scan
    # - it observed <1% of DNS traffic and missed almost all DGA/first-seen domains.
    # We now consume every line since the previous scan (deduped to unique domains).
    MAX_READ = 96 * 1024 * 1024  # safety cap; ~100x more than 10 min of busy DNS
    size = src.stat().st_size
    off_raw = get_kv(con, "dns_log_offset", "")
    if off_raw == "":
        # First run after upgrade: start at EOF so we don't backfill the whole
        # historical log (can be ~GB). Steady-state scans read the new window.
        set_kv(con, "dns_log_offset", str(size))
        return {"domains_seen": 0, "dns": "initialized_offset"}
    offset = int(off_raw or 0)
    if offset > size:  # log rotated/truncated
        offset = 0
    new_offset = offset
    counts: dict[str, int] = {}
    try:
        with src.open("r", errors="ignore") as fh:
            fh.seek(offset)
            data = fh.read(MAX_READ)
            new_offset = fh.tell()
        for line in data.splitlines():
            m = re.search(r"query\[[A-Z]+\]\s+([^\s]+)", line)
            if m:
                d = m.group(1).lower().strip(".")
                if d.endswith(".in-addr.arpa") or d.endswith(".ip6.arpa"):
                    continue
                counts[d] = counts.get(d, 0) + 1
    except OSError:
        new_offset = offset
    ts = now_iso()
    for d, occ in counts.items():
        etld1 = ".".join(d.split(".")[-2:]) if "." in d else d
        score = _dga_score(d)
        row = con.execute("SELECT count FROM dns_memory WHERE domain=?", (d,)).fetchone()
        if not bootstrap and row is None and score > 3.5:
            add_finding(con, "dns", "medium", "First-seen high-entropy domain", d, entity="fleet", evidence={"dga_score": score})
        con.execute(
            """INSERT OR REPLACE INTO dns_memory(domain,etld1,first_seen,last_seen,count,dga_score)
               VALUES(?,?,COALESCE((SELECT first_seen FROM dns_memory WHERE domain=?),?),?,COALESCE((SELECT count FROM dns_memory WHERE domain=?),0)+?,?)""",
            (d, etld1, d, ts, ts, d, occ, score),
        )
    set_kv(con, "dns_log_offset", str(new_offset))
    return {"domains_seen": sum(counts.values()), "unique_domains": len(counts)}


def _dga_score(domain: str) -> float:
    label = domain.split(".")[0]
    if not label or len(label) < 8:
        return 0.0
    if domain.endswith((".goog", ".google.com", ".gvt1.com", ".akamai.net", ".akamaiedge.net")):
        return 0.0
    unique = len(set(label)) / max(1, len(label))
    digits = sum(ch.isdigit() for ch in label) / max(1, len(label))
    vowels = sum(ch in "aeiou" for ch in label.lower()) / max(1, len(label))
    return round((unique * 2.0) + (digits * 3.0) + max(0, 0.25 - vowels) * 4.0, 3)


def scan_egress(con: sqlite3.Connection, policy: dict[str, Any]) -> dict[str, Any]:
    host = hostname()
    bootstrap = get_kv(con, "bootstrap_complete") != "1"
    home = ipaddress.ip_network(policy.get("home_cidr", "192.168.0.0/16"), strict=False)
    proc = run(["ss", "-H", "-tun"], timeout=10)
    ts = now_iso()
    epoch = time.time()
    observed = 0
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].lower() not in {"tcp", "udp"}:
            continue
        peer = parts[4]
        if ":" not in peer:
            continue
        dst, port_s = peer.rsplit(":", 1)
        dst = dst.strip("[]")
        if not port_s.isdigit():
            continue
        try:
            ip = ipaddress.ip_address(dst)
            if ip in home or ip.is_loopback:
                continue
        except ValueError:
            pass
        port = int(port_s)
        proto = parts[0].lower()
        observed += 1
        row = con.execute("SELECT count,last_epoch,mean_interval,m2_interval,present_last,reconnects FROM egress_memory WHERE host=? AND dst=? AND port=? AND proto=?", (host, dst, port, proto)).fetchone()
        if row is None:
            if not bootstrap:
                add_finding(con, "egress", "low", "First-seen external destination", f"{dst}:{port}", entity=host)
            con.execute("INSERT INTO egress_memory VALUES(?,?,?,?,?,?,1,0,0,?,1,0)", (host, dst, port, proto, ts, ts, epoch))
        elif int(row["present_last"] or 0) == 1:
            # Still-present connection: a persistent/long-lived session, NOT a beacon.
            # Snapshots can't distinguish persistence from periodicity, so we only
            # feed interval stats on genuine reconnects (see the else branch) and
            # merely refresh liveness here.
            con.execute("UPDATE egress_memory SET count=count+1,last_seen=?,last_epoch=?,present_last=1 WHERE host=? AND dst=? AND port=? AND proto=?", (ts, epoch, host, dst, port, proto))
        else:
            # Reconnect: the tuple was absent last scan and is back now. The gap
            # since we last saw it is a real inter-arrival sample for beaconing.
            reconnects = int(row["reconnects"] or 0) + 1
            interval = max(0.0, epoch - float(row["last_epoch"] or epoch))
            mean = float(row["mean_interval"] or 0)
            delta = interval - mean
            mean = mean + delta / max(1, reconnects)
            m2 = float(row["m2_interval"] or 0) + delta * (interval - mean)
            if reconnects >= 6 and mean > 20:
                variance = m2 / max(1, reconnects - 1)
                cv = math.sqrt(max(0.0, variance)) / mean if mean else 99
                if cv < 0.2:
                    add_finding(con, "beacon", "medium", "Low-jitter periodic egress (reconnecting)", f"{dst}:{port} cv={cv:.2f} mean={mean:.1f}s reconnects={reconnects}", entity=host)
            con.execute("UPDATE egress_memory SET count=count+1,last_seen=?,mean_interval=?,m2_interval=?,last_epoch=?,present_last=1,reconnects=? WHERE host=? AND dst=? AND port=? AND proto=?", (ts, mean, m2, epoch, reconnects, host, dst, port, proto))
    # Tuples not observed this scan have disconnected: clear present_last so their
    # next appearance is scored as a reconnect.
    con.execute("UPDATE egress_memory SET present_last=0 WHERE host=? AND last_seen<>?", (host, ts))
    return {"external_connections": observed}


def scan_alert_memory_and_cards(con: sqlite3.Connection, policy: dict[str, Any]) -> dict[str, Any]:
    if not SHALLOTS_DB.exists():
        return {}
    db = sqlite3.connect(f"file:{SHALLOTS_DB}?mode=ro", uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    CARD_DIR.mkdir(parents=True, exist_ok=True)
    cards = []
    try:
        rows = db.execute(
            """SELECT id,timestamp,ingested_at,source,severity,title,description,src_ip,dst_ip,category,verdict,confidence,ai_reasoning
               FROM alerts
               WHERE COALESCE(ingested_at,timestamp) > datetime('now','-24 hours')
               ORDER BY COALESCE(ingested_at,timestamp) DESC LIMIT 300"""
        ).fetchall()
        ts = now_iso()
        # Watermark: each alert row is counted exactly once across scans. Without
        # this, the trailing-300 window is re-counted every run and alert_memory /
        # rarity counts inflate by scan-cycle instead of by true occurrence.
        watermark = get_kv(con, "last_alert_ts", "")
        max_ts = watermark
        counted = 0
        for r in rows:
            row_ts = str(r["ingested_at"] or r["timestamp"] or "")
            is_new = (not watermark) or (row_ts > watermark)
            text = normalize_alert_text(r)
            sh = simhash(text)
            row = con.execute("SELECT count,verdict,exemplar_title FROM alert_memory WHERE simhash=?", (sh,)).fetchone()
            if is_new:
                con.execute(
                    """INSERT OR REPLACE INTO alert_memory(simhash,first_seen,last_seen,count,exemplar_id,exemplar_title,verdict,provenance)
                       VALUES(?,COALESCE((SELECT first_seen FROM alert_memory WHERE simhash=?),?),?,COALESCE((SELECT count FROM alert_memory WHERE simhash=?),0)+1,?,?,?,?)""",
                    (sh, sh, ts, ts, sh, r["id"], r["title"] or "", r["verdict"] or "pending", "shallots_alerts"),
                )
                _bump_rarity(con, f"{r['source']}:{r['category'] or ''}", r["title"] or "")
                counted += 1
                if row_ts > max_ts:
                    max_ts = row_ts
            if (r["verdict"] or "") != "suppress" and (r["severity"] or "low") in {"medium", "high", "critical"}:
                card = build_card(con, r, row)
                cards.append(card)
                con.execute("INSERT OR REPLACE INTO escalation_cards VALUES(?,?,?,?,?,?,?)", (card["id"], ts, r["id"], card["title"], card["severity"], card["entity"], json.dumps(card)))
        if max_ts and max_ts != watermark:
            set_kv(con, "last_alert_ts", max_ts)
        (CARD_DIR / "latest.json").write_text(json.dumps(cards[:40], indent=2))
    finally:
        db.close()
    return {"alert_memory_rows": len(rows), "counted_new": counted, "cards": len(cards)}


def _bump_rarity(con: sqlite3.Connection, scope: str, item: str) -> None:
    ts = now_iso()
    con.execute(
        """INSERT OR REPLACE INTO rarity_counts(scope,item,count,last_seen)
           VALUES(?,?,COALESCE((SELECT count FROM rarity_counts WHERE scope=? AND item=?),0)+1,?)""",
        (scope, item, scope, item, ts),
    )


def build_card(con: sqlite3.Connection, alert: sqlite3.Row, prior: sqlite3.Row | None) -> dict[str, Any]:
    entity = alert["src_ip"] or alert["dst_ip"] or ""
    coverage = [
        dict(r) for r in con.execute("SELECT sensor,state,last_seen,detail FROM sensor_coverage WHERE entity IN (?, 'fleet') ORDER BY sensor", (entity,))
    ]
    prior_case = dict(prior) if prior else None
    return {
        "id": stable_id("card", alert["id"]),
        "created_at": now_iso(),
        "alert_id": alert["id"],
        "title": alert["title"] or "Untitled alert",
        "severity": alert["severity"] or "medium",
        "entity": entity,
        "asset_role": lookup_asset_role(entity),
        "expected_behavior": "see posture policy and service/egress baselines",
        "observed_deviation": alert["description"] or alert["title"] or "",
        "coverage_stamp": coverage,
        "novelty": {"simhash_prior": prior_case},
        "rarity": rarity_for_alert(con, alert),
        "fleet_memory": {"status": "not_queried", "note": "Hyphae integration annotates only; never suppresses"},
        "evidence": {"source": alert["source"], "category": alert["category"], "db": str(SHALLOTS_DB)},
        "confidence": alert["confidence"],
        "uncertainty": alert["ai_reasoning"] or "",
        "why_rules_might_miss": "role-specific baseline or prior verdict context may be required",
    }


def lookup_asset_role(entity: str) -> dict[str, Any]:
    inv = read_inventory()
    d = inv.get(entity) or {}
    return {"tier": d.get("tier", "unknown"), "role": d.get("role") or d.get("hostname") or ""}


def rarity_for_alert(con: sqlite3.Connection, alert: sqlite3.Row) -> dict[str, Any]:
    scope = f"{alert['source']}:{alert['category'] or ''}"
    row = con.execute("SELECT count FROM rarity_counts WHERE scope=? AND item=?", (scope, alert["title"] or "")).fetchone()
    count = int(row["count"]) if row else 0
    score = round(-math.log2(max(count, 1) / max(count + 100, 101)), 3)
    return {"scope": scope, "count": count, "self_information": score}


def scan_suppression_hygiene(con: sqlite3.Connection) -> dict[str, Any]:
    if not SHALLOTS_DB.exists():
        return {}
    db = sqlite3.connect(f"file:{SHALLOTS_DB}?mode=ro", uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    rows = db.execute(
        """SELECT COALESCE(ai_reasoning,'native') reason, source, category, COUNT(*) hits, MIN(COALESCE(ingested_at,timestamp)) first_seen, MAX(COALESCE(ingested_at,timestamp)) last_seen
           FROM alerts WHERE verdict='suppress' AND COALESCE(ingested_at,timestamp) > datetime('now','-7 days')
           GROUP BY 1,2,3 ORDER BY hits DESC LIMIT 100"""
    ).fetchall()
    db.close()
    for r in rows:
        key = stable_id(r["reason"], r["source"], r["category"])
        con.execute(
            "INSERT OR REPLACE INTO suppression_hygiene VALUES(?,?,?,?,?,?,datetime('now','+7 days'),1)",
            (key, r["reason"], f"{r['source']}:{r['category']}", r["first_seen"], r["last_seen"], int(r["hits"])),
        )
    return {"suppression_patterns": len(rows)}


def ensure_canaries(con: sqlite3.Connection, policy: dict[str, Any]) -> dict[str, Any]:
    cfg = policy.get("canaries", {})
    if not cfg.get("enabled", True):
        return {"enabled": False}
    directory = Path(cfg.get("directory", "/var/lib/shallots/canaries"))
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        add_finding(con, "canary", "medium", "Canary directory not writable", str(directory), entity=hostname())
        return {"enabled": True, "error": "permission"}
    created = 0
    for name in cfg.get("files", []):
        p = directory / name
        if not p.exists():
            p.write_text(f"SHALLOTS-CANARY-NOT-A-SECRET {name}\n")
            created += 1
        digest, detail = file_digest(p)
        con.execute(
            """INSERT OR REPLACE INTO drift_snapshots(target,kind,digest,detail,first_seen,last_seen)
               VALUES(?,?,?,?,COALESCE((SELECT first_seen FROM drift_snapshots WHERE target=?),?),?)""",
            (str(p), "canary", digest, detail, str(p), now_iso(), now_iso()),
        )
    return {"enabled": True, "created": created}


def prune(con: sqlite3.Connection, policy: dict[str, Any]) -> dict[str, Any]:
    """Bounded state, not retention: drop learned rows unseen past the horizon and
    cap the card archive. Keeps posture.db small per the design principle."""
    days = int(policy["scan"].get("retention_days", 60))
    max_cards = int(policy["scan"].get("max_escalation_cards", 500))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    removed = 0
    for table in ("dns_memory", "egress_memory", "execution_ledger", "alert_memory", "rarity_counts"):
        removed += con.execute(f"DELETE FROM {table} WHERE last_seen < ?", (cutoff,)).rowcount
    removed += con.execute(
        "DELETE FROM escalation_cards WHERE id NOT IN (SELECT id FROM escalation_cards ORDER BY ts DESC LIMIT ?)",
        (max_cards,),
    ).rowcount
    return {"pruned_rows": removed, "cutoff": cutoff}


def write_report(con: sqlite3.Connection, summary: dict[str, Any]) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    findings = [dict(r) for r in con.execute("SELECT category,severity,title,entity,detail,ts FROM posture_findings WHERE status='open' ORDER BY ts DESC LIMIT 40")]
    coverage = [dict(r) for r in con.execute("SELECT entity,sensor,state,last_seen,detail FROM sensor_coverage ORDER BY entity,sensor LIMIT 120")]
    lines = [
        "# Posture State",
        "",
        f"Updated: {now_iso()}",
        "",
        "## Summary",
        "",
        "```json",
        json.dumps(summary, indent=2, sort_keys=True),
        "```",
        "",
        "## Open Findings",
        "",
    ]
    if findings:
        lines.extend(f"- **{f['severity']}** `{f['category']}` {f['title']} ({f['entity']}): {f['detail']}" for f in findings)
    else:
        lines.append("- none")
    lines.extend(["", "## Coverage", ""])
    lines.extend(f"- `{c['entity']}` / `{c['sensor']}`: {c['state']} {c['last_seen']} {c['detail']}" for c in coverage)
    REPORT_PATH.write_text("\n".join(lines) + "\n")


def scan_all(policy_path: Path = POLICY_PATH) -> dict[str, Any]:
    policy = load_policy(policy_path)
    con = connect()
    summary: dict[str, Any] = {"started_at": now_iso()}
    try:
        summary["asset_coverage"] = scan_asset_and_coverage(con, policy)
        summary["time_integrity"] = scan_time_integrity(con, policy)
        summary["services"] = scan_services(con, policy)
        summary["drift"] = scan_drift(con, policy)
        summary["execution"] = scan_execution(con, policy)
        summary["dns"] = scan_dns(con)
        summary["egress"] = scan_egress(con, policy)
        summary["alert_memory"] = scan_alert_memory_and_cards(con, policy)
        summary["suppression_hygiene"] = scan_suppression_hygiene(con)
        summary["canaries"] = ensure_canaries(con, policy)
        summary["prune"] = prune(con, policy)
        summary["finished_at"] = now_iso()
        set_kv(con, "bootstrap_complete", "1")
        con.commit()
        write_report(con, summary)
        return summary
    finally:
        con.close()


def status() -> dict[str, Any]:
    con = connect()
    try:
        tables = {}
        for name in (
            "posture_findings", "sensor_coverage", "service_baselines",
            "drift_snapshots", "execution_ledger", "dns_memory",
            "egress_memory", "rarity_counts", "alert_memory",
            "suppression_hygiene", "escalation_cards",
        ):
            tables[name] = con.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
        findings = [dict(r) for r in con.execute("SELECT category,severity,title,entity,detail,ts FROM posture_findings WHERE status='open' ORDER BY ts DESC LIMIT 20")]
        return {
            "db": str(DB_PATH),
            "db_mb": round(DB_PATH.stat().st_size / (1024 * 1024), 3) if DB_PATH.exists() else 0,
            "report": str(REPORT_PATH),
            "cards": str(CARD_DIR / "latest.json"),
            "tables": tables,
            "open_findings": findings,
        }
    finally:
        con.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Small-footprint Shallots posture engine")
    sub = parser.add_subparsers(dest="cmd", required=True)
    scan_p = sub.add_parser("scan")
    scan_p.add_argument("--policy", default=str(POLICY_PATH))
    sub.add_parser("status")
    sub.add_parser("init-policy")
    args = parser.parse_args(argv)
    if args.cmd == "scan":
        print(json.dumps(scan_all(Path(args.policy)), indent=2, sort_keys=True))
    elif args.cmd == "status":
        print(json.dumps(status(), indent=2, sort_keys=True))
    elif args.cmd == "init-policy":
        POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if yaml is None:
            POLICY_PATH.write_text(json.dumps(DEFAULT_POLICY, indent=2))
        else:
            POLICY_PATH.write_text(yaml.safe_dump(DEFAULT_POLICY, sort_keys=False))
        print(POLICY_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
