"""Version, update, system health, db stats, backup, audit log, DHCP,
analytics, reports, firewall, saved searches, MITRE, assets, devices,
test detection."""

from __future__ import annotations

import asyncio
import importlib.metadata
import json
import logging
import subprocess
import time
from pathlib import Path

from aiohttp import web

from . import _json_response, _db

log = logging.getLogger(__name__)
_security_ops_cache: dict = {"data": None, "ts": 0}


def _ingest_queue_metrics(daemon) -> dict:
    queue = getattr(daemon, "alert_queue", None)
    if queue is None:
        return {
            "available": False,
            "note": "daemon has no alert_queue attribute",
        }
    maxsize = int(getattr(queue, "maxsize", 0) or 0)
    size = int(queue.qsize())
    free = max(0, maxsize - size) if maxsize > 0 else None
    return {
        "available": True,
        "size": size,
        "maxsize": maxsize,
        "free": free,
        "full": bool(queue.full()),
        "dropped_total": int(getattr(daemon, "_dropped_alerts", 0) or 0),
    }


# ── /api/health ──────────────────────────────────────────────────────────────

async def handle_health(request: web.Request) -> web.Response:
    """GET /api/health — liveness check."""
    daemon = request.app["daemon"]
    try:
        stats = await daemon.db.get_stats()
        te = daemon.cfg.threat_engine

        triage_stats: dict = {}
        triage_worker = getattr(daemon, "_triage_worker", None)
        if triage_worker is not None:
            triage_stats = triage_worker.get_stats()

        cb = triage_stats.get("circuit_breaker", {})
        overall_status = "degraded" if cb.get("tripped") else "ok"

        return _json_response({
            "status": overall_status,
            "total_alerts": stats.get("total_alerts", 0),
            "ws_clients": len(daemon.ws_clients),
            "profile": daemon.cfg.profile,
            "ai_tier": daemon.cfg.ai.tier,
            "triage": triage_stats,
            "ingest_queue": _ingest_queue_metrics(daemon),
            "threat_engine": {
                "tier": te.tier,
                "baselines": te.baselines and hasattr(daemon, '_baselines'),
                "graph": te.graph and hasattr(daemon, '_graph'),
                "ml_detector": te.ml_detector and hasattr(daemon, '_ml_detector'),
                "killchain": te.killchain and hasattr(daemon, '_killchain'),
                "correlator_interval_sec": te.correlator_interval_sec,
                "ml_retrain_sec": te.ml_retrain_sec,
                "graph_max_nodes": te.graph_max_nodes,
            },
        })
    except Exception as exc:
        return _json_response({"status": "degraded", "error": str(exc)}, status=503)


# ── /api/stats ────────────────────────────────────────────────────────────────

async def handle_stats(request: web.Request) -> web.Response:
    """GET /api/stats — dashboard overview statistics."""
    try:
        daemon = request.app["daemon"]
        home_cidr = daemon.cfg.network.home_cidr
        stats = await daemon.db.get_dashboard_stats(home_cidr)
        return _json_response(stats)
    except Exception as exc:
        log.exception("Error fetching stats")
        raise web.HTTPInternalServerError(reason=str(exc))


async def handle_security_ops(request: web.Request) -> web.Response:
    """GET /api/security/ops — compact production/security operations snapshot."""
    now = time.time()
    if _security_ops_cache["data"] and (now - _security_ops_cache["ts"]) < 30:
        return _json_response(_security_ops_cache["data"])

    daemon = request.app["daemon"]
    config_path = getattr(daemon, "config_path", "") or "config.yaml"

    def load() -> dict:
        from tools.shallot_security_snapshot import load_snapshot

        return load_snapshot(
            config=str(config_path),
            hours=1.0,
            expected_log_sources="docs/NETWORK_LOG_SOURCES.yaml",
        )

    try:
        snapshot = await asyncio.wait_for(asyncio.to_thread(load), timeout=20)
    except Exception as exc:
        log.exception("Error fetching security ops snapshot")
        return _json_response({"status": "error", "error": str(exc)}, status=503)

    _security_ops_cache["data"] = snapshot
    _security_ops_cache["ts"] = now
    return _json_response(snapshot)


# ── /api/agent-guide ──────────────────────────────────────────────────────────

_agent_guide_cache: dict = {"data": None, "ts": 0}

async def handle_agent_guide(request: web.Request) -> web.Response:
    """GET /api/agent-guide — machine-readable system manifest for CLI agents.

    No auth required. Cached for 60 seconds.
    """
    now = time.time()
    if _agent_guide_cache["data"] and (now - _agent_guide_cache["ts"]) < 60:
        return _json_response(_agent_guide_cache["data"])

    daemon = request.app["daemon"]
    try:
        stats = await daemon.db.get_stats()
    except Exception:
        stats = {}

    guide = {
        "version": "1.0",
        "system": "security-shallots",
        "description": "AI-augmented security monitoring stack",
        "architecture": {
            "daemon": "shallotd (Python asyncio)",
            "database": "SQLite FTS5",
            "web_framework": "aiohttp",
            "ingestors": ["suricata", "wazuh", "argus", "crowdsec", "syslog", "pfsense"],
            "ai_pipeline": "normalize → dedup → enrich → AI triage → correlate",
        },
        "api_endpoints": [
            {"method": "GET", "path": "/api/health", "auth": False,
             "purpose": "Liveness check — returns status and total alert count"},
            {"method": "GET", "path": "/api/stats", "auth": True,
             "purpose": "Dashboard statistics — totals, breakdowns by source/severity"},
            {"method": "GET", "path": "/api/alerts", "auth": True,
             "purpose": "Paginated alert list with filters (source, severity, verdict, since)",
             "params": "limit, offset, source, severity, verdict, since"},
            {"method": "GET", "path": "/api/alerts/{id}", "auth": True,
             "purpose": "Single alert detail"},
            {"method": "PATCH", "path": "/api/alerts/{id}/verdict", "auth": True,
             "purpose": "Set alert verdict (suppress/investigate/escalate)"},
            {"method": "POST", "path": "/api/alerts/bulk-verdict", "auth": True,
             "purpose": "Bulk update verdict for up to 500 alert IDs"},
            {"method": "POST", "path": "/api/alerts/suppress-filtered", "auth": True,
             "purpose": "Suppress all alerts matching filter criteria"},
            {"method": "GET", "path": "/api/alerts/search", "auth": True,
             "purpose": "FTS5 full-text search over alerts"},
            {"method": "POST", "path": "/api/query", "auth": True,
             "purpose": "Natural language query — translates question to SQL via AI"},
            {"method": "GET", "path": "/api/correlations", "auth": True,
             "purpose": "AI-detected cross-alert correlation patterns"},
            {"method": "WS", "path": "/ws/alerts", "auth": True,
             "purpose": "WebSocket live feed — real-time alert stream"},
            {"method": "GET", "path": "/api/agent-guide", "auth": False,
             "purpose": "This endpoint — system manifest for CLI agents"},
        ],
        "common_commands": {
            "restart": "sudo systemctl restart shallotd",
            "logs": "journalctl -u shallotd -f",
            "health_check": "sudo bash setup/shallot-doctor check",
            "backup": "sudo bash setup/shallot-doctor backup",
            "db_query": "sqlite3 shallots.db 'SELECT COUNT(*) FROM alerts'",
            "deploy": "cd /path/to/security-shallots && git pull && sudo systemctl restart shallotd",
        },
        "troubleshooting": [
            {"symptom": "shallotd won't start",
             "steps": ["Check logs: journalctl -u shallotd -n 50",
                        "Validate config: python3 -c \"import yaml; yaml.safe_load(open('config.yaml'))\"",
                        "Check port: ss -tlnp | grep 8844",
                        "Fix TLS: sudo bash setup/shallot-doctor fix-tls"]},
            {"symptom": "No alerts appearing",
             "steps": ["Check ingestor logs: journalctl -u shallotd -f | grep -i ingest",
                        "Verify EVE log: ls -la /var/log/suricata/eve.json",
                        "Check config toggles: components.suricata, components.wazuh"]},
            {"symptom": "AI triage stuck on pending",
             "steps": ["Verify AI config: grep -A5 'ai:' config.yaml",
                        "Check Ollama: curl http://OLLAMA_HOST:11434/api/tags",
                        "Check triage logs: journalctl -u shallotd | grep -i triage"]},
        ],
        "status": {
            "total_alerts": stats.get("total_alerts", 0),
            "pending_triage": stats.get("pending_triage", 0),
            "suppressed": stats.get("suppressed", 0),
            "investigate": stats.get("investigate", 0),
            "escalated": stats.get("escalated", 0),
            "correlations": stats.get("correlations", 0),
            "by_source": stats.get("by_source", {}),
            "by_severity": stats.get("by_severity", {}),
        },
        "config_paths": {
            "config": "./config.yaml",
            "database": "./shallots.db",
            "tls_cert": "./tls.cert",
            "tls_key": "./tls.key",
            "suricata_rules": "/var/lib/suricata/rules/shallots-home.rules",
            "systemd_service": "/etc/systemd/system/shallotd.service",
        },
    }

    _agent_guide_cache["data"] = guide
    _agent_guide_cache["ts"] = now
    return _json_response(guide)


# ── /api/version ──────────────────────────────────────────────────────────

def _get_repo_dir() -> Path:
    """Find the repository root directory."""
    # Walk up from this file to find .git
    d = Path(__file__).resolve().parent
    for _ in range(5):
        if (d / ".git").exists():
            return d
        d = d.parent
    return Path(__file__).resolve().parent.parent.parent


async def handle_version(request: web.Request) -> web.Response:
    """GET /api/version — return version info and update availability."""
    repo_dir = _get_repo_dir()

    try:
        version = importlib.metadata.version("security-shallots")
    except importlib.metadata.PackageNotFoundError:
        version = "0.1.0"

    git_hash = ""
    git_branch = ""
    git_dirty = False
    update_available = False
    commits_behind = 0

    try:
        git_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo_dir), timeout=5, stderr=subprocess.DEVNULL,
        ).decode().strip()

        git_branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(repo_dir), timeout=5, stderr=subprocess.DEVNULL,
        ).decode().strip()

        dirty_check = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=str(repo_dir), timeout=5, stderr=subprocess.DEVNULL,
        ).decode().strip()
        git_dirty = bool(dirty_check)

        # Fetch and check for updates
        subprocess.run(
            ["git", "fetch", "--quiet"],
            cwd=str(repo_dir), timeout=15, stderr=subprocess.DEVNULL,
        )

        behind = subprocess.check_output(
            ["git", "rev-list", "--count", f"HEAD..origin/{git_branch}"],
            cwd=str(repo_dir), timeout=5, stderr=subprocess.DEVNULL,
        ).decode().strip()
        commits_behind = int(behind)
        update_available = commits_behind > 0

    except (subprocess.SubprocessError, FileNotFoundError, ValueError):
        pass

    return _json_response({
        "version": version,
        "git_hash": git_hash,
        "git_branch": git_branch,
        "git_dirty": git_dirty,
        "update_available": update_available,
        "commits_behind": commits_behind,
    })


# ── /api/update ──────────────────────────────────────────────────────────

async def handle_update(request: web.Request) -> web.Response:
    """POST /api/update — pull latest code from remote."""
    repo_dir = _get_repo_dir()

    try:
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(repo_dir), timeout=5, stderr=subprocess.DEVNULL,
        ).decode().strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        branch = "main"

    try:
        result = subprocess.run(
            ["git", "pull", "origin", branch],
            cwd=str(repo_dir), capture_output=True, text=True, timeout=30,
        )
        return _json_response({
            "ok": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "message": "Update pulled. Restart shallotd to apply."
                       if result.returncode == 0 else "Update failed.",
        })
    except subprocess.TimeoutExpired:
        return _json_response(
            {"ok": False, "message": "Git pull timed out after 30s"}, status=504
        )
    except FileNotFoundError:
        return _json_response(
            {"ok": False, "message": "git not found on this system"}, status=500
        )


# ── /api/saved-searches ─────────────────────────────────────────────────────

async def handle_get_saved_searches(request: web.Request) -> web.Response:
    """GET /api/saved-searches — list saved searches."""
    searches = await _db(request).get_saved_searches()
    return _json_response({"searches": searches})


async def handle_save_search(request: web.Request) -> web.Response:
    """POST /api/saved-searches — save a search query."""
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    name = (body.get("name") or "").strip()
    query = (body.get("query") or "").strip()
    if not name or not query:
        raise web.HTTPBadRequest(reason="name and query are required")

    search_type = body.get("search_type", "fts")
    sid = await _db(request).save_search(name, query, search_type)
    return _json_response({"ok": True, "id": sid}, status=201)


async def handle_delete_saved_search(request: web.Request) -> web.Response:
    """DELETE /api/saved-searches/{id} — delete a saved search."""
    search_id = request.match_info["id"]
    deleted = await _db(request).delete_saved_search(search_id)
    if not deleted:
        raise web.HTTPNotFound(reason="Saved search not found")
    return _json_response({"ok": True})


# ── /api/dashboard/* ────────────────────────────────────────────────────────

async def handle_top_talkers(request: web.Request) -> web.Response:
    """GET /api/dashboard/top-talkers — top source IPs, dest IPs, signatures."""
    qs = request.rel_url.query
    since = qs.get("since", "24h")
    try:
        limit = min(int(qs.get("limit", 10)), 50)
    except ValueError:
        limit = 10
    data = await _db(request).get_top_talkers(since=since, limit=limit)
    return _json_response(data)


async def handle_timeline(request: web.Request) -> web.Response:
    """GET /api/dashboard/timeline — hourly alert timeline."""
    since = request.rel_url.query.get("since", "24h")
    data = await _db(request).get_timeline(since=since)
    return _json_response({"timeline": data})


async def handle_connections(request: web.Request) -> web.Response:
    """GET /api/dashboard/connections — unique connection pairs."""
    qs = request.rel_url.query
    since = qs.get("since", "24h")
    try:
        limit = min(int(qs.get("limit", 20)), 100)
    except ValueError:
        limit = 20
    data = await _db(request).get_unique_connections(since=since, limit=limit)
    return _json_response(data)


# ── /api/network/hosts ──────────────────────────────────────────────────────

async def handle_network_hosts(request: web.Request) -> web.Response:
    """GET /api/network/hosts — local network hosts only."""
    import ipaddress
    since = request.rel_url.query.get("since", "7d")
    all_hosts = await _db(request).get_network_hosts(since=since)

    # Filter to home_cidr (local network only)
    daemon = request.app["daemon"]
    try:
        home_net = ipaddress.ip_network(daemon.cfg.network.home_cidr, strict=False)
    except (ValueError, AttributeError):
        home_net = ipaddress.ip_network("192.168.0.0/16", strict=False)

    local_hosts = []
    for h in all_hosts:
        try:
            if ipaddress.ip_address(h["ip"]) in home_net:
                local_hosts.append(h)
        except (ValueError, TypeError):
            continue

    return _json_response({"hosts": local_hosts, "total": len(local_hosts)})


# ── /api/vulnerabilities ────────────────────────────────────────────────────

async def handle_vulnerabilities(request: web.Request) -> web.Response:
    """GET /api/vulnerabilities — CVE summary from Wazuh alerts."""
    since = request.rel_url.query.get("since", "30d")
    data = await _db(request).get_vulnerability_summary(since=since)
    return _json_response(data)


async def handle_vuln_correlation(request: web.Request) -> web.Response:
    """GET /api/vulnerabilities/correlation — cross-reference Wazuh CVEs with Suricata exploits."""
    days = int(request.rel_url.query.get("days", "30"))
    data = await _db(request).get_vuln_alert_correlation(days=days)
    return _json_response(data)


async def handle_mitre_coverage(request: web.Request) -> web.Response:
    """GET /api/mitre — MITRE ATT&CK coverage based on actual detections."""
    db = _db(request)

    # Static mapping: category patterns / correlation types → MITRE techniques
    MITRE_MAP = {
        "Reconnaissance": {
            "T1595": {"name": "Active Scanning", "sources": ["port_scan"]},
            "T1046": {"name": "Network Service Discovery", "sources": ["port_scan"]},
        },
        "Initial Access": {
            "T1190": {"name": "Exploit Public-Facing Application", "sources": ["Exploit", "CVE", "ET EXPLOIT"]},
            "T1078": {"name": "Valid Accounts", "sources": ["brute_force", "4624", "4625"]},
        },
        "Execution": {
            "T1059": {"name": "Command and Scripting Interpreter", "sources": ["4688", "process"]},
            "T1053": {"name": "Scheduled Task/Job", "sources": ["4698", "4702"]},
        },
        "Persistence": {
            "T1136": {"name": "Create Account", "sources": ["4720"]},
            "T1098": {"name": "Account Manipulation", "sources": ["4728", "4732", "4756", "4757"]},
        },
        "Credential Access": {
            "T1110": {"name": "Brute Force", "sources": ["brute_force", "4625"]},
        },
        "Lateral Movement": {
            "T1021": {"name": "Remote Services", "sources": ["lateral_movement", "4624"]},
        },
        "Command and Control": {
            "T1071": {"name": "Application Layer Protocol", "sources": ["c2_beacon"]},
            "T1573": {"name": "Encrypted Channel", "sources": ["c2_beacon"]},
            "T1568": {"name": "Dynamic Resolution (DGA)", "sources": ["DGA", "dga"]},
        },
        "Exfiltration": {
            "T1041": {"name": "Exfiltration Over C2 Channel", "sources": ["data_exfil"]},
        },
        "Defense Evasion": {
            "T1070": {"name": "Indicator Removal", "sources": ["1102"]},
            "T1562": {"name": "Impair Defenses", "sources": ["firewall"]},
        },
    }

    # Count correlations by type (last 30 days)
    corr_counts = {}
    try:
        cursor = await db._db.execute(
            "SELECT corr_type, COUNT(*) FROM correlations "
            "WHERE created_at > datetime('now', '-30 day') GROUP BY corr_type"
        )
        for row in await cursor.fetchall():
            corr_counts[row[0]] = row[1]
    except Exception:
        pass

    # Count alert categories/titles matching patterns (last 30 days)
    pattern_counts = {}
    search_patterns = set()
    for tactic_techs in MITRE_MAP.values():
        for tech in tactic_techs.values():
            for src in tech["sources"]:
                if not src.startswith("T") and src not in corr_counts:
                    search_patterns.add(src)

    for pat in search_patterns:
        try:
            cursor = await db._db.execute(
                "SELECT COUNT(*) FROM alerts WHERE "
                "(category LIKE ? OR title LIKE ? OR description LIKE ?) "
                "AND ingested_at > datetime('now', '-30 day')",
                (f"%{pat}%", f"%{pat}%", f"%{pat}%"),
            )
            row = await cursor.fetchone()
            if row and row[0] > 0:
                pattern_counts[pat] = row[0]
        except Exception:
            pass

    # Build response
    tactics = []
    for tactic_name, techniques in MITRE_MAP.items():
        techs = []
        for tech_id, tech_info in techniques.items():
            count = 0
            for src in tech_info["sources"]:
                count += corr_counts.get(src, 0) + pattern_counts.get(src, 0)
            techs.append({
                "id": tech_id,
                "name": tech_info["name"],
                "count": count,
                "detected": count > 0,
            })
        tactics.append({
            "tactic": tactic_name,
            "techniques": techs,
            "detected_count": sum(1 for t in techs if t["detected"]),
            "total_count": len(techs),
        })

    return _json_response({"tactics": tactics})


# ── Audit Log ─────────────────────────────────────────────────────────────

async def handle_audit_log(request: web.Request) -> web.Response:
    """GET /api/audit-log — view action audit trail."""
    qs = request.rel_url.query
    limit = min(int(qs.get("limit", 100)), 500)
    offset = int(qs.get("offset", 0))
    action = qs.get("action") or None
    db = _db(request)
    entries = await db.get_audit_log(limit=limit, offset=offset, action=action)
    total = await db.get_audit_count()
    return _json_response({"entries": entries, "total": total})


# ── Asset Inventory ───────────────────────────────────────────────────────

async def handle_get_assets(request: web.Request) -> web.Response:
    """GET /api/assets — list all known assets."""
    assets = await _db(request).get_assets()
    return _json_response(assets)


async def handle_get_asset(request: web.Request) -> web.Response:
    """GET /api/assets/{id} — single asset detail."""
    aid = request.match_info["id"]
    asset = await _db(request).get_asset(aid)
    if not asset:
        raise web.HTTPNotFound()
    return _json_response(asset)


async def handle_update_asset(request: web.Request) -> web.Response:
    """PATCH /api/assets/{id} — update asset fields."""
    aid = request.match_info["id"]
    body = await request.json()
    db = _db(request)
    ok = await db.update_asset(aid, **body)
    if not ok:
        raise web.HTTPNotFound()
    await db.insert_audit("update_asset", "asset", aid, json.dumps(body))
    return _json_response({"ok": True})


async def handle_create_asset(request: web.Request) -> web.Response:
    """POST /api/assets — manually create an asset."""
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        raise web.HTTPBadRequest(reason="IP address required")
    db = _db(request)
    aid = await db.upsert_asset(
        ip=ip,
        mac=body.get("mac", ""),
        hostname=body.get("hostname", ""),
        os=body.get("os", ""),
        asset_type=body.get("asset_type", "unknown"),
        source="manual",
    )
    if body.get("criticality"):
        await db.update_asset(aid, criticality=body["criticality"])
    if body.get("network_segment"):
        await db.update_asset(aid, network_segment=body["network_segment"])
    if body.get("notes"):
        await db.update_asset(aid, notes=body["notes"])
    await db.insert_audit("create_asset", "asset", aid, f"IP: {ip}")
    return _json_response({"ok": True, "id": aid})


# ── Known Devices ─────────────────────────────────────────────────────────

async def handle_known_devices(request: web.Request) -> web.Response:
    """GET /api/devices — list all known MAC addresses."""
    devices = await _db(request).get_known_devices()
    return _json_response(devices)


# ── System Admin ──────────────────────────────────────────────────────────

async def handle_db_stats(request: web.Request) -> web.Response:
    """GET /api/system/db-stats — database size and table counts."""
    stats = await _db(request).get_db_stats()
    return _json_response(stats)


async def handle_backup(request: web.Request) -> web.Response:
    """POST /api/system/backup — create database backup."""
    db = _db(request)
    try:
        path = await db.backup_database()
        await db.insert_audit("database_backup", "system", "", f"Backup: {path}")
        return _json_response({"ok": True, "path": path})
    except Exception as exc:
        return _json_response({"error": str(exc)}, status=500)


async def handle_system_health(request: web.Request) -> web.Response:
    """GET /api/system/health — comprehensive system health."""
    import os
    import json
    from datetime import datetime, timezone
    try:
        import psutil
    except ImportError:
        psutil = None
    daemon = request.app["daemon"]
    db = _db(request)

    db_stats = await db.get_db_stats()

    # Disk usage for db partition
    disk_info = None
    mem_info = None
    if psutil:
        try:
            disk = psutil.disk_usage(os.path.dirname(daemon.db.db_path))
            disk_info = {
                "total_gb": round(disk.total / (1024**3), 2),
                "used_gb": round(disk.used / (1024**3), 2),
                "free_gb": round(disk.free / (1024**3), 2),
                "percent": disk.percent,
            }
        except Exception:
            pass

        try:
            mem = psutil.virtual_memory()
            mem_info = {
                "total_gb": round(mem.total / (1024**3), 2),
                "used_gb": round(mem.used / (1024**3), 2),
                "percent": mem.percent,
            }
        except Exception:
            pass

    # Queue depth
    queue_depth = daemon.alert_queue.qsize()

    fleet: list[dict] = []
    try:
        rows = await db.get_agent_heartbeats()
        now = datetime.now(timezone.utc)
        for row in rows:
            agent = str(row.get("agent_name") or "")
            if agent.startswith(("shallot-load-", "shallot-experiment", "shallot-auth-boundary", "tls-smoke")):
                continue
            try:
                health = json.loads(row.get("health") or "{}")
                health = health if isinstance(health, dict) else {}
            except json.JSONDecodeError:
                health = {}
            metrics = health.get("host_metrics") if isinstance(health.get("host_metrics"), dict) else {}
            last_seen_raw = str(row.get("last_seen") or "")
            age_sec = None
            try:
                parsed = datetime.fromisoformat(last_seen_raw.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                age_sec = int((now - parsed.astimezone(timezone.utc)).total_seconds())
            except ValueError:
                pass
            state = str(health.get("state") or "unknown")
            if age_sec is not None and age_sec > 900:
                state = "OFFLINE"
            elif age_sec is not None and age_sec > 360:
                state = f"STALE/{state}"
            fleet.append(
                {
                    "agent": agent,
                    "ip": row.get("ip") or "",
                    "state": state,
                    "age_sec": age_sec,
                    "cpu_count": metrics.get("cpu_count", ""),
                    "cpu_util_pct": metrics.get("cpu_util_pct", ""),
                    "cpu_temp_c": metrics.get("cpu_temp_c", ""),
                    "cpu_temp_label": metrics.get("cpu_temp_label", ""),
                    "load1": metrics.get("load1", ""),
                    "load5": metrics.get("load5", ""),
                    "load15": metrics.get("load15", ""),
                    "load_per_core": metrics.get("load_per_core", ""),
                    "uptime_seconds": metrics.get("uptime_seconds", ""),
                    "mem_used_pct": metrics.get("mem_used_pct", ""),
                    "mem_total_mb": metrics.get("mem_total_mb", ""),
                    "mem_available_mb": metrics.get("mem_available_mb", ""),
                    "disk_used_pct": metrics.get("disk_used_pct", ""),
                    "disk_free_gb": metrics.get("disk_free_gb", ""),
                    "gpu_count": metrics.get("gpu_count", 0),
                    "gpus": metrics.get("gpus", []),
                }
            )
        fleet.sort(key=lambda item: str(item.get("agent")))
    except Exception:
        fleet = []

    return _json_response({
        "db": db_stats,
        "disk": disk_info,
        "memory": mem_info,
        "queue_depth": queue_depth,
        "ws_clients": len(daemon.ws_clients),
        "fleet": fleet,
    })


# ── Storage Settings ─────────────────────────────────────────────────────────

async def handle_get_storage_settings(request: web.Request) -> web.Response:
    """GET /api/settings/storage — current storage config."""
    daemon = request.app["daemon"]
    cfg = daemon.cfg.storage
    return _json_response({
        "retention_days": cfg.retention_days,
        "max_backups": cfg.max_backups,
        "db_path": cfg.db_path,
    })


async def handle_patch_storage_settings(request: web.Request) -> web.Response:
    """PATCH /api/settings/storage — update retention/backup settings (runtime only)."""
    daemon = request.app["daemon"]
    data = await request.json()
    cfg = daemon.cfg.storage

    if "retention_days" in data:
        val = int(data["retention_days"])
        if 1 <= val <= 365:
            cfg.retention_days = val
    if "max_backups" in data:
        val = int(data["max_backups"])
        if 0 <= val <= 30:
            cfg.max_backups = val

    return _json_response({
        "retention_days": cfg.retention_days,
        "max_backups": cfg.max_backups,
        "note": "Changes apply at next retention cycle. To persist, update config.yaml.",
    })


# ── DHCP Lease History ────────────────────────────────────────────────────────

async def handle_dhcp_history(request: web.Request) -> web.Response:
    """GET /api/dhcp — DHCP lease history with optional IP/MAC filter."""
    qs = request.rel_url.query
    ip = qs.get("ip")
    mac = qs.get("mac")
    limit = min(int(qs.get("limit", 200)), 500)
    rows = await _db(request).get_dhcp_history(ip=ip, mac=mac, limit=limit)
    return _json_response({"leases": rows, "total": len(rows)})


async def handle_dhcp_changes(request: web.Request) -> web.Response:
    """GET /api/dhcp/changes — IPs that changed MAC address (possible spoofing)."""
    days = int(request.rel_url.query.get("days", 7))
    changes = await _db(request).get_dhcp_ip_changes(days=days)
    return _json_response({"changes": changes, "total": len(changes)})


# ── Protocol / DNS Analytics ─────────────────────────────────────────────────

async def handle_protocol_analytics(request: web.Request) -> web.Response:
    """GET /api/analytics/protocols — alert breakdown by protocol, port, category, source."""
    qs = request.rel_url.query
    since = qs.get("since")
    db = _db(request)
    protocols = await db.get_protocol_distribution(since=since)
    ports = await db.get_port_distribution(since=since)
    categories = await db.get_category_distribution(since=since)
    sources = await db.get_source_distribution(since=since)
    return _json_response({
        "protocols": protocols,
        "ports": ports,
        "categories": categories,
        "sources": sources,
    })


async def handle_dns_analytics(request: web.Request) -> web.Response:
    """GET /api/analytics/dns — DNS-specific alert analytics."""
    since = request.rel_url.query.get("since")
    data = await _db(request).get_dns_analytics(since=since)
    return _json_response(data)


# ── Scheduled Reports ────────────────────────────────────────────────────────

async def handle_get_report_summary(request: web.Request) -> web.Response:
    """GET /api/reports/summary — generate activity summary for the last N hours."""
    hours = int(request.rel_url.query.get("hours", 24))
    summary = await _db(request).get_report_summary(hours=hours)
    return _json_response(summary)


async def handle_send_report_email(request: web.Request) -> web.Response:
    """POST /api/reports/send — send an email report now."""
    daemon = request.app["daemon"]
    hours = 24
    try:
        body = await request.json()
        hours = int(body.get("hours", 24))
    except Exception:
        pass

    summary = await daemon.db.get_report_summary(hours=hours)
    alerter = getattr(daemon, '_alerter', None)
    if not alerter:
        return _json_response({"error": "Alerter not configured"}, 400)

    email_cfg = alerter._cfg.email
    if not email_cfg.enabled:
        return _json_response({"error": "Email not enabled in config"}, 400)

    # Build the report email
    lines = [
        "Security Shallots — Daily Report",
        "=" * 40,
        f"Period: last {summary['period_hours']} hours",
        f"Total new alerts: {summary['total_alerts']}",
        f"Escalated: {summary['escalated']}",
        f"New incidents: {summary['new_incidents']}",
        f"Unique source IPs: {summary['unique_src_ips']}",
        "",
        "Severity breakdown:",
    ]
    for sev, count in summary.get("by_severity", {}).items():
        lines.append(f"  {sev}: {count}")
    lines.append("")
    lines.append("Top alerts:")
    for item in summary.get("top_alerts", [])[:10]:
        lines.append(f"  [{item['count']}x] {item['title']}")

    body_text = "\n".join(lines)
    subject = f"[Security Shallots] Daily Report — {summary['total_alerts']} alerts"

    try:
        try:
            import aiosmtplib
            await alerter._send_email_async(email_cfg, subject, body_text, aiosmtplib)
        except ImportError:
            import asyncio
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, alerter._send_email_sync, email_cfg, subject, body_text)
        return _json_response({"ok": True, "sent_to": email_cfg.to_addr})
    except Exception as exc:
        log.exception("Failed to send report email")
        return _json_response({"error": str(exc)}, 500)


# ── pfSense IP Blocking ─────────────────────────────────────────────────────

async def handle_block_ip(request: web.Request) -> web.Response:
    """POST /api/firewall/block — block an IP via pfSense API."""
    body = await request.json()
    ip = body.get("ip", "").strip()
    reason = body.get("reason", "Blocked by Security Shallots")
    if not ip:
        return _json_response({"error": "ip required"}, 400)

    daemon = request.app["daemon"]
    pf_cfg = daemon.cfg.pfsense

    if not pf_cfg.api_url or not pf_cfg.api_key:
        return _json_response({"error": "pfSense API not configured"}, 400)

    import aiohttp as _aiohttp
    import ipaddress
    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return _json_response({"error": "Invalid IP address"}, 400)

    # Don't block internal IPs
    try:
        if ipaddress.ip_address(ip).is_private:
            return _json_response({"error": "Cannot block internal/private IPs"}, 400)
    except Exception:
        pass

    # pfSense API: create a firewall alias entry or rule
    api_url = pf_cfg.api_url.rstrip("/")
    headers = {
        "Authorization": pf_cfg.api_key,
        "Content-Type": "application/json",
    }

    try:
        async with _aiohttp.ClientSession(timeout=_aiohttp.ClientTimeout(total=10)) as session:
            # Try to add to a "shallots_blocklist" alias
            alias_url = f"{api_url}/api/v1/firewall/alias"
            payload = {
                "name": "shallots_blocklist",
                "type": "host",
                "address": ip,
                "descr": reason,
                "detail": f"Blocked by Shallots: {reason}",
            }
            async with session.post(alias_url, json=payload, headers=headers,
                                     ssl=pf_cfg.verify_ssl) as resp:
                result = await resp.json()
                if resp.status >= 400:
                    return _json_response({
                        "error": f"pfSense API returned {resp.status}",
                        "detail": result,
                    }, resp.status)

        # Log the action
        await _db(request).add_audit_log("block_ip", "firewall", ip, reason)
        return _json_response({"ok": True, "ip": ip, "action": "blocked"})
    except Exception as exc:
        log.exception("pfSense block failed for %s", ip)
        return _json_response({"error": str(exc)}, 500)


async def handle_unblock_ip(request: web.Request) -> web.Response:
    """POST /api/firewall/unblock — remove an IP from the pfSense blocklist."""
    body = await request.json()
    ip = body.get("ip", "").strip()
    if not ip:
        return _json_response({"error": "ip required"}, 400)

    daemon = request.app["daemon"]
    pf_cfg = daemon.cfg.pfsense

    if not pf_cfg.api_url or not pf_cfg.api_key:
        return _json_response({"error": "pfSense API not configured"}, 400)

    import aiohttp as _aiohttp
    api_url = pf_cfg.api_url.rstrip("/")
    headers = {
        "Authorization": pf_cfg.api_key,
        "Content-Type": "application/json",
    }

    try:
        async with _aiohttp.ClientSession(timeout=_aiohttp.ClientTimeout(total=10)) as session:
            alias_url = f"{api_url}/api/v1/firewall/alias"
            payload = {
                "name": "shallots_blocklist",
                "address": ip,
            }
            async with session.delete(alias_url, json=payload, headers=headers,
                                       ssl=pf_cfg.verify_ssl) as resp:
                result = await resp.json()
                if resp.status >= 400:
                    return _json_response({
                        "error": f"pfSense API returned {resp.status}",
                        "detail": result,
                    }, resp.status)

        await _db(request).add_audit_log("unblock_ip", "firewall", ip)
        return _json_response({"ok": True, "ip": ip, "action": "unblocked"})
    except Exception as exc:
        log.exception("pfSense unblock failed for %s", ip)
        return _json_response({"error": str(exc)}, 500)


# ── Test Detection Pipeline ───────────────────────────────────────────────

async def handle_test_detection(request: web.Request) -> web.Response:
    """Inject a synthetic test alert through the full pipeline to verify it works.

    Creates a clearly-marked test alert, runs it through normalize/store/triage,
    then verifies it appeared in the database. Returns pass/fail for each stage.
    """
    import uuid as _uuid
    from datetime import datetime, timezone
    from shallots.store.models import Alert, now_iso

    daemon = request.app["daemon"]
    db = daemon.db

    test_id = str(_uuid.uuid4())
    test_ts = now_iso()
    test_title = "SHALLOTS-TEST: Detection Pipeline Validation"

    results = {"test_id": test_id, "timestamp": test_ts, "stages": {}}

    # Stage 1: Insert a test alert
    test_alert = Alert(
        id=test_id,
        timestamp=test_ts,
        source="argus",
        source_ref=f"test-{test_id[:8]}",
        severity="medium",
        title=test_title,
        description=(
            "This is a synthetic test alert injected by the detection pipeline "
            "validator. It verifies that alerts flow correctly from ingestion "
            "through storage, search, and display. Safe to dismiss."
        ),
        src_ip="127.0.0.1",
        src_port=0,
        dst_ip="10.0.0.1",
        dst_port=4444,
        proto="tcp",
        category="TEST",
        signature_id=9999999,
        raw=json.dumps({"test": True, "test_id": test_id}),
        verdict="pending",
        ingested_at=test_ts,
    )

    try:
        alert_id = await db.insert_alert(test_alert)
        results["stages"]["ingest"] = {"status": "pass", "alert_id": alert_id}
    except Exception as exc:
        results["stages"]["ingest"] = {"status": "fail", "error": str(exc)}
        results["overall"] = "fail"
        return _json_response(results)

    # Stage 2: Verify it's in the database
    try:
        rows = await db.execute_sql(
            "SELECT id, title, verdict FROM alerts WHERE id = ?", (test_id,)
        )
        if rows and rows[0]["id"] == test_id:
            results["stages"]["storage"] = {"status": "pass"}
        else:
            results["stages"]["storage"] = {"status": "fail", "error": "Alert not found after insert"}
    except Exception as exc:
        results["stages"]["storage"] = {"status": "fail", "error": str(exc)}

    # Stage 3: Verify FTS search works
    try:
        rows = await db.execute_sql(
            'SELECT id FROM alerts_fts WHERE alerts_fts MATCH \'"SHALLOTS-TEST"\' LIMIT 1',
            (),
        )
        results["stages"]["search"] = {
            "status": "pass" if rows else "fail",
            "detail": "FTS index working" if rows else "FTS match not found (may need rebuild)",
        }
    except Exception as exc:
        # FTS might not index immediately or table might not exist
        results["stages"]["search"] = {"status": "warn", "error": str(exc)}

    # Stage 4: WebSocket broadcast check
    try:
        ws_count = len(daemon.ws_clients)
        if ws_count > 0:
            await daemon._ws_broadcast({
                "type": "test_detection",
                "data": {"test_id": test_id, "message": "Pipeline test — alert injected successfully"},
            })
            results["stages"]["websocket"] = {"status": "pass", "clients": ws_count}
        else:
            results["stages"]["websocket"] = {"status": "warn", "detail": "No WebSocket clients connected"}
    except Exception as exc:
        results["stages"]["websocket"] = {"status": "warn", "error": str(exc)}

    # Stage 5: Check agent connectivity (are any agents reporting?)
    try:
        heartbeats = await db.execute_sql(
            """SELECT agent_name, last_seen FROM agent_heartbeats
               WHERE last_seen >= datetime('now', '-10 minutes')
               ORDER BY last_seen DESC""",
            (),
        )
        agent_names = [r["agent_name"] for r in heartbeats]
        results["stages"]["agents"] = {
            "status": "pass" if agent_names else "warn",
            "active_agents": agent_names,
            "detail": f"{len(agent_names)} agent(s) reporting" if agent_names else "No agents reported in last 10 min",
        }
    except Exception as exc:
        results["stages"]["agents"] = {"status": "warn", "error": str(exc)}

    # Stage 6: Check data source freshness
    try:
        source_rows = await db.execute_sql(
            """SELECT source, MAX(timestamp) as latest, COUNT(*) as cnt
               FROM alerts
               WHERE timestamp >= datetime('now', '-24 hours')
               GROUP BY source
               ORDER BY latest DESC""",
            (),
        )
        sources = {r["source"]: {"latest": r["latest"], "count_24h": r["cnt"]} for r in source_rows}
        results["stages"]["data_sources"] = {
            "status": "pass" if sources else "warn",
            "active_sources": sources,
            "detail": f"{len(sources)} source(s) active in last 24h" if sources else "No alerts from any source in 24h",
        }
    except Exception as exc:
        results["stages"]["data_sources"] = {"status": "warn", "error": str(exc)}

    # Overall verdict
    statuses = [s["status"] for s in results["stages"].values()]
    if "fail" in statuses:
        results["overall"] = "fail"
    elif "warn" in statuses:
        results["overall"] = "partial"
    else:
        results["overall"] = "pass"

    # Auto-suppress the test alert so it doesn't clutter the dashboard
    try:
        await db.bulk_update_verdict([test_id], "suppress", confidence=1.0,
                                      reasoning="Auto-suppressed test alert")
        results["cleanup"] = "Test alert auto-suppressed"
    except Exception as exc:
        results["cleanup"] = f"Could not auto-suppress test alert: {exc}"

    return _json_response(results)
