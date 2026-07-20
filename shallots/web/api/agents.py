"""Agent health, heartbeat, clove/argus ingest."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import secrets
from datetime import datetime, timezone

from aiohttp import web

from . import _json_response, _db

log = logging.getLogger(__name__)


def _valid_ip(value) -> str:
    """Return value if it is a valid IP address, else "". Agent-supplied IPs are
    untrusted and must never reach the dashboard as free text (XSS)."""
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return ""


def _secret_rejection(request: web.Request, secret: str, header_name: str) -> web.Response | None:
    """Return a 401 response when a configured ingest secret is missing or wrong."""
    if not secret:
        log.error("Write-capable ingest route is missing configured secret for %s", header_name)
        return _json_response({"error": "ingest secret not configured"}, status=503)
    if not secrets.compare_digest(request.headers.get(header_name, ""), secret):
        return _json_response({"error": "unauthorized"}, status=401)
    return None


# ── /api/heartbeat ────────────────────────────────────────────────────────

async def handle_heartbeat(request: web.Request) -> web.Response:
    """POST /api/heartbeat - receive agent heartbeat."""
    daemon = request.app["daemon"]
    rejection = _secret_rejection(
        request,
        daemon.cfg.agent_monitor.heartbeat_secret,
        "X-Heartbeat-Secret",
    )
    if rejection is not None:
        return rejection

    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    agent_name = (body.get("agent_name") or "").strip()
    if not agent_name:
        raise web.HTTPBadRequest(reason="agent_name is required")

    health = body.get("health", {})
    health_json = json.dumps(health) if isinstance(health, dict) else "{}"
    baselines = body.get("baselines", {})
    baselines_json = json.dumps(baselines) if isinstance(baselines, dict) else "{}"

    db = _db(request)
    await db.upsert_agent_heartbeat(
        agent_name=agent_name,
        agent_type=body.get("agent_type", "unknown"),
        os=body.get("os", ""),
        ip=body.get("ip", ""),
        version=body.get("version", ""),
        health_data=health_json,
    )

    # Also upsert into agent_heartbeats table (clove-compatible)
    commands = await db.upsert_clove_heartbeat(
        agent_name=agent_name,
        agent_type=body.get("agent_type", "unknown"),
        os=body.get("os", ""),
        ip=body.get("ip", ""),
        version=body.get("version", ""),
        health=health_json,
        baselines=baselines_json,
    )

    return _json_response({"status": "ok", "commands": commands})


# ── /api/agents ──────────────────────────────────────────────────────────

async def handle_agents(request: web.Request) -> web.Response:
    """GET /api/agents - list all registered agents with health data."""
    agents = await _db(request).get_agents()
    # Parse health_data JSON strings
    for a in agents:
        try:
            a["health_data"] = json.loads(a.get("health_data", "{}"))
        except (json.JSONDecodeError, TypeError):
            a["health_data"] = {}
    return _json_response({"agents": agents, "count": len(agents)})


# ── Agent API (CLI agent compat) ─────────────────────────────────────────────

async def handle_agent_briefing(request: web.Request) -> web.Response:
    """GET /api/agent/briefing - Structured briefing for AI agents."""
    db = _db(request)
    stats = await db.get_stats()
    top = await db.get_top_talkers(since="24h", limit=5)
    investigations = await db.get_recent_investigations(limit=3)
    briefing = {
        "pending_alerts": stats.get("pending_triage", 0),
        "escalated_alerts": stats.get("escalated", 0),
        "total_alerts": stats.get("total_alerts", 0),
        "investigate_alerts": stats.get("investigate", 0),
        "active_correlations": stats.get("correlations", 0),
        "agents_online": stats.get("agents_online", 0),
        "agents_offline": stats.get("agents_offline", 0),
        "top_sources": stats.get("by_source", {}),
        "top_src_ips": top.get("src_ips", [])[:5],
        "top_dst_ips": top.get("dst_ips", [])[:5],
        "recent_investigations": investigations,
    }
    return _json_response(briefing)


async def handle_agent_investigate(request: web.Request) -> web.Response:
    """POST /api/agent/investigate - Agent submits investigation findings."""
    db = _db(request)
    try:
        body = await request.json()
    except Exception:
        return _json_response({"error": "Invalid JSON"}, status=400)

    alert_ids = body.get("alert_ids", [])
    narrative = body.get("narrative", "")
    verdicts = body.get("verdicts", [])
    recommendations = body.get("recommendations", [])

    # Apply verdicts
    applied = 0
    valid = {"suppress", "investigate", "escalate"}
    for v in verdicts:
        verdict_val = v.get("verdict", "")
        if verdict_val in valid and v.get("alert_id"):
            await db.update_verdict(
                alert_id=v["alert_id"],
                verdict=verdict_val,
                confidence=0.9,
                reasoning=f"[Agent] {v.get('reasoning', '')}",
            )
            applied += 1

    return _json_response({
        "ok": True,
        "verdicts_applied": applied,
        "alert_ids": alert_ids,
    })


async def handle_agent_context(request: web.Request) -> web.Response:
    """GET /api/agent/context/{alert_id} - Full enriched context for one alert."""
    alert_id = request.match_info["alert_id"]
    db = _db(request)

    alert = await db.get_alert(alert_id)
    if not alert:
        return _json_response({"error": "Alert not found"}, status=404)

    triage = await db.get_triage(alert_id)

    ip_rep = {}
    for ip_field in ("src_ip", "dst_ip"):
        ip = alert.get(ip_field, "")
        if ip:
            rep = await db.get_ip_reputation(ip)
            if rep:
                ip_rep[ip] = rep

    related = []
    if alert.get("src_ip"):
        related = await db.get_alerts(limit=10, since="24h", src_ip=alert["src_ip"])
        related = [r for r in related if r["id"] != alert_id]

    kb = await db.search_knowledge(alert.get("title", ""), limit=3)
    chat = await db.get_chat_history(alert_id, limit=10)

    return _json_response({
        "alert": alert,
        "triage": triage,
        "ip_reputation": ip_rep,
        "related_alerts": [
            {"id": r["id"], "title": r["title"], "severity": r["severity"], "timestamp": r["timestamp"]}
            for r in related[:5]
        ],
        "knowledge_base": kb,
        "chat_history": chat,
    })


# ── /api/ingest/clove ──────────────────────────────────────────────────────

async def handle_clove_ingest(request: web.Request) -> web.Response:
    """POST /api/ingest/clove - receive clove-watchdog payload."""
    from shallots.store.models import Alert, now_iso

    daemon = request.app["daemon"]
    rejection = _secret_rejection(
        request,
        daemon.cfg.agent_monitor.heartbeat_secret,
        "X-Heartbeat-Secret",
    )
    if rejection is not None:
        return rejection

    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    db = _db(request)
    agent_name = (body.get("agent_name") or "").strip()
    if not agent_name:
        raise web.HTTPBadRequest(reason="agent_name is required")

    agent_type = body.get("agent_type", "clove")
    agent_os = body.get("os", "")
    agent_ip = body.get("ip", "")
    agent_version = body.get("version", "")
    health = body.get("health", {})
    baselines = body.get("baselines", {})
    health_json = json.dumps(health) if isinstance(health, dict) else "{}"
    baselines_json = json.dumps(baselines) if isinstance(baselines, dict) else "{}"

    # Upsert into agent_heartbeats
    commands = await db.upsert_clove_heartbeat(
        agent_name=agent_name,
        agent_type=agent_type,
        os=agent_os,
        ip=agent_ip,
        version=agent_version,
        health=health_json,
        baselines=baselines_json,
    )

    # Also upsert into agent_status (legacy table) so existing dashboard sees it
    await db.upsert_agent_heartbeat(
        agent_name=agent_name,
        agent_type=agent_type,
        os=agent_os,
        ip=agent_ip,
        version=agent_version,
        health_data=health_json,
    )

    # Severity name → numeric mapping
    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    alerts = body.get("alerts", [])
    count = 0
    for alert_data in alerts:
        # Clove-watchdog emits "type"; older/other payloads may use "alert_type".
        # Accept both so agent events aren't silently mislabeled "unknown".
        alert_type = alert_data.get("alert_type") or alert_data.get("type") or "unknown"
        severity = alert_data.get("severity", "medium")
        title = alert_data.get("title", "")
        details = alert_data.get("details", {})
        # Coerce agent-supplied source_ip to a valid IP (or empty). Never trust it
        # as free text - it flows into the dashboard and must not carry markup.
        source_ip = _valid_ip(alert_data.get("source_ip")) or _valid_ip(agent_ip)
        timestamp = alert_data.get("timestamp") or now_iso()
        details_json = json.dumps(details) if isinstance(details, dict) else str(details)

        # Insert into clove_alerts table
        await db.insert_clove_alert(
            agent_name=agent_name,
            alert_type=alert_type,
            severity=severity,
            title=title,
            details=details_json,
            source_ip=source_ip,
            timestamp=timestamp,
        )

        # Normalize into main alerts table for dashboard visibility
        sig_id_str = f"{agent_name}:{alert_type}:{title}"
        sig_id = int(hashlib.sha256(sig_id_str.encode()).hexdigest()[:8], 16)
        numeric_severity = severity_map.get(severity, 2)
        severity_label = {1: "low", 2: "medium", 3: "high", 4: "critical"}.get(
            numeric_severity, "medium"
        )

        alert = Alert(
            timestamp=timestamp,
            source="clove",
            source_ref=f"clove:{agent_name}",
            severity=severity_label,
            title=title,
            description=json.dumps(details) if isinstance(details, dict) else str(details),
            src_ip=source_ip,
            category=alert_type,
            signature_id=sig_id,
            verdict="pending",
            confidence=0.0,
        )
        await db.insert_alert(alert)
        count += 1

    return _json_response({"status": "ok", "alerts_ingested": count, "commands": commands})


# ── /api/ingest/argus ──────────────────────────────────────────────────────

async def handle_argus_ingest(request: web.Request) -> web.Response:
    """POST /api/ingest/argus - receive Argus agent events.

    Accepts either a single ArgusEvent dict or a list of them.
    Each event has: host, event_type, severity, title, description, details, timestamp, etc.
    Heartbeat events update agent_heartbeats; alert events go into main alerts table.
    """
    from shallots.ingest.argus import (
        _parse_argus_event,
        argus_source_allowed,
        normalize_argus_events,
        route_argus_heartbeat,
    )

    daemon = request.app["daemon"]
    if not argus_source_allowed(request.remote or "", daemon.cfg.argus.allowed_source_cidrs):
        return _json_response({"error": "source not allowed"}, status=403)

    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    events = normalize_argus_events(body)
    if events is None:
        return _json_response({"error": "event body must be an object or list of objects"}, status=400)
    from shallots.ingest.argus import argus_secret_allowed

    if not argus_secret_allowed(
        request.headers.get("X-Argus-Secret", ""),
        events,
        shared_secret=daemon.cfg.argus.webhook_secret,
        agent_secrets=daemon.cfg.argus.agent_secrets,
        require_per_agent=daemon.cfg.argus.require_per_agent_secret,
    ):
        return _json_response({"error": "unauthorized"}, status=401)

    commands: dict = {}
    count = 0
    for ev in events:
        if ev.get("event_type") == "heartbeat":
            commands = await route_argus_heartbeat(_db(request), ev, request.remote or "")
            continue

        alert = _parse_argus_event(ev, json.dumps(ev))
        if alert:
            try:
                daemon.alert_queue.put_nowait(alert)
                count += 1
            except asyncio.QueueFull:
                daemon._dropped_alerts = getattr(daemon, "_dropped_alerts", 0) + 1
                log.warning("Argus main API ingest: alert queue full, dropping event")

    return _json_response({"status": "ok", "alerts_ingested": count, "commands": commands})


# ── /api/agents (clove) ────────────────────────────────────────────────────

async def handle_clove_agents(request: web.Request) -> web.Response:
    """GET /api/agents/clove - list all clove agent heartbeats with stale/dead flags."""
    db = _db(request)
    agents = await db.get_agent_heartbeats()
    now = datetime.now(timezone.utc)

    for a in agents:
        # Parse health/baselines JSON
        for field in ("health", "baselines"):
            try:
                a[field] = json.loads(a.get(field, "{}"))
            except (json.JSONDecodeError, TypeError):
                a[field] = {}

        # Compute stale/dead flags
        try:
            last = datetime.fromisoformat(a["last_seen"].replace("Z", "+00:00"))
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            age_min = (now - last).total_seconds() / 60
        except (ValueError, TypeError, KeyError):
            age_min = 999

        if age_min > 30:
            a["status"] = "dead"
        elif age_min > 10:
            a["status"] = "stale"
        else:
            a["status"] = "online"
        a["minutes_since_seen"] = round(age_min, 1)

    return _json_response({"agents": agents, "count": len(agents)})


async def handle_clove_agent_alerts(request: web.Request) -> web.Response:
    """GET /api/agents/{name}/alerts - clove alerts for a specific agent."""
    agent_name = request.match_info["name"]
    qs = request.rel_url.query
    resolved = None
    if "resolved" in qs:
        resolved = int(qs["resolved"])
    limit = min(int(qs.get("limit", 100)), 500)

    db = _db(request)
    alerts = await db.get_clove_alerts(
        agent_name=agent_name, resolved=resolved, limit=limit,
    )
    # Parse details JSON
    for a in alerts:
        try:
            a["details"] = json.loads(a.get("details", "{}"))
        except (json.JSONDecodeError, TypeError):
            a["details"] = {}
    return _json_response({"alerts": alerts, "count": len(alerts)})


async def handle_clove_agent_update(request: web.Request) -> web.Response:
    """POST /api/agents/{name}/update - request agent self-update."""
    agent_name = request.match_info["name"]
    db = _db(request)
    await db.request_agent_update(agent_name)
    return _json_response({"status": "ok", "agent": agent_name, "update_requested": True})
