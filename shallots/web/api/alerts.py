"""Alert CRUD, search, export, notes, pivot, bulk ops, NL query."""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone

from aiohttp import web

from . import _json_response, _db

log = logging.getLogger(__name__)


# ── /api/alerts ───────────────────────────────────────────────────────────────

async def handle_alerts(request: web.Request) -> web.Response:
    """GET /api/alerts - paginated alert list with optional filters.

    Query params:
        limit   int   default 50
        offset  int   default 0
        source  str   filter by source (suricata, wazuh, crowdsec, …)
        severity str  filter by severity (low, medium, high, critical)
        verdict str   filter by verdict (pending, suppress, investigate, escalate)
    """
    qs = request.rel_url.query
    try:
        limit = min(int(qs.get("limit", 50)), 500)
        offset = int(qs.get("offset", 0))
    except ValueError:
        raise web.HTTPBadRequest(reason="limit and offset must be integers")

    source = qs.get("source") or None
    severity = qs.get("severity") or None
    verdict = qs.get("verdict") or None
    since = qs.get("since") or None  # ISO timestamp or relative like "24h", "7d"
    src_ip = qs.get("src_ip") or None
    title = qs.get("title") or None

    db = _db(request)
    alerts = await db.get_alerts(
        limit=limit,
        offset=offset,
        source=source,
        severity=severity,
        verdict=verdict,
        since=since,
        src_ip=src_ip,
        title=title,
    )
    total = await db.get_filtered_count(
        source=source, severity=severity, verdict=verdict, since=since,
    )
    return _json_response({
        "alerts": alerts, "limit": limit, "offset": offset, "total": total,
    })


async def handle_alert_detail(request: web.Request) -> web.Response:
    """GET /api/alerts/{id} - single alert detail."""
    alert_id = request.match_info["id"]
    alert = await _db(request).get_alert(alert_id)
    if alert is None:
        raise web.HTTPNotFound(reason=f"Alert {alert_id!r} not found")
    return _json_response(alert)


async def handle_alert_context(request: web.Request) -> web.Response:
    """GET /api/alerts/{id}/context - investigation context for an alert."""
    alert_id = request.match_info["id"]
    db = _db(request)
    alert = await db.get_alert(alert_id)
    if alert is None:
        raise web.HTTPNotFound(reason=f"Alert {alert_id!r} not found")

    # Triage data (suggested_action, iocs)
    triage = await db.get_triage(alert_id)

    # IP summaries for src and dst
    src_summary = await db.get_ip_alert_summary(alert["src_ip"]) if alert.get("src_ip") else None
    dst_summary = await db.get_ip_alert_summary(alert["dst_ip"]) if alert.get("dst_ip") else None

    # Recent related alerts from same src_ip (last 5, excluding self)
    related = []
    if alert.get("src_ip"):
        rows = await db.get_alerts(src_ip=alert["src_ip"], limit=6, since="7d")
        related = [r for r in rows if r["id"] != alert_id][:5]

    return _json_response({
        "triage": triage,
        "src_summary": src_summary,
        "dst_summary": dst_summary,
        "related_alerts": related,
    })


async def handle_set_verdict(request: web.Request) -> web.Response:
    """PATCH /api/alerts/{id}/verdict - manually set alert verdict.

    Accepts JSON body: {"verdict": "suppress|investigate|escalate"}
    """
    alert_id = request.match_info["id"]
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    verdict = (body.get("verdict") or "").strip().lower()
    if verdict not in ("suppress", "investigate", "escalate"):
        raise web.HTTPBadRequest(reason="verdict must be suppress, investigate, or escalate")

    db = _db(request)
    alert = await db.get_alert(alert_id)
    if alert is None:
        raise web.HTTPNotFound(reason=f"Alert {alert_id!r} not found")

    await db.update_verdict(alert_id, verdict, 1.0, "Manual verdict set via dashboard")
    await db.insert_audit("set_verdict", "alert", alert_id, f"{alert.get('verdict')} → {verdict}")
    # Edge-triage: capture this operator disposition as retrievable grounding.
    try:
        from shallots.ai.embed import embed_text
        _url = getattr(getattr(request.app["daemon"], "cfg", None), "ai", None)
        _url = getattr(_url, "ollama_url", None) or "http://127.0.0.1:11434"
        _txt = f"{alert.get('title','')} | {alert.get('category','')} | {alert.get('description','')}"
        _vec = await embed_text(_txt, base_url=_url)
        await db.record_disposition({"alert_id": alert_id, "title": alert.get("title"),
            "category": alert.get("category"), "host": alert.get("src_asset"),
            "src_ip": alert.get("src_ip"), "dst_ip": alert.get("dst_ip")},
            verdict, "operator dashboard verdict", _vec, "operator")
    except Exception:
        log.debug("disposition capture failed", exc_info=True)
    log.info("Verdict set: %s → %s (alert %s)", alert.get("verdict"), verdict, alert_id[:8])
    return _json_response({"ok": True, "id": alert_id, "verdict": verdict})


# ── /api/alerts/bulk-verdict ──────────────────────────────────────────────────

async def handle_bulk_verdict(request: web.Request) -> web.Response:
    """POST /api/alerts/bulk-verdict - update verdict for multiple alerts.

    Accepts JSON body: {"alert_ids": [...], "verdict": "suppress|investigate|escalate"}
    Max 500 IDs per call.
    """
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    alert_ids = body.get("alert_ids", [])
    if not isinstance(alert_ids, list) or not alert_ids:
        raise web.HTTPBadRequest(reason="alert_ids must be a non-empty list")
    if len(alert_ids) > 500:
        raise web.HTTPBadRequest(reason="Maximum 500 alert IDs per request")

    verdict = (body.get("verdict") or "").strip().lower()
    if verdict not in ("suppress", "investigate", "escalate"):
        raise web.HTTPBadRequest(reason="verdict must be suppress, investigate, or escalate")

    db = _db(request)
    updated = await db.bulk_update_verdict(alert_ids, verdict)
    log.info("Bulk verdict: %s → %d alerts", verdict, updated)
    return _json_response({"ok": True, "updated": updated})


# ── /api/alerts/suppress-filtered ─────────────────────────────────────────────

async def handle_suppress_filtered(request: web.Request) -> web.Response:
    """POST /api/alerts/suppress-filtered - suppress all alerts matching filters.

    Accepts JSON body: {"source": "", "severity": "", "verdict": "", "since": ""}
    """
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    db = _db(request)
    updated = await db.suppress_filtered(
        source=body.get("source") or None,
        severity=body.get("severity") or None,
        verdict=body.get("verdict") or None,
        since=body.get("since") or None,
    )
    log.info("Suppress filtered: %d alerts updated", updated)
    return _json_response({"ok": True, "updated": updated})


# ── /api/alerts/search ────────────────────────────────────────────────────────

async def handle_search(request: web.Request) -> web.Response:
    """GET /api/alerts/search?q=... - FTS5 full-text search."""
    q = request.rel_url.query.get("q", "").strip()
    if not q:
        raise web.HTTPBadRequest(reason="Missing required query parameter: q")
    try:
        limit = min(int(request.rel_url.query.get("limit", 50)), 500)
    except ValueError:
        limit = 50

    results = await _db(request).search_alerts(q, limit=limit)
    return _json_response({"query": q, "results": results, "count": len(results)})


# ── /api/query ────────────────────────────────────────────────────────────────

async def handle_nl_query(request: web.Request) -> web.Response:
    """POST /api/query - natural language query over alerts.

    Accepts JSON body: {"question": "..."}
    Returns: {"question": "...", "sql": "...", "results": [...], "summary": "..."}

    This handler attempts to use the AI triage module to translate the natural-
    language question to SQL.  If AI is unavailable it falls back to a simple
    keyword search so the dashboard is always usable.
    """
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    question = (body.get("question") or "").strip()
    if not question:
        raise web.HTTPBadRequest(reason="Missing required field: question")

    db = _db(request)
    daemon = request.app["daemon"]

    # Try AI-assisted SQL generation
    sql: str = ""
    summary: str = ""
    results: list[dict] = []

    try:
        from shallots.ai.query import translate_question_to_sql
        sql, summary = await translate_question_to_sql(question, daemon.cfg.ai, db)
        if sql:
            results = await db.execute_sql(sql)
    except (ImportError, AttributeError):
        # AI query module not available - fall back to FTS search
        log.debug("AI query module unavailable, falling back to FTS search")
    except Exception:
        log.exception("AI query failed for question: %r", question)

    # Fallback: FTS search on the raw question keywords
    if not results and not sql:
        try:
            results = await db.search_alerts(question, limit=50)
            sql = f"-- FTS fallback for: {question}"
            summary = (
                f"Found {len(results)} alert(s) matching keywords from your question."
                if results
                else "No alerts matched your question."
            )
        except Exception:
            results = []
            summary = "Query could not be executed. Check that your question contains searchable terms."

    # Log query
    try:
        from shallots.store.models import QueryLog
        from shallots.store.db import AlertDB
        qlog = QueryLog(
            question=question,
            generated_sql=sql,
            result_summary=summary or f"{len(results)} result(s)",
        )
        await db.log_query(qlog)
    except Exception:
        pass  # Non-fatal

    return _json_response({
        "question": question,
        "sql": sql,
        "results": results,
        "count": len(results),
        "summary": summary or f"Returned {len(results)} result(s).",
    })


# ── /api/alerts/{id}/acknowledge ─────────────────────────────────────────────

async def handle_acknowledge(request: web.Request) -> web.Response:
    """PATCH /api/alerts/{id}/acknowledge - toggle alert acknowledgement."""
    alert_id = request.match_info["id"]
    db = _db(request)
    alert = await db.get_alert(alert_id)
    if alert is None:
        raise web.HTTPNotFound(reason=f"Alert {alert_id!r} not found")

    if alert.get("acknowledged_at"):
        await db.unacknowledge_alert(alert_id)
        return _json_response({"ok": True, "id": alert_id, "acknowledged": False})
    else:
        await db.acknowledge_alert(alert_id)
        return _json_response({"ok": True, "id": alert_id, "acknowledged": True})


# ── /api/alerts/{id}/notes ──────────────────────────────────────────────────

async def handle_get_notes(request: web.Request) -> web.Response:
    """GET /api/alerts/{id}/notes - list investigation notes."""
    alert_id = request.match_info["id"]
    notes = await _db(request).get_notes(alert_id)
    return _json_response({"alert_id": alert_id, "notes": notes})


async def handle_add_note(request: web.Request) -> web.Response:
    """POST /api/alerts/{id}/notes - add an investigation note."""
    alert_id = request.match_info["id"]
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    note_text = (body.get("note") or "").strip()
    if not note_text:
        raise web.HTTPBadRequest(reason="Missing required field: note")

    note_id = await _db(request).add_note(alert_id, note_text)
    return _json_response({"ok": True, "id": note_id}, status=201)


# ── /api/alerts/export ──────────────────────────────────────────────────────

async def handle_export(request: web.Request) -> web.Response:
    """GET /api/alerts/export?format=csv|json - export filtered alerts."""
    qs = request.rel_url.query
    fmt = qs.get("format", "json").lower()
    source = qs.get("source") or None
    severity = qs.get("severity") or None
    verdict = qs.get("verdict") or None
    since = qs.get("since") or None
    search_query = qs.get("q") or None

    db = _db(request)
    if search_query:
        alerts = await db.search_alerts(search_query, limit=5000)
    else:
        alerts = await db.get_alerts(
            limit=5000, offset=0, source=source, severity=severity,
            verdict=verdict, since=since,
        )

    if fmt == "csv":
        if not alerts:
            return web.Response(
                status=200, content_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=alerts.csv"},
                body="No alerts found\n",
            )
        output = io.StringIO()
        fields = ["id", "timestamp", "source", "severity", "verdict", "title",
                   "src_ip", "dst_ip", "dst_port", "proto", "category"]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for a in alerts:
            writer.writerow(a)
        return web.Response(
            status=200, content_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=alerts.csv"},
            body=output.getvalue(),
        )
    else:
        return web.Response(
            status=200, content_type="application/json",
            headers={"Content-Disposition": "attachment; filename=alerts.json"},
            body=json.dumps(alerts, default=str),
        )


# ── /api/alerts/grouped ─────────────────────────────────────────────────────

async def handle_grouped_alerts(request: web.Request) -> web.Response:
    """GET /api/alerts/grouped - alerts condensed by (src_ip, title)."""
    qs = request.rel_url.query
    try:
        limit = min(int(qs.get("limit", 50)), 500)
        offset = int(qs.get("offset", 0))
    except ValueError:
        raise web.HTTPBadRequest(reason="limit and offset must be integers")

    source = qs.get("source") or None
    severity = qs.get("severity") or None
    verdict = qs.get("verdict") or None
    since = qs.get("since") or None

    db = _db(request)
    groups = await db.get_grouped_alerts(
        limit=limit, offset=offset, source=source,
        severity=severity, verdict=verdict, since=since,
    )
    total = await db.get_filtered_count(
        source=source, severity=severity, verdict=verdict, since=since,
    )
    return _json_response({"groups": groups, "total": total})


async def handle_stale_alerts(request: web.Request) -> web.Response:
    """GET /api/alerts/stale - alerts pending for more than 24 hours."""
    db = _db(request)
    limit = min(int(request.rel_url.query.get("limit", 200)), 500)
    cursor = await db._db.execute(
        "SELECT * FROM alerts WHERE verdict = 'pending' "
        "AND ingested_at IS NOT NULL AND ingested_at < datetime('now', '-1 day') "
        "ORDER BY ingested_at ASC LIMIT ?",
        (limit,),
    )
    rows = [dict(r) for r in await cursor.fetchall()]
    # Add age_hours to each
    now = datetime.now(timezone.utc)
    for r in rows:
        try:
            ing = datetime.fromisoformat(r["ingested_at"].replace("Z", "+00:00"))
            r["age_hours"] = round((now - ing).total_seconds() / 3600, 1)
        except Exception:
            r["age_hours"] = 0
    return _json_response({"alerts": rows, "total": len(rows)})


async def handle_alert_chat(request: web.Request) -> web.Response:
    """GET /api/alerts/{id}/chat - get chat history for an alert."""
    alert_id = request.match_info["id"]
    db = _db(request)
    history = await db.get_chat_history(alert_id, limit=50)
    return _json_response({"alert_id": alert_id, "messages": history})


# ── /api/pivot ────────────────────────────────────────────────────────────────

async def handle_pivot(request: web.Request) -> web.Response:
    """POST /api/pivot - unified view of all alerts + incidents for given IPs.

    Body: {"ips": [...], "incident_id": "optional", "limit": 200}
    When incident_id is provided, scopes alerts to ±24h of the incident and
    highlights the incident's own linked alerts.
    """
    import datetime as _dt

    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    ips = body.get("ips", [])
    if not isinstance(ips, list) or not ips:
        raise web.HTTPBadRequest(reason="ips must be a non-empty list")
    ips = [str(ip).strip() for ip in ips[:20]]

    incident_id = body.get("incident_id")
    limit = min(int(body.get("limit", 200)), 500)
    db = _db(request)

    # If coming from an incident, get its details for time scoping
    incident = None
    linked_alert_ids = set()
    time_filter = ""
    time_params = []
    if incident_id:
        incident = await db.get_incident(incident_id)
        if incident:
            linked_alert_ids = set(incident.get("alert_ids") or [])
            # Scope to ±24h of incident creation
            try:
                created = _dt.datetime.fromisoformat(incident["created_at"].replace("Z", "+00:00"))
            except Exception:
                created = _dt.datetime.now(_dt.timezone.utc)
            window_start = (created - _dt.timedelta(hours=24)).isoformat()
            window_end = (created + _dt.timedelta(hours=24)).isoformat()
            time_filter = " AND timestamp BETWEEN ? AND ?"
            time_params = [window_start, window_end]

    # Fetch alerts matching any of the IPs (src or dst), time-scoped if from incident
    ip_placeholders = ",".join("?" for _ in ips)
    alert_rows = await db.execute_sql(
        f"""SELECT id, timestamp, source, severity, title, src_ip, dst_ip,
                   dst_port, proto, verdict, category
            FROM alerts
            WHERE (src_ip IN ({ip_placeholders}) OR dst_ip IN ({ip_placeholders}))
            {time_filter}
            ORDER BY timestamp DESC
            LIMIT ?""",
        ips + ips + time_params + [limit],
    )

    # Mark which alerts are directly linked to the source incident
    for row in alert_rows:
        row["linked"] = row["id"] in linked_alert_ids

    # Fetch incidents that share these IPs (only the specific one + closely related)
    all_incidents = await db.get_incidents(limit=200)
    ip_set = set(ips)
    related_incidents = []
    for inc in all_incidents:
        inc_ips = set(inc.get("affected_ips") or [])
        if inc_ips & ip_set:
            inc["is_source"] = (inc["id"] == incident_id) if incident_id else False
            related_incidents.append(inc)

    return _json_response({
        "ips": ips,
        "alerts": alert_rows,
        "alert_count": len(alert_rows),
        "incidents": related_incidents,
        "incident_count": len(related_incidents),
        "time_scoped": bool(incident_id and incident),
        "source_incident_id": incident_id,
    })
