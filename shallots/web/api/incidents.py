"""Incidents, correlations, clusters."""

from __future__ import annotations

import json
import logging

from aiohttp import web

from . import _json_response, _db, _call_ai

log = logging.getLogger(__name__)


# ── /api/correlations ──────────────────────────────────────────────────────

async def handle_correlations(request: web.Request) -> web.Response:
    """GET /api/correlations — list recent correlation groups."""
    try:
        limit = min(int(request.rel_url.query.get("limit", 20)), 100)
    except ValueError:
        limit = 20
    db = _db(request)
    cursor = await db._db.execute(
        "SELECT * FROM correlations ORDER BY created_at DESC LIMIT ?", (limit,)
    )
    rows = [dict(r) for r in await cursor.fetchall()]
    # Parse alert_ids JSON strings
    for r in rows:
        try:
            r["alert_ids"] = json.loads(r.get("alert_ids", "[]"))
        except (json.JSONDecodeError, TypeError):
            r["alert_ids"] = []
    return _json_response({"correlations": rows, "count": len(rows)})


async def handle_correlation_alerts(request: web.Request) -> web.Response:
    """GET /api/correlations/{id}/alerts — fetch alerts belonging to a correlation."""
    corr_id = request.match_info["id"]
    db = _db(request)
    cursor = await db._db.execute(
        "SELECT alert_ids FROM correlations WHERE id = ?", (corr_id,)
    )
    row = await cursor.fetchone()
    if row is None:
        raise web.HTTPNotFound(reason=f"Correlation {corr_id!r} not found")
    try:
        alert_ids = json.loads(row["alert_ids"] or "[]")
    except (json.JSONDecodeError, TypeError):
        alert_ids = []
    alerts = await db.get_alerts_by_ids(alert_ids)
    return _json_response({"alerts": alerts, "count": len(alerts)})


async def handle_delete_correlation(request: web.Request) -> web.Response:
    """DELETE /api/correlations/{id} — dismiss a single correlation."""
    corr_id = request.match_info["id"]
    db = _db(request)
    await db._db.execute("DELETE FROM correlations WHERE id = ?", (corr_id,))
    await db._db.commit()
    return _json_response({"ok": True, "deleted": corr_id})


async def handle_clear_correlations(request: web.Request) -> web.Response:
    """POST /api/correlations/clear — dismiss all correlations."""
    db = _db(request)
    cursor = await db._db.execute("SELECT COUNT(*) FROM correlations")
    row = await cursor.fetchone()
    count = row[0] if row else 0
    await db._db.execute("DELETE FROM correlations")
    await db._db.commit()
    return _json_response({"ok": True, "deleted": count})


async def handle_correlation_ai(request: web.Request) -> web.Response:
    """POST /api/correlations/{id}/ai — AI analysis of a correlation pattern."""
    corr_id = request.match_info["id"]
    db = _db(request)
    daemon = request.app["daemon"]

    cursor = await db._db.execute(
        "SELECT * FROM correlations WHERE id = ?", (corr_id,)
    )
    corr = await cursor.fetchone()
    if corr is None:
        raise web.HTTPNotFound(reason=f"Correlation {corr_id!r} not found")
    corr = dict(corr)

    try:
        alert_ids = json.loads(corr.get("alert_ids", "[]"))
    except (json.JSONDecodeError, TypeError):
        alert_ids = []

    alerts = await db.get_alerts_by_ids(alert_ids)
    alerts_json = json.dumps([
        {k: v for k, v in a.items() if k != "raw" and v is not None and v != ""}
        for a in alerts
    ], indent=2, default=str)

    # Knowledge base RAG
    search_terms = f"{corr.get('pattern', '')} {corr.get('summary', '')}"
    kb_matches = await db.search_knowledge(search_terms, limit=5) if search_terms.strip() else []
    knowledge_section = ""
    if kb_matches:
        knowledge_section = "Knowledge Base Context:\n" + "\n".join(
            f"- [{m['category']}] {m['topic']}: {m['content']}"
            for m in kb_matches
        )

    from shallots.ai.prompts import CORR_ANALYSIS_SYSTEM, CORR_ANALYSIS_TEMPLATE
    user_prompt = CORR_ANALYSIS_TEMPLATE.format(
        pattern=corr.get("pattern", "Unknown pattern"),
        summary=corr.get("summary", ""),
        severity=corr.get("severity", "medium"),
        alert_count=len(alerts),
        alerts_json=alerts_json,
        knowledge_section=knowledge_section,
    )

    # Check for SSE streaming
    accept = request.headers.get("Accept", "")
    if "text/event-stream" in accept:
        cfg = daemon.cfg.ai
        if cfg.tier == "none" or not cfg.ollama_url:
            return _json_response({
                "response": "AI is not configured. Set an AI tier in settings.",
                "correlation_id": corr_id,
            })
        from shallots.ai.ollama_client import OllamaClient
        client = OllamaClient(base_url=cfg.ollama_url)
        response = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
        await response.prepare(request)
        try:
            session = await client._get_session()
            payload = {
                "model": cfg.ollama_model or "llama3.2",
                "prompt": user_prompt,
                "system": CORR_ANALYSIS_SYSTEM,
                "stream": True,
            }
            async with session.post(
                f"{cfg.ollama_url}/api/generate", json=payload
            ) as ollama_resp:
                async for line in ollama_resp.content:
                    text = line.decode("utf-8", errors="replace").strip()
                    if not text:
                        continue
                    try:
                        chunk = json.loads(text)
                        token = chunk.get("response", "")
                        if token:
                            await response.write(
                                f"data: {json.dumps({'token': token})}\n\n".encode()
                            )
                    except json.JSONDecodeError:
                        continue
            await response.write(b"data: [DONE]\n\n")
        except Exception as exc:
            await response.write(
                f"data: {json.dumps({'error': str(exc)})}\n\n".encode()
            )
        finally:
            await client.close()
        return response

    # Non-streaming
    ai_text = await _call_ai(daemon, CORR_ANALYSIS_SYSTEM, user_prompt)
    return _json_response({"response": ai_text, "correlation_id": corr_id})


# ── Clusters ──────────────────────────────────────────────────────────────────

async def handle_clusters(request: web.Request) -> web.Response:
    """GET /api/clusters — paginated cluster list."""
    qs = request.rel_url.query
    try:
        limit = min(int(qs.get("limit", 50)), 500)
        offset = int(qs.get("offset", 0))
    except ValueError:
        raise web.HTTPBadRequest(reason="limit and offset must be integers")

    verdict = qs.get("verdict") or None
    sort = qs.get("sort", "last_seen")

    db = _db(request)
    clusters = await db.get_clusters(limit=limit, offset=offset, verdict=verdict, sort=sort)
    total = await db.get_cluster_count(verdict=verdict)
    return _json_response({"clusters": clusters, "total": total})


async def handle_cluster_detail(request: web.Request) -> web.Response:
    """GET /api/clusters/{id} — cluster detail with member alerts."""
    cluster_id = request.match_info["id"]
    db = _db(request)
    cluster = await db.get_cluster(cluster_id)
    if not cluster:
        raise web.HTTPNotFound(reason="Cluster not found")
    alerts = await db.get_cluster_alerts(cluster_id)
    cluster["alerts"] = alerts
    return _json_response(cluster)


async def handle_cluster_verdict(request: web.Request) -> web.Response:
    """PATCH /api/clusters/{id}/verdict — set verdict on a cluster + all member alerts."""
    cluster_id = request.match_info["id"]
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Invalid JSON body")

    verdict = body.get("verdict", "")
    valid = {"suppress", "investigate", "escalate", "pending", "noise"}
    if verdict not in valid:
        raise web.HTTPBadRequest(reason=f"verdict must be one of: {', '.join(sorted(valid))}")

    reasoning = body.get("reasoning", "")
    db = _db(request)
    cluster = await db.get_cluster(cluster_id)
    if not cluster:
        raise web.HTTPNotFound(reason="Cluster not found")

    updated = await db.set_cluster_verdict(cluster_id, verdict, reasoning)
    # Edge-triage: capture this operator disposition (Investigate-panel verb) as grounding.
    try:
        from shallots.ai.embed import embed_text
        _members = await db.get_cluster_alerts(cluster_id, limit=1)
        _a = _members[0] if _members else {}
        _url = getattr(getattr(request.app["daemon"], "cfg", None), "ai", None)
        _url = getattr(_url, "ollama_url", None) or "http://127.0.0.1:11434"
        _txt = f"{_a.get('title', cluster.get('title',''))} | {_a.get('category','')} | {_a.get('description','')}"
        _vec = await embed_text(_txt, base_url=_url)
        await db.record_disposition({"cluster_id": cluster_id, "title": cluster.get("title"),
            "category": _a.get("category"), "host": _a.get("src_asset"),
            "src_ip": _a.get("src_ip"), "dst_ip": _a.get("dst_ip")},
            verdict, reasoning or "operator investigate-panel disposition", _vec, "operator")
    except Exception:
        log.debug("cluster disposition capture failed", exc_info=True)
    return _json_response({"cluster_id": cluster_id, "verdict": verdict, "alerts_updated": updated})


async def handle_cluster_stats(request: web.Request) -> web.Response:
    """GET /api/clusters/stats — cluster summary counts."""
    db = _db(request)
    total = await db.get_cluster_count()
    pending = await db.get_cluster_count("pending")
    suppressed = await db.get_cluster_count("suppress")
    escalated = await db.get_cluster_count("escalate")
    return _json_response({
        "total": total,
        "pending": pending,
        "suppressed": suppressed,
        "escalated": escalated,
    })


# ── /api/incidents ────────────────────────────────────────────────────────────

async def handle_incidents(request: web.Request) -> web.Response:
    """GET /api/incidents — list incidents with optional status filter."""
    qs = request.rel_url.query
    status = qs.get("status")
    limit = min(int(qs.get("limit", 50)), 200)
    offset = int(qs.get("offset", 0))
    incidents = await _db(request).get_incidents(status=status, limit=limit, offset=offset)
    return _json_response(incidents)


async def handle_incident_detail(request: web.Request) -> web.Response:
    """GET /api/incidents/{id} — single incident with full details."""
    iid = request.match_info["id"]
    incident = await _db(request).get_incident(iid)
    if not incident:
        raise web.HTTPNotFound()
    # Also fetch the linked alerts
    alert_ids = incident.get("alert_ids", [])
    if alert_ids:
        placeholders = ",".join("?" for _ in alert_ids[:50])
        try:
            alerts = await _db(request).execute_sql(
                f"SELECT id, timestamp, source, severity, title, src_ip, dst_ip, dst_port, verdict FROM alerts WHERE id IN ({placeholders}) ORDER BY timestamp DESC",
                alert_ids[:50],
            )
            incident["alerts"] = alerts
        except Exception:
            incident["alerts"] = []
    else:
        incident["alerts"] = []
    return _json_response(incident)


async def handle_incident_status(request: web.Request) -> web.Response:
    """PATCH /api/incidents/{id}/status — update incident status."""
    iid = request.match_info["id"]
    body = await request.json()
    status = body.get("status", "")
    if status not in ("new", "investigating", "resolved", "false_positive"):
        raise web.HTTPBadRequest(reason="Invalid status")
    ok = await _db(request).update_incident_status(iid, status, resolved_by=body.get("resolved_by", ""))
    if not ok:
        raise web.HTTPNotFound()
    return _json_response({"ok": True, "status": status})


async def handle_incident_counts(request: web.Request) -> web.Response:
    """GET /api/incidents/counts — count by status."""
    counts = await _db(request).get_incident_counts()
    return _json_response(counts)


async def handle_runbook_execute(request: web.Request) -> web.Response:
    """POST /api/incidents/{id}/runbook/execute — execute a runbook command on the server."""
    body = await request.json()
    command = body.get("command", "").strip()
    if not command:
        raise web.HTTPBadRequest(reason="No command provided")

    # SECURITY: runbook commands are AI-generated, and the alert content feeding
    # that model is attacker-influenceable, so this endpoint must NEVER run an
    # arbitrary shell string (the old substring denylist was trivially bypassed).
    # Parse to argv and execute WITHOUT a shell, allowing only a fixed set of
    # safe read-only diagnostics (+ ufw, the one mutating response action the
    # runbooks use). With no shell, any metacharacters are inert literal args.
    import shlex, asyncio as _asyncio
    try:
        argv = shlex.split(command)
    except ValueError:
        return _json_response({"error": "Command rejected: could not be parsed."}, status=400)
    if not argv:
        raise web.HTTPBadRequest(reason="No command provided")
    # INERT local-state diagnostics only, plus ufw (the one mutating response the
    # runbooks use). Deliberately EXCLUDES everything that can reach the network
    # or disclose secrets when run as root: `ip` (netns exec = RCE), `whois`
    # (arbitrary TCP send / SSRF), `dig`/`nslookup`/`host`/`ping`/`traceroute`
    # (DNS/connectivity SSRF), `getent` (`getent shadow`/`passwd` dumps hashes),
    # `journalctl` (log secrets), `ps`/`ss` (cmdline/connection disclosure),
    # `who`/`w`/`last`/`arp`. Anything not here, the operator runs manually.
    _SAFE = {"id", "uptime", "free", "df", "uname", "date", "hostname",
             "geoiplookup", "ufw"}
    base = argv[0]
    check = argv[1] if base == "sudo" and len(argv) > 1 else base
    if base == "sudo" and check != "ufw":
        return _json_response({"error": "Command not permitted: sudo may only run ufw."}, status=403)
    if check not in _SAFE:
        return _json_response({"error": "Command not permitted: '" + str(check) + "' is not on the runbook allowlist; run it manually if needed."}, status=403)
    try:
        proc = await _asyncio.create_subprocess_exec(
            *argv,
            stdout=_asyncio.subprocess.PIPE,
            stderr=_asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await _asyncio.wait_for(proc.communicate(), timeout=30)
        except _asyncio.TimeoutError:
            # Kill the runaway child so repeated timeouts don't leak root processes.
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise
        return _json_response({
            "stdout": stdout.decode(errors="replace")[:10000],
            "stderr": stderr.decode(errors="replace")[:5000],
            "returncode": proc.returncode,
        })
    except _asyncio.TimeoutError:
        return _json_response({"error": "Command timed out after 30 seconds"}, status=408)
    except Exception as exc:
        return _json_response({"error": str(exc)}, status=500)


async def handle_runbook_interpret(request: web.Request) -> web.Response:
    """POST /api/incidents/{id}/runbook/interpret — AI interprets command output."""
    body = await request.json()
    command = body.get("command", "")
    stdout = body.get("stdout", "")
    stderr = body.get("stderr", "")
    context = body.get("context", "")
    expect = body.get("expect", "")
    bad_sign = body.get("bad_sign", "")

    daemon = request.app["daemon"]
    if daemon.cfg.ai.tier == "none":
        return _json_response({"interpretation": "AI is not configured. Review the output manually."})

    from shallots.ai.ollama_client import OllamaClient
    client = OllamaClient(base_url=daemon.cfg.ai.ollama_url or "http://localhost:11434")

    prompt = f"""You ran this command as part of a security investigation:

Command: {command}

Output (stdout):
{stdout[:3000]}

{f"Errors (stderr): {stderr[:1000]}" if stderr else ""}

Context: {context}
{f"Expected (safe) output: {expect}" if expect else ""}
{f"Suspicious output would look like: {bad_sign}" if bad_sign else ""}

In 2-4 sentences, tell the operator:
1. What this output means (plain English)
2. Whether it looks normal or suspicious
3. What they should do next

Be specific — reference actual values from the output. This is a home network."""

    try:
        raw = await client.generate(
            prompt=prompt,
            model=daemon.cfg.ai.ollama_model,
            system="You are a security analyst helping a home network operator interpret command output. Be clear, specific, and practical. No jargon.",
        )
        await client.close()
        return _json_response({"interpretation": raw.strip()})
    except Exception as exc:
        await client.close()
        return _json_response({"interpretation": f"AI interpretation failed: {exc}. Review the output manually."})


async def handle_incident_decision(request: web.Request) -> web.Response:
    """POST /api/incidents/{id}/decide — record decision and update status."""
    iid = request.match_info["id"]
    body = await request.json()
    decision = body.get("decision", "")
    if decision not in ("resolved", "false_positive", "investigating"):
        raise web.HTTPBadRequest(reason="Invalid decision")

    db = _db(request)

    # Get incident for pattern key
    incident = await db.get_incident(iid)
    if not incident:
        raise web.HTTPNotFound()

    # Record the learning decision
    category = incident.get("category", "other")
    # Build pattern key from category + first affected IP
    ips = incident.get("affected_ips", [])
    first_ip = ips[0] if ips else ""
    pattern_key = f"{category}:{incident.get('title', '')}"

    await db.record_incident_decision(iid, category, pattern_key, decision)

    # Update incident status
    status = decision
    await db.update_incident_status(iid, status)

    # Audit + timeline
    await db.insert_audit("incident_decision", "incident", iid, f"Decision: {decision}")
    await db.add_incident_event(iid, "decision", f"Marked as {decision}", "", "analyst")

    # Check if this pattern should be auto-dismissed in future
    suggestion = None
    if decision == "false_positive":
        history = await db.get_pattern_history(pattern_key)
        fp_count = sum(h["count"] for h in history if h["decision"] == "false_positive")
        if fp_count >= 3:
            suggestion = {
                "message": f"You've marked {fp_count} similar incidents as false positive. Want to auto-dismiss these in the future?",
                "pattern_key": pattern_key,
                "category": category,
            }

    return _json_response({"ok": True, "status": status, "suggestion": suggestion})


async def handle_auto_dismiss_candidates(request: web.Request) -> web.Response:
    """GET /api/incidents/auto-dismiss — get patterns that could be auto-dismissed."""
    candidates = await _db(request).get_auto_dismiss_candidates()
    return _json_response(candidates)


# ── Incident Notes & Timeline ─────────────────────────────────────────────

async def handle_incident_notes(request: web.Request) -> web.Response:
    """GET /api/incidents/{id}/notes — get all notes for an incident."""
    iid = request.match_info["id"]
    notes = await _db(request).get_incident_notes(iid)
    return _json_response(notes)


async def handle_add_incident_note(request: web.Request) -> web.Response:
    """POST /api/incidents/{id}/notes — add a note to an incident."""
    iid = request.match_info["id"]
    body = await request.json()
    note = (body.get("note") or "").strip()
    if not note:
        raise web.HTTPBadRequest(reason="Note text required")
    author = body.get("author", "analyst")
    db = _db(request)
    nid = await db.add_incident_note(iid, note, author)
    await db.add_incident_event(iid, "note_added", f"Note added by {author}", note, author)
    await db.insert_audit("add_incident_note", "incident", iid, f"Note: {note[:100]}")
    return _json_response({"ok": True, "id": nid})


async def handle_incident_timeline(request: web.Request) -> web.Response:
    """GET /api/incidents/{id}/timeline — full chronological timeline."""
    iid = request.match_info["id"]
    timeline = await _db(request).get_incident_timeline(iid)
    return _json_response(timeline)
