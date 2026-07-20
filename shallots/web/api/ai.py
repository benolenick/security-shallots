"""AI status/mode/suggestions, autopilot, investigations, wiki, settings."""

from __future__ import annotations

import json
import logging

import aiohttp
from aiohttp import web

from . import _json_response, _db, _call_ai

log = logging.getLogger(__name__)


# ── /api/alerts/{id}/ai/{action} ─────────────────────────────────────────────

async def _build_ai_context(db, alert: dict, action: str,
                             user_message: str = "") -> dict:
    """Build context dict for AI prompt rendering."""
    from shallots.ai.prompts import (
        EXPLAIN_SYSTEM, EXPLAIN_TEMPLATE, REMEDIATE_SYSTEM, REMEDIATE_TEMPLATE,
        HUNT_SYSTEM, HUNT_TEMPLATE, CHAT_SYSTEM, CHAT_TEMPLATE,
    )
    alert_id = alert["id"]

    # Common context pieces
    triage = await db.get_triage(alert_id)
    triage_section = ""
    if triage:
        triage_section = (
            f"AI Triage:\n  Verdict: {triage.get('verdict')}\n"
            f"  Confidence: {triage.get('confidence')}\n"
            f"  Reasoning: {triage.get('reasoning')}\n"
            f"  Suggested action: {triage.get('suggested_action')}"
        )

    # IP reputation
    reputation_section = ""
    for label, ip in [("Source IP", alert.get("src_ip")), ("Dest IP", alert.get("dst_ip"))]:
        if ip:
            rep = await db.get_ip_reputation(ip)
            if rep:
                reputation_section += (
                    f"\n{label} ({ip}) reputation: {rep.get('verdict', 'unknown')}"
                    f" - VT: {rep.get('vt_malicious', 0)} malicious"
                    f", AbuseIPDB: {rep.get('abuse_score', 0)}%"
                    f", Country: {rep.get('country', '?')}"
                    f", ISP: {rep.get('isp', '?')}"
                )

    # Knowledge base RAG
    search_terms = " ".join(filter(None, [
        alert.get("title", ""),
        alert.get("category", ""),
        user_message,
    ]))
    kb_matches = await db.search_knowledge(search_terms, limit=5) if search_terms.strip() else []
    knowledge_section = ""
    if kb_matches:
        knowledge_section = "Knowledge Base Context:\n" + "\n".join(
            f"- [{m['category']}] {m['topic']}: {m['content']}"
            for m in kb_matches
        )

    # Related alerts
    related_section = ""
    ip_summary_section = ""
    correlation_section = ""

    if action in ("explain", "hunt"):
        if alert.get("src_ip"):
            rows = await db.get_alerts(src_ip=alert["src_ip"], limit=10, since="7d")
            related = [r for r in rows if r["id"] != alert_id][:8]
            if related:
                related_section = "Related alerts from same source IP:\n" + "\n".join(
                    f"  - [{r['severity']}] {r['title']} at {r['timestamp']}"
                    for r in related
                )

    if action == "hunt":
        # IP summaries
        for label, ip in [("Source", alert.get("src_ip")), ("Dest", alert.get("dst_ip"))]:
            if ip:
                summary = await db.get_ip_alert_summary(ip)
                ip_summary_section += (
                    f"\n{label} IP ({ip}): {summary['total']} total alerts, "
                    f"{summary['last_24h']} in last 24h. "
                    f"Top signatures: {', '.join(t['title'] for t in summary['top_titles'][:3])}"
                )

    # Chat history (for chat action)
    chat_history = ""
    if action == "chat":
        history = await db.get_chat_history(alert_id, limit=10)
        if history:
            chat_history = "\n".join(
                f"{'User' if m['role'] == 'user' else 'Assistant'}: {m['content']}"
                for m in history
            )

    # Select prompt pair
    alert_json = json.dumps({
        k: v for k, v in alert.items()
        if k != "raw" and v is not None and v != ""
    }, indent=2, default=str)

    prompts = {
        "explain": (EXPLAIN_SYSTEM, EXPLAIN_TEMPLATE),
        "remediate": (REMEDIATE_SYSTEM, REMEDIATE_TEMPLATE),
        "hunt": (HUNT_SYSTEM, HUNT_TEMPLATE),
        "chat": (CHAT_SYSTEM, CHAT_TEMPLATE),
    }
    system_prompt, template = prompts[action]

    user_prompt = template.format(
        alert_json=alert_json,
        triage_section=triage_section,
        reputation_section=reputation_section,
        knowledge_section=knowledge_section,
        related_section=related_section,
        ip_summary_section=ip_summary_section,
        correlation_section=correlation_section,
        chat_history=chat_history,
        user_message=user_message,
    )

    return {"system": system_prompt, "user": user_prompt}


async def _stream_ai_response(request, daemon, db, alert_id, action, ctx):
    """Stream AI response as Server-Sent Events."""
    response = web.StreamResponse(
        status=200,
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )
    await response.prepare(request)

    cfg = daemon.cfg.ai
    full_text = ""

    try:
        if cfg.ollama_url and cfg.tier != "none":
            # Stream from Ollama
            from shallots.ai.ollama_client import OllamaClient
            client = OllamaClient(base_url=cfg.ollama_url)
            session = await client._get_session()
            payload = {
                "model": cfg.ollama_model or "llama3.2",
                "prompt": ctx["user"],
                "system": ctx["system"],
                "stream": True,
            }
            async with session.post(f"{cfg.ollama_url.rstrip('/')}/api/generate",
                                     json=payload) as resp:
                async for line in resp.content:
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("response", "")
                        if token:
                            full_text += token
                            await response.write(
                                f"data: {json.dumps({'token': token})}\n\n".encode()
                            )
                        if chunk.get("done"):
                            break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
            await client.close()
        else:
            # Fallback to non-streaming
            full_text = await _call_ai(daemon, ctx["system"], ctx["user"])
            await response.write(
                f"data: {json.dumps({'token': full_text})}\n\n".encode()
            )
    except Exception as exc:
        full_text = f"AI streaming error: {exc}"
        await response.write(
            f"data: {json.dumps({'token': full_text, 'error': True})}\n\n".encode()
        )

    # Send done signal
    await response.write(f"data: {json.dumps({'done': True})}\n\n".encode())

    # Store the full response
    if full_text:
        await db.add_chat_message(alert_id, "assistant", full_text, action)

    return response


async def handle_ai_consult(request: web.Request) -> web.Response:
    """POST /api/alerts/{id}/ai/{action} - AI investigation actions."""
    alert_id = request.match_info["id"]
    action = request.match_info["action"]

    if action not in ("explain", "remediate", "hunt", "chat"):
        raise web.HTTPBadRequest(reason="Action must be explain, remediate, hunt, or chat")

    db = _db(request)
    daemon = request.app["daemon"]

    alert = await db.get_alert(alert_id)
    if alert is None:
        raise web.HTTPNotFound(reason=f"Alert {alert_id!r} not found")

    # For chat, get user message
    user_message = ""
    if action == "chat":
        try:
            body = await request.json()
            user_message = (body.get("message") or "").strip()
        except Exception:
            raise web.HTTPBadRequest(reason="Chat action requires JSON body with 'message'")
        if not user_message:
            raise web.HTTPBadRequest(reason="Message cannot be empty")
        # Store user message
        await db.add_chat_message(alert_id, "user", user_message, action)

    ctx = await _build_ai_context(db, alert, action, user_message)

    # Check for SSE streaming request
    accept = request.headers.get("Accept", "")
    if "text/event-stream" in accept:
        return await _stream_ai_response(request, daemon, db, alert_id, action, ctx)

    # Non-streaming: get full response
    ai_text = await _call_ai(daemon, ctx["system"], ctx["user"])

    # Store assistant response
    await db.add_chat_message(alert_id, "assistant", ai_text, action)

    return _json_response({"response": ai_text, "action": action, "alert_id": alert_id})


# ── /api/settings/ai ─────────────────────────────────────────────────────────

async def handle_get_ai_settings(request: web.Request) -> web.Response:
    """GET /api/settings/ai - current AI configuration (secrets masked)."""
    cfg = request.app["daemon"].cfg.ai
    return _json_response({
        "tier": cfg.tier,
        "ollama_url": cfg.ollama_url,
        "ollama_model": cfg.ollama_model,
        "has_openai_key": bool(cfg.openai_api_key),
        "has_anthropic_key": bool(cfg.anthropic_api_key),
        "batch_size": cfg.batch_size,
    })


async def handle_patch_ai_settings(request: web.Request) -> web.Response:
    """PATCH /api/settings/ai - update AI config at runtime + persist to config.yaml."""
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    daemon = request.app["daemon"]
    cfg = daemon.cfg.ai

    # Update in-memory config
    if "tier" in body:
        cfg.tier = body["tier"]
    if "ollama_url" in body:
        cfg.ollama_url = body["ollama_url"]
    if "ollama_model" in body:
        cfg.ollama_model = body["ollama_model"]
    if "openai_api_key" in body and body["openai_api_key"]:
        cfg.openai_api_key = body["openai_api_key"]
    if "anthropic_api_key" in body and body["anthropic_api_key"]:
        cfg.anthropic_api_key = body["anthropic_api_key"]

    # Persist to config.yaml
    try:
        import yaml
        from shallots.config import CONFIG_SEARCH_PATHS
        config_path = None
        for p in CONFIG_SEARCH_PATHS:
            if p.exists():
                config_path = p
                break
        if config_path:
            raw = yaml.safe_load(config_path.read_text()) or {}
            if "ai" not in raw:
                raw["ai"] = {}
            raw["ai"]["tier"] = cfg.tier
            raw["ai"]["ollama_url"] = cfg.ollama_url
            raw["ai"]["ollama_model"] = cfg.ollama_model
            if body.get("openai_api_key"):
                raw["ai"]["openai_api_key"] = cfg.openai_api_key
            if body.get("anthropic_api_key"):
                raw["ai"]["anthropic_api_key"] = cfg.anthropic_api_key
            config_path.write_text(yaml.dump(raw, default_flow_style=False))
            log.info("AI settings persisted to %s", config_path)
    except Exception as exc:
        log.warning("Failed to persist AI settings: %s", exc)

    log.info("AI settings updated: tier=%s, model=%s", cfg.tier, cfg.ollama_model)
    return _json_response({"ok": True, "tier": cfg.tier, "ollama_model": cfg.ollama_model})


async def handle_ai_scan(request: web.Request) -> web.Response:
    """POST /api/settings/ai/scan - auto-discover available LLM providers."""
    providers = []
    cfg = request.app["daemon"].cfg.ai

    # Scan Ollama instances
    ollama_urls = set()
    if cfg.ollama_url:
        ollama_urls.add(cfg.ollama_url.rstrip("/"))
    ollama_urls.add("http://localhost:11434")

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for url in ollama_urls:
            try:
                async with session.get(f"{url}/api/tags") as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        models = [m.get("name", "") for m in data.get("models", [])]
                        providers.append({
                            "type": "ollama",
                            "url": url,
                            "models": models,
                            "status": "online",
                        })
            except Exception:
                providers.append({
                    "type": "ollama",
                    "url": url,
                    "models": [],
                    "status": "offline",
                })

    # Check OpenAI
    if cfg.openai_api_key:
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"Authorization": f"Bearer {cfg.openai_api_key}"}
                async with session.get("https://api.openai.com/v1/models",
                                        headers=headers) as resp:
                    if resp.status == 200:
                        providers.append({
                            "type": "openai", "url": "https://api.openai.com",
                            "models": ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"],
                            "status": "online",
                        })
                    else:
                        providers.append({
                            "type": "openai", "url": "https://api.openai.com",
                            "models": [], "status": "auth_failed",
                        })
        except Exception:
            providers.append({
                "type": "openai", "url": "https://api.openai.com",
                "models": [], "status": "offline",
            })

    # Check Anthropic
    if cfg.anthropic_api_key:
        providers.append({
            "type": "anthropic", "url": "https://api.anthropic.com",
            "models": ["claude-3-haiku-20240307", "claude-3-sonnet-20240229"],
            "status": "configured",
        })

    return _json_response({"providers": providers})


# ── AI Autopilot API ──────────────────────────────────────────────────────────

async def handle_ai_status(request: web.Request) -> web.Response:
    """GET /api/ai/status - current autopilot mode, stats, last action."""
    db = _db(request)
    daemon = request.app["daemon"]
    stats = await db.get_ai_stats()
    mode = "off"
    if hasattr(daemon, "_autopilot"):
        mode = daemon._autopilot._mode
        stats.update(daemon._autopilot.get_stats())
    stats["mode"] = mode
    return _json_response(stats)


async def handle_ai_set_mode(request: web.Request) -> web.Response:
    """POST /api/ai/mode - set autopilot mode (off/copilot/autopilot)."""
    daemon = request.app["daemon"]
    try:
        body = await request.json()
    except Exception:
        return _json_response({"error": "invalid JSON"}, status=400)
    mode = body.get("mode", "")
    if mode not in ("off", "copilot", "autopilot"):
        return _json_response({"error": "mode must be off, copilot, or autopilot"}, status=400)
    if hasattr(daemon, "_autopilot"):
        await daemon._autopilot.set_mode(mode)
    return _json_response({"mode": mode})


async def handle_ai_decisions(request: web.Request) -> web.Response:
    """GET /api/ai/decisions - paginated decision log."""
    db = _db(request)
    limit = int(request.query.get("limit", "50"))
    offset = int(request.query.get("offset", "0"))
    decisions = await db.get_ai_decisions(limit=limit, offset=offset)
    return _json_response(decisions)


async def handle_ai_suggestions(request: web.Request) -> web.Response:
    """GET /api/ai/suggestions - pending copilot suggestions."""
    db = _db(request)
    suggestions = await db.get_ai_decisions(limit=50, status="pending")
    return _json_response(suggestions)


async def handle_ai_suggestion_approve(request: web.Request) -> web.Response:
    """POST /api/ai/suggestions/{id}/approve - approve a copilot suggestion."""
    db = _db(request)
    daemon = request.app["daemon"]
    decision_id = request.match_info["id"]
    ok = await db.resolve_ai_decision(decision_id, resolved_by="human")
    if not ok:
        return _json_response({"error": "not found"}, status=404)
    # Execute the suggested action (auto-suppress the alerts)
    decisions = await db.get_ai_decisions(limit=1, offset=0)
    # Find the decision to apply
    for d in await db.get_ai_decisions(limit=200):
        if d["id"] == decision_id:
            # Parse alert_ids and suppress them
            alert_ids = [aid.strip() for aid in d.get("alert_ids", "").split(",") if aid.strip()]
            for aid in alert_ids:
                await db.update_verdict(aid, "suppress", 0.9, "Approved by human via AI copilot")
            # If this was a silence rule suggestion, create the rule
            try:
                detail = json.loads(d.get("detail", "{}"))
                if detail.get("suggested_rule"):
                    rule = detail["suggested_rule"]
                    await db.add_silence_rule(
                        rule.get("match_type", "title"),
                        rule.get("pattern", ""),
                        reason="AI copilot (human approved)",
                        pattern2=rule.get("pattern2", ""),
                    )
            except (json.JSONDecodeError, KeyError):
                pass
            break
    # Broadcast update
    if hasattr(daemon, "_autopilot"):
        await daemon._ws_broadcast({"type": "ai_suggestion_resolved", "data": {"id": decision_id, "action": "approved"}})
    return _json_response({"ok": True})


async def handle_ai_suggestion_reject(request: web.Request) -> web.Response:
    """POST /api/ai/suggestions/{id}/reject - reject a copilot suggestion."""
    db = _db(request)
    daemon = request.app["daemon"]
    decision_id = request.match_info["id"]
    ok = await db.reject_ai_decision(decision_id)
    if not ok:
        return _json_response({"error": "not found"}, status=404)
    if hasattr(daemon, "_autopilot"):
        await daemon._ws_broadcast({"type": "ai_suggestion_resolved", "data": {"id": decision_id, "action": "rejected"}})
    return _json_response({"ok": True})


async def handle_ai_squawks(request: web.Request) -> web.Response:
    """GET /api/ai/squawks - active (undismissed) squawks."""
    db = _db(request)
    squawks = await db.get_active_squawks()
    return _json_response(squawks)


async def handle_ai_squawk_dismiss(request: web.Request) -> web.Response:
    """POST /api/ai/squawks/{id}/dismiss - dismiss a squawk."""
    db = _db(request)
    daemon = request.app["daemon"]
    squawk_id = request.match_info["id"]
    ok = await db.dismiss_squawk(squawk_id)
    if not ok:
        return _json_response({"error": "not found"}, status=404)
    if hasattr(daemon, "_autopilot"):
        await daemon._ws_broadcast({"type": "squawk_dismiss", "data": {"id": squawk_id}})
    return _json_response({"ok": True})


async def handle_ai_reports(request: web.Request) -> web.Response:
    """GET /api/ai/reports - shift reports list."""
    db = _db(request)
    reports = await db.get_shift_reports(limit=20)
    return _json_response(reports)


async def handle_ai_report_detail(request: web.Request) -> web.Response:
    """GET /api/ai/reports/{id} - single shift report."""
    db = _db(request)
    report_id = request.match_info["id"]
    report = await db.get_shift_report(report_id)
    if not report:
        return _json_response({"error": "not found"}, status=404)
    return _json_response(report)


async def handle_ai_verdicts(request: web.Request) -> web.Response:
    """GET /api/ai/verdicts - learned verdict patterns."""
    db = _db(request)
    verdicts = await db.get_ai_verdicts(limit=100)
    return _json_response(verdicts)


# ── Investigations (JTTW) ─────────────────────────────────────────────────────

async def handle_run_investigation(request: web.Request) -> web.Response:
    """POST /api/investigations/run - Trigger deep AI investigation."""
    daemon = request.app["daemon"]
    db = daemon.db

    try:
        body = await request.json()
    except Exception:
        body = {}

    since = body.get("since", "24h")
    min_severity = body.get("min_severity", "medium")
    auto_verdict = body.get("auto_verdict", False)

    ai_cfg = daemon.cfg.ai if hasattr(daemon, "cfg") else None
    if ai_cfg is None or ai_cfg.tier == "none":
        return _json_response({"error": "AI is not configured"}, status=400)

    from shallots.ai.investigator import DeepInvestigator
    investigator = DeepInvestigator(ai_cfg, db)
    try:
        report = await investigator.investigate(
            since=since, min_severity=min_severity, auto_verdict=auto_verdict,
        )
        return _json_response(report.to_dict())
    except Exception as exc:
        log.exception("Investigation failed")
        return _json_response({"error": str(exc)}, status=500)


async def handle_get_investigation(request: web.Request) -> web.Response:
    """GET /api/investigations/{id} - Get investigation report."""
    inv_id = request.match_info["id"]
    inv = await _db(request).get_investigation(inv_id)
    if not inv:
        return _json_response({"error": "Not found"}, status=404)
    return _json_response(inv)


async def handle_list_investigations(request: web.Request) -> web.Response:
    """GET /api/investigations - List past investigations."""
    limit = min(int(request.query.get("limit", "20")), 100)
    investigations = await _db(request).get_recent_investigations(limit=limit)
    return _json_response(investigations)


# ── /api/wiki ─────────────────────────────────────────────────────────────────

async def handle_wiki_stats(request: web.Request) -> web.Response:
    """GET /api/wiki/stats - aggregate stats for a wiki article's alert type."""
    qs = request.rel_url.query
    source = qs.get("source") or None
    category = qs.get("category") or None
    sig_id = qs.get("signature_id") or None

    if not source and not category and not sig_id:
        raise web.HTTPBadRequest(reason="At least one of source, category, or signature_id required")

    clauses, params = [], []
    if source:
        clauses.append("source = ?")
        params.append(source)
    if sig_id:
        clauses.append("signature_id = ?")
        params.append(int(sig_id))
    if category:
        clauses.append("category LIKE ?")
        params.append(f"%{category}%")

    where = " AND ".join(clauses)
    db = _db(request)
    row = await db._db.execute(
        f"SELECT COUNT(*) as total, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen FROM alerts WHERE {where}",
        params,
    )
    r = dict(await row.fetchone())
    return _json_response(r)


async def handle_wiki_recent(request: web.Request) -> web.Response:
    """GET /api/wiki/recent - recent alerts for a wiki article's alert type."""
    qs = request.rel_url.query
    source = qs.get("source") or None
    category = qs.get("category") or None
    sig_id = qs.get("signature_id") or None

    try:
        limit = min(int(qs.get("limit", 5)), 20)
    except ValueError:
        limit = 5

    if not source and not category and not sig_id:
        raise web.HTTPBadRequest(reason="At least one of source, category, or signature_id required")

    clauses, params = [], []
    if source:
        clauses.append("source = ?")
        params.append(source)
    if sig_id:
        clauses.append("signature_id = ?")
        params.append(int(sig_id))
    if category:
        clauses.append("category LIKE ?")
        params.append(f"%{category}%")

    where = " AND ".join(clauses)
    params.append(limit)
    db = _db(request)
    cursor = await db._db.execute(
        f"SELECT id, timestamp, src_ip, dst_ip, title, severity, verdict FROM alerts WHERE {where} ORDER BY timestamp DESC LIMIT ?",
        params,
    )
    rows = [dict(r) for r in await cursor.fetchall()]
    return _json_response({"recent": rows})


async def handle_wiki_ai(request: web.Request) -> web.Response:
    """POST /api/wiki/ai - ask AI about a wiki topic."""
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    question = (body.get("question") or "").strip()
    article_context = (body.get("article_context") or "").strip()

    if not question:
        raise web.HTTPBadRequest(reason="Missing 'question' field")

    daemon = request.app["daemon"]
    db = _db(request)

    # Knowledge base RAG based on the question
    kb_matches = await db.search_knowledge(question, limit=5) if question else []
    knowledge_section = ""
    if kb_matches:
        knowledge_section = "\n\nKnowledge Base Context:\n" + "\n".join(
            f"- [{m['category']}] {m['topic']}: {m['content']}"
            for m in kb_matches
        )

    system_prompt = (
        "You are a security expert answering questions about network security topics. "
        "Use the provided wiki article context and knowledge base to give accurate, "
        "practical answers. Be concise and actionable. If the topic relates to a home "
        "network, prefer practical solutions."
    )

    user_prompt = f"""Wiki Article Context:
{article_context}
{knowledge_section}

User question: {question}

Answer the question based on the article context and your security expertise."""

    # Check for SSE streaming
    accept = request.headers.get("Accept", "")
    if "text/event-stream" in accept:
        cfg = daemon.cfg.ai
        if cfg.tier == "none" or not cfg.ollama_url:
            return _json_response({"response": "AI is not configured. Set an AI tier in settings."})
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
                "system": system_prompt,
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
    ai_text = await _call_ai(daemon, system_prompt, user_prompt)
    return _json_response({"response": ai_text})
