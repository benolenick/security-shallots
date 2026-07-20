"""Silence rules, custom detection rules."""

from __future__ import annotations

import json
import logging

from aiohttp import web

from . import _json_response, _db, _call_ai

log = logging.getLogger(__name__)


# ── /api/silence-rules ──────────────────────────────────────────────────────

async def handle_get_silence_rules(request: web.Request) -> web.Response:
    """GET /api/silence-rules - list user-created silence rules."""
    rules = await _db(request).get_silence_rules()
    return _json_response({"rules": rules})


async def handle_add_silence_rule(request: web.Request) -> web.Response:
    """POST /api/silence-rules - create a silence rule.

    Body: {"match_type": "title|sig_id|src_ip|category|src_ip+title|src_cidr",
           "pattern": "...", "pattern2": "...", "reason": "..."}
    Also suppresses all existing matching alerts.
    """
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    match_type = (body.get("match_type") or "").strip()
    pattern = (body.get("pattern") or "").strip()
    pattern2 = (body.get("pattern2") or "").strip()
    if not match_type or not pattern:
        raise web.HTTPBadRequest(reason="match_type and pattern are required")

    valid_types = {"title", "sig_id", "src_ip", "dst_ip", "category", "src_ip+title", "src_cidr", "dst_cidr"}
    if match_type not in valid_types:
        raise web.HTTPBadRequest(reason=f"match_type must be one of: {', '.join(sorted(valid_types))}")

    db = _db(request)
    rule_id = await db.add_silence_rule(match_type, pattern, body.get("reason", ""), pattern2)

    # Suppress existing alerts matching this rule
    suppressed = await _suppress_existing_for_rule(db, match_type, pattern, pattern2)

    # Reload silence rules into the classifier
    daemon = request.app["daemon"]
    await _reload_silence_rules(daemon)

    await db.insert_audit("create_silence_rule", "silence_rule", rule_id,
                          f"{match_type}: {pattern} (suppressed {suppressed})")
    log.info("Silence rule added: %s '%s' (pattern2='%s') - suppressed %d existing alerts",
             match_type, pattern, pattern2, suppressed)
    return _json_response({
        "ok": True, "id": rule_id, "suppressed": suppressed,
    }, status=201)


async def _suppress_existing_for_rule(db, match_type: str, pattern: str, pattern2: str = "") -> int:
    """Suppress existing alerts that match a silence rule."""
    suppressed = 0
    reason = f"Silenced: {match_type} {pattern}"
    if pattern2:
        reason += f" + {pattern2}"

    if match_type == "title":
        cursor = await db._db.execute(
            "UPDATE alerts SET verdict = 'suppress', ai_reasoning = ? "
            "WHERE title LIKE ? AND verdict != 'suppress'",
            (reason, f"%{pattern}%"),
        )
        suppressed = cursor.rowcount
    elif match_type == "sig_id":
        try:
            cursor = await db._db.execute(
                "UPDATE alerts SET verdict = 'suppress', ai_reasoning = ? "
                "WHERE signature_id = ? AND verdict != 'suppress'",
                (reason, int(pattern)),
            )
            suppressed = cursor.rowcount
        except (ValueError, TypeError):
            pass
    elif match_type == "src_ip":
        cursor = await db._db.execute(
            "UPDATE alerts SET verdict = 'suppress', ai_reasoning = ? "
            "WHERE src_ip = ? AND verdict != 'suppress'",
            (reason, pattern),
        )
        suppressed = cursor.rowcount
    elif match_type == "dst_ip":
        cursor = await db._db.execute(
            "UPDATE alerts SET verdict = 'suppress', ai_reasoning = ? "
            "WHERE dst_ip = ? AND verdict != 'suppress'",
            (reason, pattern),
        )
        suppressed = cursor.rowcount
    elif match_type == "category":
        cursor = await db._db.execute(
            "UPDATE alerts SET verdict = 'suppress', ai_reasoning = ? "
            "WHERE category LIKE ? AND verdict != 'suppress'",
            (reason, f"%{pattern}%"),
        )
        suppressed = cursor.rowcount
    elif match_type == "src_ip+title":
        cursor = await db._db.execute(
            "UPDATE alerts SET verdict = 'suppress', ai_reasoning = ? "
            "WHERE src_ip = ? AND title LIKE ? AND verdict != 'suppress'",
            (reason, pattern, f"%{pattern2}%"),
        )
        suppressed = cursor.rowcount
    elif match_type == "src_cidr":
        # CIDR matching requires Python-side logic - fetch and update
        import ipaddress as _ipaddress
        try:
            net = _ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return 0
        cursor = await db._db.execute(
            "SELECT id, src_ip FROM alerts WHERE verdict != 'suppress' AND src_ip != ''"
        )
        rows = await cursor.fetchall()
        ids_to_suppress = []
        for row in rows:
            try:
                if _ipaddress.ip_address(row["src_ip"]) in net:
                    ids_to_suppress.append(row["id"])
            except ValueError:
                continue
        if ids_to_suppress:
            placeholders = ",".join("?" * len(ids_to_suppress))
            cursor = await db._db.execute(
                f"UPDATE alerts SET verdict = 'suppress', ai_reasoning = ? "
                f"WHERE id IN ({placeholders})",
                [reason] + ids_to_suppress,
            )
            suppressed = cursor.rowcount
    elif match_type == "dst_cidr":
        # CIDR matching on dst_ip requires Python-side logic
        import ipaddress as _ipaddress
        try:
            net = _ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return 0
        cursor = await db._db.execute(
            "SELECT id, dst_ip FROM alerts WHERE verdict != 'suppress' AND dst_ip != ''"
        )
        rows = await cursor.fetchall()
        ids_to_suppress = []
        for row in rows:
            try:
                if _ipaddress.ip_address(row["dst_ip"]) in net:
                    ids_to_suppress.append(row["id"])
            except ValueError:
                continue
        if ids_to_suppress:
            placeholders = ",".join("?" * len(ids_to_suppress))
            cursor = await db._db.execute(
                f"UPDATE alerts SET verdict = 'suppress', ai_reasoning = ? "
                f"WHERE id IN ({placeholders})",
                [reason] + ids_to_suppress,
            )
            suppressed = cursor.rowcount

    if suppressed:
        await db._db.commit()
    return suppressed


async def handle_delete_silence_rule(request: web.Request) -> web.Response:
    """DELETE /api/silence-rules/{id} - remove a silence rule."""
    rule_id = request.match_info["id"]
    deleted = await _db(request).delete_silence_rule(rule_id)
    if not deleted:
        raise web.HTTPNotFound(reason="Silence rule not found")
    # Reload rules
    daemon = request.app["daemon"]
    await _reload_silence_rules(daemon)
    return _json_response({"ok": True})


async def _reload_silence_rules(daemon) -> None:
    """Load silence rules from DB and inject into the classifier."""
    try:
        import ipaddress as _ipaddress
        import re as _re

        rules = await daemon.db.get_silence_rules()

        # Store rules on daemon for the pipeline to use for combo matching
        daemon._silence_rules = rules

        for rule in rules:
            mt = rule["match_type"]
            pattern = rule["pattern"]

            if mt == "title":
                existing = [p.pattern for p in daemon.classifier._suppress_patterns]
                if pattern not in existing:
                    daemon.classifier._suppress_patterns.append(
                        _re.compile(pattern, _re.IGNORECASE)
                    )
            elif mt == "sig_id":
                try:
                    daemon.classifier._cfg.suppress_sig_ids.add(int(pattern))
                except (ValueError, TypeError):
                    pass
            elif mt == "src_ip":
                daemon.classifier._cfg.suppress_source_ips.add(pattern)
            elif mt == "dst_ip":
                daemon.classifier._cfg.suppress_dest_ips.add(pattern)
            elif mt == "dst_cidr":
                try:
                    net = _ipaddress.ip_network(pattern, strict=False)
                    existing_cidrs = [str(n) for n in daemon.classifier._cfg.suppress_dest_cidrs]
                    if str(net) not in existing_cidrs:
                        daemon.classifier._cfg.suppress_dest_cidrs.append(net)
                except ValueError:
                    pass
            elif mt == "src_cidr":
                try:
                    net = _ipaddress.ip_network(pattern, strict=False)
                    existing_cidrs = [str(n) for n in daemon.classifier._cfg.suppress_source_cidrs]
                    if str(net) not in existing_cidrs:
                        daemon.classifier._cfg.suppress_source_cidrs.append(net)
                except ValueError:
                    pass
            elif mt == "category":
                # Suppress alerts whose category matches. (Previously this wrote
                # "suppress" into category_severity_map, which the classifier reads
                # as a SEVERITY override - corrupting alert.severity to the invalid
                # string "suppress" instead of actually silencing anything.)
                if pattern not in daemon.classifier._cfg.suppress_categories:
                    daemon.classifier._cfg.suppress_categories.append(pattern)
            elif mt == "src_ip+title":
                pattern2 = rule.get("pattern2", "")
                if pattern and pattern2:
                    combo = (pattern, pattern2)
                    if combo not in daemon.classifier._combo_rules:
                        daemon.classifier._combo_rules.append(combo)
    except Exception as exc:
        log.warning("Failed to reload silence rules: %s", exc)


# ── /api/silence-rules/ai ────────────────────────────────────────────────────

_AI_SILENCE_SYSTEM = """\
You are a security alert tuning assistant for a home/small-office SIEM.
The user will describe noisy alerts they want silenced. You must pick the
best silence rule to create.

Available match types:
- title        - suppress alerts whose title contains a substring
- sig_id       - suppress by Suricata signature ID (integer)
- src_ip       - suppress all alerts from a source IP
- dst_ip       - suppress all alerts to a destination IP
- src_cidr     - suppress all alerts from a source subnet (CIDR notation)
- dst_cidr     - suppress all alerts to a destination subnet (CIDR notation)
- category     - suppress alerts whose category contains a substring
- src_ip+title - suppress alerts matching BOTH a source IP AND a title substring

Respond with ONLY a JSON object (no markdown, no explanation):
{
  "match_type": "...",
  "pattern": "...",
  "pattern2": "...",
  "reason": "short human-readable reason"
}

pattern2 is only used for src_ip+title (the title part). Leave it "" otherwise.
Pick the most surgical rule that covers the user's request without over-suppressing.
"""


async def _rule_hits_high_severity(db, match_type: str, pattern: str, pattern2: str) -> bool:
    """True if a proposed silence rule matches any existing non-suppressed
    high/critical alert - i.e. applying it would hide a real threat."""
    sev = "severity IN ('high','critical') AND verdict != 'suppress'"
    if match_type == "title":
        q, args = f"SELECT 1 FROM alerts WHERE title LIKE ? AND {sev} LIMIT 1", (f"%{pattern}%",)
    elif match_type == "src_ip":
        q, args = f"SELECT 1 FROM alerts WHERE src_ip = ? AND {sev} LIMIT 1", (pattern,)
    elif match_type == "dst_ip":
        q, args = f"SELECT 1 FROM alerts WHERE dst_ip = ? AND {sev} LIMIT 1", (pattern,)
    elif match_type == "src_ip+title":
        q, args = (f"SELECT 1 FROM alerts WHERE src_ip = ? AND title LIKE ? AND {sev} LIMIT 1",
                   (pattern, f"%{pattern2}%"))
    elif match_type == "sig_id":
        try:
            args = (int(pattern),)
        except (TypeError, ValueError):
            return False
        q = f"SELECT 1 FROM alerts WHERE signature_id = ? AND {sev} LIMIT 1"
    else:
        return True  # unknown / broad - treat as risky
    try:
        cur = await db._db.execute(q, args)
        return (await cur.fetchone()) is not None
    except Exception:
        return True  # fail closed


async def handle_ai_silence_rule(request: web.Request) -> web.Response:
    """POST /api/silence-rules/ai - AI-assisted silence rule creation.

    Body: {"request": "natural language description of what to silence"}
    Gathers dashboard context, asks AI to propose a rule, applies it.
    """
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Request body must be valid JSON")

    user_request = (body.get("request") or "").strip()
    if not user_request:
        raise web.HTTPBadRequest(reason="'request' field is required")

    daemon = request.app["daemon"]
    db = _db(request)

    # Gather context for the AI
    # Top noisy alert patterns (src_ip + title combos, dst_ip patterns)
    context_parts = []

    try:
        cursor = await db._db.execute(
            "SELECT src_ip, dst_ip, title, category, signature_id, COUNT(*) as cnt "
            "FROM alerts WHERE verdict != 'suppress' "
            "GROUP BY src_ip, dst_ip, title ORDER BY cnt DESC LIMIT 30"
        )
        rows = await cursor.fetchall()
        if rows:
            lines = ["Top unsuppressed alert patterns (src_ip | dst_ip | title | category | sig_id | count):"]
            for r in rows:
                lines.append(f"  {r['src_ip']} | {r['dst_ip']} | {r['title']} | {r['category']} | {r['signature_id']} | {r['cnt']}")
            context_parts.append("\n".join(lines))
    except Exception:
        pass

    try:
        cursor = await db._db.execute(
            "SELECT dst_ip, COUNT(*) as cnt FROM alerts WHERE verdict != 'suppress' AND dst_ip != '' "
            "GROUP BY dst_ip ORDER BY cnt DESC LIMIT 15"
        )
        rows = await cursor.fetchall()
        if rows:
            lines = ["Top destination IPs (unsuppressed):"]
            for r in rows:
                lines.append(f"  {r['dst_ip']}: {r['cnt']} alerts")
            context_parts.append("\n".join(lines))
    except Exception:
        pass

    try:
        rules = await db.get_silence_rules()
        if rules:
            lines = ["Existing silence rules:"]
            for r in rules:
                lines.append(f"  {r['match_type']}: {r['pattern']} {r.get('pattern2', '')}")
            context_parts.append("\n".join(lines))
    except Exception:
        pass

    context = "\n\n".join(context_parts)
    user_prompt = f"Dashboard context:\n{context}\n\nUser request: {user_request}"

    # Call AI
    ai_response = await _call_ai(daemon, _AI_SILENCE_SYSTEM, user_prompt)

    # Parse the AI's JSON response
    import json as _json
    # Strip markdown fences if present
    cleaned = ai_response.strip()
    if cleaned.startswith("```"):
        cleaned = "\n".join(cleaned.split("\n")[1:])
    if cleaned.endswith("```"):
        cleaned = "\n".join(cleaned.split("\n")[:-1])
    cleaned = cleaned.strip()

    try:
        rule = _json.loads(cleaned)
    except _json.JSONDecodeError:
        return _json_response({
            "ok": False,
            "error": "AI returned invalid JSON",
            "ai_raw": ai_response,
        }, status=422)

    match_type = (rule.get("match_type") or "").strip()
    pattern = (rule.get("pattern") or "").strip()
    pattern2 = (rule.get("pattern2") or "").strip()
    reason = (rule.get("reason") or "AI-suggested rule").strip()

    valid_types = {"title", "sig_id", "src_ip", "dst_ip", "category", "src_ip+title", "src_cidr", "dst_cidr"}
    if match_type not in valid_types or not pattern:
        return _json_response({
            "ok": False,
            "error": f"AI proposed invalid rule: type={match_type!r} pattern={pattern!r}",
            "ai_raw": ai_response,
        }, status=422)

    # GUARDRAIL: the prompt context above is built from ingested alert text, which
    # an attacker can influence (agent events, log lines, IDS-visible strings). A
    # prompt-injected rule must not be able to auto-suppress real detections.
    # Refuse broad rules and anything that would hide existing high/critical alerts;
    # the operator can still create such a rule manually via /api/silence-rules.
    if match_type in ("category", "src_cidr", "dst_cidr"):
        return _json_response({
            "ok": False,
            "error": f"Refusing to auto-apply a broad '{match_type}' silence rule. "
                     "Review and create it manually if intended.",
        }, status=422)
    if await _rule_hits_high_severity(db, match_type, pattern, pattern2):
        return _json_response({
            "ok": False,
            "error": "Refusing to auto-apply: this rule matches existing high/critical "
                     "alerts and would hide real threats. Create it manually after review.",
        }, status=422)

    # Apply the rule
    rule_id = await db.add_silence_rule(match_type, pattern, reason, pattern2)
    suppressed = await _suppress_existing_for_rule(db, match_type, pattern, pattern2)
    await _reload_silence_rules(daemon)

    log.info("AI silence rule: %s '%s' (p2='%s') reason='%s' - suppressed %d existing",
             match_type, pattern, pattern2, reason, suppressed)

    return _json_response({
        "ok": True,
        "id": rule_id,
        "match_type": match_type,
        "pattern": pattern,
        "pattern2": pattern2,
        "reason": reason,
        "suppressed": suppressed,
    }, status=201)


# ── Custom Detection Rules ────────────────────────────────────────────────────

async def handle_get_custom_rules(request: web.Request) -> web.Response:
    """GET /api/rules - list custom detection rules."""
    rules = await _db(request).get_custom_rules()
    return _json_response({"rules": rules})


async def handle_add_custom_rule(request: web.Request) -> web.Response:
    """POST /api/rules - create a custom detection rule."""
    body = await request.json()
    name = body.get("name", "").strip()
    match_field = body.get("match_field", "").strip()
    match_value = body.get("match_value", "").strip()
    if not name or not match_field or not match_value:
        return _json_response({"error": "name, match_field, match_value required"}, 400)

    rid = await _db(request).add_custom_rule(
        name=name,
        match_field=match_field,
        match_op=body.get("match_op", "contains"),
        match_value=match_value,
        match_field2=body.get("match_field2", ""),
        match_op2=body.get("match_op2", ""),
        match_value2=body.get("match_value2", ""),
        action=body.get("action", "escalate"),
        action_param=body.get("action_param", ""),
        severity_override=body.get("severity_override", ""),
        description=body.get("description", ""),
    )
    await _db(request).add_audit_log("create_rule", "custom_rule", rid, f"Rule: {name}")
    return _json_response({"id": rid, "name": name})


async def handle_update_custom_rule(request: web.Request) -> web.Response:
    """PATCH /api/rules/{id} - update a custom detection rule."""
    rule_id = request.match_info["id"]
    body = await request.json()
    ok = await _db(request).update_custom_rule(rule_id, **body)
    if not ok:
        return _json_response({"error": "Rule not found or no changes"}, 404)
    return _json_response({"ok": True})


async def handle_delete_custom_rule(request: web.Request) -> web.Response:
    """DELETE /api/rules/{id} - delete a custom detection rule."""
    rule_id = request.match_info["id"]
    ok = await _db(request).delete_custom_rule(rule_id)
    if not ok:
        return _json_response({"error": "Rule not found"}, 404)
    await _db(request).add_audit_log("delete_rule", "custom_rule", rule_id)
    return _json_response({"ok": True})


async def handle_test_custom_rule(request: web.Request) -> web.Response:
    """POST /api/rules/test - test a rule against recent alerts."""
    body = await request.json()
    db = _db(request)
    rule = {
        "match_field": body.get("match_field", ""),
        "match_op": body.get("match_op", "contains"),
        "match_value": body.get("match_value", ""),
        "match_field2": body.get("match_field2", ""),
        "match_op2": body.get("match_op2", ""),
        "match_value2": body.get("match_value2", ""),
    }
    cursor = await db._db.execute(
        "SELECT * FROM alerts ORDER BY ingested_at DESC LIMIT 500"
    )
    alerts = [dict(r) for r in await cursor.fetchall()]
    matches = [a for a in alerts if db.match_custom_rule(rule, a)]
    return _json_response({
        "tested": len(alerts),
        "matched": len(matches),
        "samples": matches[:10],
    })
