"""Investigate view — assembles a single, plain-language investigation payload
for one cluster: verdict + evidence diff + entities + the 'what else happened
around this' timeline + the AI tier-ladder reasoning. Built to be extended over
a long test/tweak cycle; every section degrades gracefully when its data is absent.

Design notes (from EDR + SIEM research): verdict-first, no jargon, only render
sections backed by real data, and make the related-events timeline the star — it
answers the question that resolves most homelab alerts: is this alone, or part of
a story?
"""
from __future__ import annotations

import json
import logging

from aiohttp import web

from . import _json_response, _db, _call_ai

log = logging.getLogger(__name__)

# Plain-language, homelabber-facing explanation per detection category. The AI
# reasoning string is shown separately; this is the always-there "what is this".
# Verdict-neutral, plain-language, calm. From microcopy research (2026-07-16):
# lead with what happened, say whether it's *usually* bad, no jargon/IDs, ≤2 sentences.
# The certainty lead-in (see _BANDS) composes on top; keep these neutral.
_CATEGORY_EXPLAIN = {
    "persistence": (
        "Something set itself up to run automatically on {host} — a new scheduled task, "
        "service, or startup item. That's normal for an install or update, but it's also exactly "
        "how malware makes itself survive a reboot, so it's worth a glance if you didn't just change something."
    ),
    "lateral_movement": (
        "{host} reached toward another machine on your network the way an admin tool — or an attacker — "
        "would: a remote login, file share, or remote command. At home this is sometimes you or a backup job, "
        "but it's the classic sign of something spreading from one device to the next."
    ),
    "session": (
        "Someone or something logged in to {host}. Most logins are just you or a service you run — "
        "this matters most when it's at an odd hour, from a new place, or right after another alert."
    ),
    "network_egress": (
        "{host} opened a connection out to the internet. The large majority of these are ordinary apps "
        "phoning home; it only matters when the destination is unfamiliar or the timing is strange."
    ),
    "anti_tamper": (
        "Something changed or tried to disable the security agent that watches {host}. Updates and restarts "
        "can do this innocently, but attackers switch off monitoring first — so if you didn't just update, "
        "treat this as a real red flag."
    ),
    "file_sentinel": (
        "A file being watched on {host} was changed, added, or deleted. Expected if you were editing or "
        "updating something; on a config, key, or system file you didn't touch, it deserves a second look."
    ),
    "a network trojan was detected": (
        "Traffic on {host} matched a known malware pattern — the kind trojans use to talk to a control server. "
        "These rules do occasionally false-alarm on ordinary software, but a real hit is one of the more serious "
        "things here and shouldn't be waved off."
    ),
    "attempted information leak": (
        "Something on {host} sent data in a pattern that can mean information is leaving where it shouldn't. "
        "Ordinary apps and scanners trigger this a lot, so it's usually low-stakes unless it repeats or pairs "
        "with another alert."
    ),
    "potentially bad traffic": (
        "{host} sent or received traffic that looks unusual but isn't clearly an attack. This is a low-confidence "
        "heads-up — normally nothing, worth noting only if there's a lot of it or it lines up with something else."
    ),
}
_DEFAULT_EXPLAIN = "Shallots flagged unusual activity involving {host}. See the evidence and timeline below."

# Plain-language certainty bands (microcopy research). We drive the band from the
# verdict + severity (an honest read of "how sure are we it's bad"), NOT the raw
# detection-confidence number, which measures something different.
_BANDS = {
    "danger":  {"key": "danger",  "label": "Looks dangerous",       "lead": "This looks dangerous",            "seg": 3},
    "bad":     {"key": "bad",     "label": "Probably bad",           "lead": "This is probably something bad",  "seg": 3},
    "unsure":  {"key": "unsure",  "label": "Not sure",               "lead": "I can't tell if this is a problem", "seg": 2},
    "normal":  {"key": "normal",  "label": "Probably normal",        "lead": "This is probably normal",         "seg": 1},
    "routine": {"key": "routine", "label": "Routine",                "lead": "This looks routine",              "seg": 1},
}


def _assess(primary: dict) -> dict:
    """Plain-language 'how bad is it, honestly' band from verdict + severity."""
    v = (primary.get("verdict") or "pending").strip().lower()
    sev = (primary.get("severity") or "").strip().lower()
    if v == "escalate" or sev == "critical":
        band = _BANDS["danger"]
    elif v in ("investigate", "pending") and sev == "high":
        band = _BANDS["unsure"]        # serious-looking but unresolved = be honest: not sure
    elif v == "investigate":
        band = _BANDS["unsure"]
    elif v in ("suppress", "benign", "noise"):
        band = _BANDS["routine"]
    elif sev in ("low",):
        band = _BANDS["normal"]
    else:
        band = _BANDS["unsure"]
    return dict(band)

# Human-readable ATT&CK blurbs so we never make a homelabber read a technique ID.
_MITRE_BLURB = {
    "T1053": "survives reboots by adding a scheduled task (cron).",
    "T1053.003": "survives reboots via a cron job.",
    "T1053.005": "survives reboots via a scheduled task.",
    "T1098.004": "adds an SSH key to keep access.",
    "T1547": "runs itself at boot/logon.",
    "T1543": "installs or changes a system service.",
}


def parse_evidence(alert: dict) -> dict:
    """Normalize an alert's raw payload into a render-ready evidence object.

    Handles argus' shapes: added_lines/removed_lines at the top level, under
    'details', or under a nested 'raw'. Reusable for any diff-shaped alert
    (crontab, authorized_keys, sudoers, systemd units).
    """
    raw = alert.get("raw")
    data: dict = {}
    if isinstance(raw, str) and raw.strip():
        try:
            data = json.loads(raw)
        except Exception:
            data = {}
    elif isinstance(raw, dict):
        data = raw

    details = data.get("details") if isinstance(data.get("details"), dict) else {}
    nested = data.get("raw") if isinstance(data.get("raw"), dict) else {}

    def _pick(key):
        return details.get(key) or data.get(key) or nested.get(key)

    added = _pick("added_lines") or []
    removed = _pick("removed_lines") or []
    snapshot = _pick("snapshot_hash")
    mitre = _pick("mitre_attack") or alert.get("mitre_attack")

    added = [str(x) for x in (added if isinstance(added, list) else [])][:60]
    removed = [str(x) for x in (removed if isinstance(removed, list) else [])][:60]

    kind = "diff" if (added or removed) else ("raw" if data else "none")
    mitre_blurb = _MITRE_BLURB.get(str(mitre)) if mitre else None
    return {
        "kind": kind,
        "added": added,
        "removed": removed,
        "snapshot_hash": snapshot,
        "mitre": mitre,
        "mitre_blurb": mitre_blurb,
        "raw_pretty": json.dumps(data, indent=2)[:6000] if data else "",
    }


def _explain(primary: dict, cluster: dict) -> str:
    cat = (primary.get("category") or cluster.get("category") or "").strip().lower()
    host = primary.get("src_asset") or primary.get("src_ip") or "a host"
    tmpl = _CATEGORY_EXPLAIN.get(cat, _DEFAULT_EXPLAIN)
    try:
        return tmpl.format(host=host)
    except Exception:
        return _DEFAULT_EXPLAIN.format(host=host)


async def build_investigation(db, cluster_id: str) -> dict | None:
    """Assemble the full investigation payload for a cluster."""
    cluster = await db.get_cluster(cluster_id)
    if not cluster:
        return None
    alerts = await db.get_cluster_alerts(cluster_id)

    # Primary = the most recent still-open alert (fall back to most recent).
    def _is_open(a):
        return (a.get("verdict") or "pending") != "suppress" and not a.get("acknowledged_at")
    open_alerts = [a for a in alerts if _is_open(a)]
    ordered = sorted(alerts, key=lambda a: a.get("ingested_at") or "", reverse=True)
    primary = (sorted(open_alerts, key=lambda a: a.get("ingested_at") or "", reverse=True)
               or ordered or [None])[0]

    evidence = parse_evidence(primary) if primary else {"kind": "none"}

    # ── Entities: hosts + IPs (with reputation) ──
    hosts = sorted({a.get("src_asset") for a in alerts if a.get("src_asset")}
                   | {a.get("dst_asset") for a in alerts if a.get("dst_asset")})
    ips = sorted({a.get("src_ip") for a in alerts if a.get("src_ip")}
                 | {a.get("dst_ip") for a in alerts if a.get("dst_ip")})
    ip_entities = []
    for ip in ips:
        rep = None
        try:
            rep = await db.get_ip_reputation(ip)
        except Exception:
            rep = None
        ip_entities.append({"ip": ip, "reputation": rep})

    # ── Related events: same host +/- window, plus in-cluster siblings ──
    host = (primary or {}).get("src_asset") or ""
    center = (primary or {}).get("ingested_at") or ""
    member_ids = [a["id"] for a in alerts if a.get("id")]
    related_window = []
    try:
        related_window = await db.get_related_events(
            host, center, window_min=10, exclude_ids=member_ids, limit=40)
    except Exception:
        log.debug("related_events failed", exc_info=True)
    siblings = [a for a in ordered if not primary or a.get("id") != primary.get("id")]

    # verdict rollup across the cluster (for the "2 of 5 already benign" badge)
    rollup = {"open": len(open_alerts), "suppressed": sum(
        1 for a in alerts if (a.get("verdict") or "") == "suppress"), "total": len(alerts)}

    # ── AI tier-ladder chain ──
    chain = None
    try:
        chain = await db.get_escalation_chain_for_alerts(member_ids)
    except Exception:
        log.debug("escalation chain lookup failed", exc_info=True)

    return {
        "cluster": cluster,
        "primary": primary,
        "assessment": _assess(primary) if primary else dict(_BANDS["unsure"]),
        "explain": _explain(primary, cluster) if primary else _DEFAULT_EXPLAIN.format(host="a host"),
        "ai_reasoning": (primary or {}).get("ai_reasoning") or "",
        "evidence": evidence,
        "entities": {"hosts": hosts, "ips": ip_entities},
        "related": {
            "window": related_window,
            "siblings": siblings,
            "rollup": rollup,
        },
        "ai_chain": chain,
        "alerts": ordered,
    }


async def handle_cluster_investigate(request: web.Request) -> web.Response:
    """GET /api/clusters/{id}/investigate — full investigation payload."""
    cluster_id = request.match_info["id"]
    db = _db(request)
    payload = await build_investigation(db, cluster_id)
    if payload is None:
        raise web.HTTPNotFound(reason="Cluster not found")
    return _json_response(payload)


async def handle_cluster_analyze(request: web.Request) -> web.Response:
    """POST /api/clusters/{id}/analyze — 'Dig deeper': plain-language AI analysis
    of this specific cluster, on demand. Uses the local model (cheap)."""
    cluster_id = request.match_info["id"]
    daemon = request.app["daemon"]
    db = daemon.db
    payload = await build_investigation(db, cluster_id)
    if payload is None:
        raise web.HTTPNotFound(reason="Cluster not found")

    primary = payload.get("primary") or {}
    ev = payload.get("evidence") or {}
    diff_txt = ""
    if ev.get("added") or ev.get("removed"):
        diff_txt = ("ADDED:\n" + "\n".join(ev.get("added", [])) +
                    "\n\nREMOVED:\n" + "\n".join(ev.get("removed", [])))
    system = (
        "You are a friendly security assistant for a home-lab owner who is NOT a "
        "security analyst. Explain in plain, calm language. No jargon, no MITRE IDs. "
        "Answer three things briefly: (1) what happened, (2) is it likely dangerous "
        "or probably fine, and why, (3) what should I do. Be honest about uncertainty."
    )
    user = (
        f"Alert: {primary.get('title')}\n"
        f"Category: {primary.get('category')}\n"
        f"Host: {primary.get('src_asset') or 'unknown'}\n"
        f"Severity: {primary.get('severity')}\n"
        f"Description: {primary.get('description')}\n"
        f"Evidence:\n{diff_txt or ev.get('raw_pretty','(none)')}\n"
        f"Existing automated reasoning: {payload.get('ai_reasoning') or '(none)'}\n"
    )
    try:
        analysis = await _call_ai(daemon, system, user)
    except Exception as exc:
        log.exception("cluster analyze failed")
        return _json_response({"error": str(exc)}, status=500)
    return _json_response({"cluster_id": cluster_id, "analysis": analysis})
