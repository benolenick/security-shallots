"""Edge-Grounded Triage — the experimental core.

A local small-LLM triage grader for ONE specific network that grounds its verdict in
(a) the operator's OWN past dispositions (retrieved by semantic similarity) and
(b) the involved host's normal behavior (a cheap per-host baseline).

Run two ways for the shadow experiment:
  - GROUNDED: retrieve dispositions + baseline, feed to the model.
  - PLAIN:    the same alert, no retrieval, no baseline (the A/B control).

Novel, measurable claim: grounded beats plain and the gap GROWS as the operator's
disposition memory accumulates — without silently missing threats (audited separately).
See docs/EDGE_TRIAGE_SIGIL.md.
"""
from __future__ import annotations

import json
import time
import logging

import aiohttp

from shallots.ai.embed import embed_text

log = logging.getLogger(__name__)


async def _ollama_grade(system: str, user: str, model: str, base_url: str,
                        timeout: float = 30.0) -> str:
    """Direct Ollama call with THINKING DISABLED (qwen3 is a thinking model — leaving
    it on makes each grade 8s+; off it's ~1s and emits clean JSON). Never raises."""
    payload = {
        "model": model,
        "prompt": system.strip() + "\n\n" + user.strip(),
        "stream": False,
        "think": False,
        "options": {"num_predict": 200, "temperature": 0.1},
    }
    try:
        to = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=to) as s:
            async with s.post(f"{base_url.rstrip('/')}/api/generate", json=payload) as r:
                if r.status != 200:
                    return ""
                d = await r.json()
                return d.get("response") or ""
    except Exception as e:
        log.debug("ollama grade failed: %s", e)
        return ""

_VALID = ("suppress", "investigate", "escalate")

_SYS_PLAIN = (
    "You are a security-alert triage grader for a small home/office network. Read the "
    "alert and output ONLY JSON: {\"verdict\":\"suppress|investigate|escalate\","
    "\"confidence\":0.0-1.0,\"reason\":\"one short sentence\"}. suppress=benign/routine "
    "noise; investigate=uncertain, worth a glance; escalate=likely a real threat. Be decisive."
)
_SYS_GROUNDED = (
    "You are a security-alert triage grader for ONE specific small network you are learning. "
    "Use (1) how the OPERATOR handled similar alerts before and (2) what is NORMAL for the "
    "involved host. Use the operator's history ONLY to DOWNGRADE genuinely-ambiguous, benign-"
    "LOOKING activity (their own cron/scrapers/logins). "
    "HARD RULE — history NEVER outweighs a concrete threat signal: if the alert names a known-"
    "malware domain / threat-intel feed match, a malicious-reputation IP, or a brute-force / C2 / "
    "beaconing pattern, ESCALATE regardless of what was suppressed before. A host being usually-"
    "benign does NOT make a malware hit on that host benign. "
    "Output ONLY JSON: {\"verdict\":\"suppress|investigate|escalate\",\"confidence\":0.0-1.0,"
    "\"reason\":\"one short sentence citing the evidence you used\"}."
)

# Deterministic safety floor: phrases that indicate a HARD threat signal. Grounding
# must never suppress these — this is the "dumb reliable" layer under the model.
_HARD_THREAT_MARKERS = (
    "known-malware", "malware domain", "malware feed", "malware-domain", "urlhaus",
    "threat-intel", "brute force", "brute-force", "c2", "beacon", "command-and-control",
    "abuseipdb 100", "virustotal", "malicious", "ransomware", "exfil", "reverse shell",
)


def _hard_threat(alert: dict) -> bool:
    t = (f"{alert.get('title','')} {alert.get('description','')} {alert.get('category','')}").lower()
    return any(m in t for m in _HARD_THREAT_MARKERS)


def _alert_text(a: dict) -> str:
    return (f"{a.get('title','')} | {a.get('category','')} | "
            f"host {a.get('src_asset') or a.get('src_ip') or '?'} | {a.get('description','')}").strip()


_VERDICT_MAP = {"malicious": "escalate", "threat": "escalate", "critical": "escalate",
                "benign": "suppress", "noise": "suppress", "clean": "suppress",
                "suspicious": "investigate", "uncertain": "investigate"}


def _norm_verdict(v: str) -> str:
    v = (v or "").strip().lower()
    if v in _VALID:
        return v
    return _VERDICT_MAP.get(v, "investigate")


def _parse(text: str) -> dict:
    v, conf, reason = "investigate", 0.5, ""
    try:
        i, j = text.index("{"), text.rindex("}") + 1
        o = json.loads(text[i:j])
        v = _norm_verdict(str(o.get("verdict", "")))
        try:
            conf = min(max(float(o.get("confidence", 0.5)), 0.0), 1.0)
        except Exception:
            conf = 0.5
        reason = str(o.get("reason", ""))[:300]
    except Exception:
        t = (text or "").lower()
        for c in ("escalate", "suppress", "investigate"):
            if c in t:
                v = c
                break
    return {"verdict": v, "confidence": conf, "reason": reason}


async def host_baseline(db, host: str, days: int = 7) -> str:
    """A cheap, factual 'what's normal for this host' string from recent alerts."""
    if not host:
        return "unknown host — no baseline."
    try:
        rows = await db.execute_sql(
            "SELECT category, COUNT(*) n FROM alerts WHERE src_asset = ? "
            "AND datetime(ingested_at) >= datetime('now', ?) GROUP BY category ORDER BY n DESC",
            (host, f"-{days} days"), max_rows=50,
        )
        if not rows:
            return f"{host}: no recent history (a first-seen host or category is itself notable)."
        cats = ", ".join(f"{r['category']}×{r['n']}" for r in rows[:6])
        dsts = await db.execute_sql(
            "SELECT COUNT(DISTINCT dst_ip) d FROM alerts WHERE src_asset = ? "
            "AND dst_ip != '' AND datetime(ingested_at) >= datetime('now', ?)",
            (host, f"-{days} days"), max_rows=1,
        )
        nd = dsts[0]["d"] if dsts else 0
        return f"{host} normal (last {days}d): categories [{cats}]; ~{nd} distinct outbound dsts."
    except Exception:
        return f"{host}: baseline unavailable."


async def _grounded_context(db, alert: dict, ollama_url: str, k: int = 5):
    """Retrieve top-k similar operator dispositions + host baseline. Returns (context_str, meta)."""
    vec = await embed_text(_alert_text(alert), base_url=ollama_url)
    disp = await db.retrieve_similar_dispositions(vec, k=k) if vec else []
    host = alert.get("src_asset") or alert.get("src_ip") or ""
    base = await host_baseline(db, host)
    lines = []
    for d in disp:
        lines.append(f'- [sim {d.get("similarity")}] "{(d.get("title") or "")[:60]}" '
                     f'-> operator called it {d.get("verdict")} ({(d.get("reason") or "")[:80]})')
    disp_block = "\n".join(lines) if lines else "(no similar past decisions yet)"
    ctx = (f"ALERT: {_alert_text(alert)}\n\n"
           f"WHAT'S NORMAL FOR THIS HOST: {base}\n\n"
           f"HOW THE OPERATOR HANDLED SIMILAR ALERTS BEFORE:\n{disp_block}\n\n"
           f"Grade this alert using the operator's history and the host baseline.")
    return ctx, {"retrieved_k": len(disp), "top_sim": (disp[0]["similarity"] if disp else None)}


async def grade(db, alert: dict, ollama_url: str, model: str = "qwen3:8b",
                grounded: bool = True, k: int = 5) -> dict:
    """Grade one alert; returns {verdict, confidence, reason, grounded, latency_ms, retrieved_k}."""
    t0 = time.monotonic()
    meta = {"retrieved_k": 0, "top_sim": None}
    if grounded:
        user, meta = await _grounded_context(db, alert, ollama_url, k=k)
        system = _SYS_GROUNDED
    else:
        user = f"ALERT: {_alert_text(alert)}\n\nGrade this alert."
        system = _SYS_PLAIN
    raw = await _ollama_grade(system, user, model, ollama_url)
    res = _parse(raw) if raw else {"verdict": "ERR", "confidence": 0.0, "reason": "no model response"}
    # SAFETY FLOOR: grounding may reduce false-positives, but must never suppress a
    # hard threat signal (the naive version silently missed real threats this way).
    res["safety_override"] = False
    if grounded and res.get("verdict") == "suppress" and _hard_threat(alert):
        res["verdict"] = "escalate"
        res["reason"] = "SAFETY FLOOR: hard threat signal overrides operator history. " + res.get("reason", "")
        res["safety_override"] = True
    res["grounded"] = grounded
    res["latency_ms"] = round((time.monotonic() - t0) * 1000)
    res["retrieved_k"] = meta["retrieved_k"]
    res["top_sim"] = meta["top_sim"]
    return res
