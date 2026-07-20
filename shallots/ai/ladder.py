"""The Escalation Ladder - a tiered AI SOC-analyst pipeline.

Design (operator's spec):

    Tier 0  qwen3:8b (local, always-on)   kills low-hanging fruit, then DISTILLS
                                          what it cannot confidently close into a
                                          compact "case brief" and kicks it up.
    Tier 1  Claude Haiku   every 10 min   reads only Tier-0's briefs.
    Tier 2  Claude Sonnet  every  1 h     reads only what Haiku promoted.
    Tier 3  Claude Opus    every  4 h     reads only what Sonnet promoted.
                                          Only Opus may PING the operator.

The load-bearing idea: **each rung reads only the distilled output of the rung
below**, never the raw alert firehose. So Opus typically sees 0-2 cases per run,
which makes the whole ladder cost a rounding error even on subscription quota.

Every rung may *close* a case (dismiss / resolve) as well as *promote* it - a
higher tier closing something is the signal that the lower tier over-reacted.
The full model-by-model reasoning chain is persisted on each case, which doubles
as the audit trail and the training/eval corpus for tuning the funnel later.

Implementation notes:
  * Fully decoupled from the async daemon - the ladder runs as short-lived
    CLI/timer processes over the same SQLite DB, in its own ``escalations`` table
    the daemon never touches. Zero risk to the live pipeline.
  * Claude tiers go through the operator's OAuth login (see ``oauth_brain``);
    qwen3 goes through local Ollama.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from shallots.ai.oauth_brain import BrainError, OAuthBrain

log = logging.getLogger(__name__)

_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_TIER_NAME = {1: "haiku", 2: "sonnet", 3: "opus"}
_TIER_NUM = {v: k for k, v in _TIER_NAME.items()}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cutoff_iso(minutes: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def _as_float(value: Any, default: float) -> float:
    """Coerce a model-supplied confidence to float; never raise.

    Models occasionally return "high"/"0.9 (approx)"/None - a bare float() here
    wedged the case open and burned a Claude call every cycle retrying it.
    """
    try:
        f = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        # salvage a leading number if present, e.g. "0.9 (approx)"
        import re as _re
        m = _re.match(r"\s*([0-9]*\.?[0-9]+)", str(value or ""))
        if not m:
            return default
        try:
            f = float(m.group(1))
        except ValueError:
            return default
    return min(max(f, 0.0), 1.0)


# ── schema ───────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS escalations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key    TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    tier         INTEGER NOT NULL,      -- 1 haiku, 2 sonnet, 3 opus, 4 terminal
    state        TEXT NOT NULL,         -- open | resolved | dismissed | pinged
    severity     TEXT,
    title        TEXT,
    brief        TEXT,                  -- qwen distilled case brief
    signals      TEXT,                  -- json: {src_ips, dst_ips, categories, iocs}
    alert_ids    TEXT,                  -- json list of alert UUIDs
    alert_count  INTEGER DEFAULT 0,
    confidence   REAL DEFAULT 0.0,
    chain        TEXT,                  -- json list of per-tier verdicts
    resolution   TEXT,                  -- terminal disposition text
    ping_sent    INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_esc_tier_state ON escalations(tier, state);
CREATE INDEX IF NOT EXISTS idx_esc_dedup ON escalations(dedup_key, state);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    conn.commit()


# ── prompts ──────────────────────────────────────────────────────────────

_DISTILL_SYSTEM = (
    "You are the Tier-0 triage analyst of a home/small-fleet security monitor "
    "(the qwen3 local model). Most alerts on this network are benign self-noise. "
    "Your job: look at a CLUSTER of related alerts and decide whether it is worth "
    "a senior analyst's time. Kill anything you are confident is benign. If you "
    "cannot fully rule out a real threat, escalate it and write a crisp case brief. "
    "Be skeptical and concrete. Respond with ONLY a JSON object."
)

_DISTILL_USER_TMPL = """Cluster of {n} related alerts on the local network:

{alerts}

Decide. Respond with ONLY this JSON object:
{{
  "escalate": true|false,        // false = you are confident this is benign; kill it
  "title": "<=10 word case title",
  "severity": "low|medium|high|critical",
  "summary": "1-3 sentences: what actually happened, plainly",
  "why_it_matters": "why this could be a real problem (empty if escalate=false)",
  "uncertainty": "what you could NOT rule out / why a bigger model should look",
  "confidence": 0.0-1.0,         // confidence in your escalate decision
  "iocs": ["ip/domain/hash/..."]
}}"""

_TIER_SYSTEM = {
    "haiku": (
        "You are a Tier-1 SOC analyst (Claude Haiku) reviewing cases a local triage "
        "model escalated because it was unsure. You are fast and decisive. Most cases "
        "you see are the local model being over-cautious about benign home-network "
        "activity. DISMISS false positives, RESOLVE real-but-handled/benign-confirmed "
        "cases, and PROMOTE only cases that genuinely need deeper analysis. "
        "Respond with ONLY a JSON object."
    ),
    "sonnet": (
        "You are a Tier-2 SOC analyst (Claude Sonnet). Haiku promoted this case as "
        "non-trivial. Analyze it properly: correlate the signals, weigh attacker vs. "
        "benign explanations, consider the home/small-fleet context. DISMISS if it is "
        "a false positive, RESOLVE if real but not worth waking anyone, PROMOTE to the "
        "senior analyst only if it may warrant human action. Respond with ONLY a JSON object."
    ),
    "opus": (
        "You are the Tier-3 senior security analyst (Claude Opus), the final arbiter "
        "before the operator is personally paged. Two lower-tier models already judged "
        "this worth escalating. Be rigorous and adversarial. PING the operator ONLY if "
        "this is genuinely worthy of a human's immediate attention on a home/small "
        "fleet. Otherwise DISMISS (false positive) or RESOLVE (real but handle-later). "
        "A needless page erodes trust in the whole system. Respond with ONLY a JSON object."
    ),
}

_TIER_USER_TMPL = """CASE #{id}  (severity={severity}, {alert_count} alerts, tier-0 confidence={confidence})

TITLE: {title}

TIER-0 (qwen3) BRIEF:
{brief}

SIGNALS: {signals}

PRIOR ANALYST CHAIN:
{chain}

SAMPLE OF UNDERLYING ALERTS:
{alerts}

Respond with ONLY this JSON object:
{schema}"""

_SCHEMA_DISMISS_PROMOTE = """{
  "decision": "dismiss|resolve|promote",
  "severity": "low|medium|high|critical",
  "confidence": 0.0-1.0,
  "headline": "one-line verdict",
  "rationale": "2-4 sentences of reasoning"
}"""

_SCHEMA_OPUS = """{
  "decision": "dismiss|resolve|ping",
  "severity": "low|medium|high|critical",
  "confidence": 0.0-1.0,
  "headline": "one-line verdict the operator will read first",
  "rationale": "2-4 sentences of reasoning",
  "recommended_action": "what the operator should do (only if ping)"
}"""


# ── config view (defensive: read from the app Config, with fallbacks) ─────

@dataclass
class _TierCfg:
    model: str
    max_cases: int
    max_tokens: int
    timeout: int


class Ladder:
    """Runs the escalation ladder. One instance per short-lived CLI invocation."""

    def __init__(self, cfg: Any) -> None:
        self.cfg = cfg
        lc = getattr(cfg, "ladder", None)
        self._lc = lc

        self.db_path = (getattr(lc, "db_path", "") or cfg.storage.db_path)
        self.ollama_url = (
            getattr(lc, "distill_url", "") or cfg.ai.ollama_url or "http://127.0.0.1:11434"
        ).rstrip("/")
        self.distill_model = (
            getattr(lc, "distill_model", "") or cfg.ai.ollama_model or "qwen3:8b"
        )
        self.build_lookback_min = getattr(lc, "build_lookback_min", 180)
        self.min_sev = getattr(lc, "escalate_min_severity", "high")
        self.escalate_verdicts = set(
            getattr(lc, "escalate_verdicts", None) or ["escalate", "investigate"]
        )
        self.max_build_cases = getattr(lc, "max_build_cases", 12)

        self.brain = OAuthBrain(
            claude_bin=getattr(lc, "claude_bin", "claude"),
            creds_path=getattr(lc, "creds_path", "~/.claude/.credentials.json"),
        )

        self.tiers = {
            "haiku": _TierCfg(model="haiku", max_cases=getattr(lc, "haiku_max_cases", 15),
                              max_tokens=1024, timeout=120),
            "sonnet": _TierCfg(model="sonnet", max_cases=getattr(lc, "sonnet_max_cases", 8),
                               max_tokens=1536, timeout=180),
            "opus": _TierCfg(model="opus", max_cases=getattr(lc, "opus_max_cases", 4),
                             max_tokens=2048, timeout=300),
        }

    # ── db ───────────────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=8000")
        conn.execute("PRAGMA journal_mode=WAL")
        ensure_schema(conn)
        return conn

    # ── TIER 0: build escalations from qwen's escalate-worthy alerts ──────

    def build(self) -> dict:
        """Cluster escalate-worthy alerts and distill each into a case (or kill it)."""
        conn = self._connect()
        try:
            candidates = self._fetch_candidates(conn)
            covered = self._covered_alert_ids(conn)
            open_keys = self._open_dedup_keys(conn)

            clusters = self._cluster(
                [a for a in candidates if a["id"] not in covered]
            )
            created, killed, merged = 0, 0, 0
            for key, alerts in clusters.items():
                if key in open_keys:
                    self._merge_into_open(conn, key, alerts)
                    conn.commit()
                    merged += 1
                    continue
                verdict = self._distill(alerts)
                if not verdict.get("escalate"):
                    killed += 1
                    log.info("build: qwen killed cluster %s (%s)", key,
                             verdict.get("summary", "")[:80])
                    continue
                self._insert_escalation(conn, key, alerts, verdict)
                conn.commit()
                created += 1
                if created >= self.max_build_cases:
                    break
            conn.commit()
            result = {"candidates": len(candidates), "clusters": len(clusters),
                      "created": created, "killed": killed, "merged": merged}
            log.info("ladder build: %s", result)
            return result
        finally:
            conn.close()

    def _fetch_candidates(self, conn: sqlite3.Connection) -> list[dict]:
        cutoff = _cutoff_iso(self.build_lookback_min)
        min_rank = _SEV_RANK.get(self.min_sev, 2)
        rows = conn.execute(
            """
            SELECT id, timestamp, ingested_at, source, severity, title, description,
                   src_ip, src_port, dst_ip, dst_port, proto, category, verdict,
                   confidence, ai_reasoning, signature_id
            FROM alerts
            WHERE ingested_at >= ?
            ORDER BY ingested_at DESC
            LIMIT 2000
            """,
            (cutoff,),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            v = (d.get("verdict") or "").lower()
            sev_ok = _SEV_RANK.get((d.get("severity") or "").lower(), 0) >= min_rank
            # Candidate if qwen explicitly flagged it, OR it is high/critical and
            # qwen did NOT suppress it (an un-suppressed serious alert still merits
            # a second look up the ladder).
            if v in self.escalate_verdicts or (sev_ok and v != "suppress"):
                out.append(d)
        return out

    def _covered_alert_ids(self, conn: sqlite3.Connection) -> set[str]:
        ids: set[str] = set()
        for (blob,) in conn.execute("SELECT alert_ids FROM escalations"):
            try:
                ids.update(json.loads(blob or "[]"))
            except Exception:
                pass
        return ids

    def _open_dedup_keys(self, conn: sqlite3.Connection) -> set[str]:
        return {
            r[0] for r in conn.execute(
                "SELECT dedup_key FROM escalations WHERE state='open'"
            )
        }

    @staticmethod
    def _norm_title(title: str) -> str:
        import re
        t = (title or "").lower()
        t = re.sub(r"[0-9a-f]{6,}", "", t)       # strip hex/uuid-ish tokens
        t = re.sub(r"\d+", "", t)                 # strip numbers
        t = re.sub(r"\s+", " ", t).strip()
        return t[:60]

    def _cluster(self, alerts: list[dict]) -> dict[str, list[dict]]:
        clusters: dict[str, list[dict]] = {}
        for a in alerts:
            src = a.get("src_ip") or "-"
            key = f"{src}|{a.get('category') or self._norm_title(a.get('title', ''))}"
            clusters.setdefault(key, []).append(a)
        # cap each cluster to a representative sample
        return {k: v[:40] for k, v in clusters.items()}

    def _distill(self, alerts: list[dict]) -> dict:
        rendered = _render_alerts(alerts, limit=25)
        user = _DISTILL_USER_TMPL.format(n=len(alerts), alerts=rendered)
        try:
            obj = self._ollama_json(_DISTILL_SYSTEM, user)
        except Exception as exc:  # noqa: BLE001
            # If qwen is unavailable, fail safe by escalating (let Haiku decide).
            log.warning("distill: ollama failed (%s) - escalating conservatively", exc)
            worst = max(alerts, key=lambda a: _SEV_RANK.get((a.get("severity") or "").lower(), 0))
            return {
                "escalate": True,
                "title": (worst.get("title") or "Uncategorized cluster")[:60],
                "severity": worst.get("severity") or "high",
                "summary": f"{len(alerts)} related alerts; local triage model unavailable.",
                "why_it_matters": "Auto-escalated because Tier-0 distiller was offline.",
                "uncertainty": "Not analyzed by qwen.",
                "confidence": 0.3,
                "iocs": [],
            }
        return obj

    def _insert_escalation(self, conn: sqlite3.Connection, key: str,
                           alerts: list[dict], v: dict) -> None:
        now = _now_iso()
        signals = {
            "src_ips": sorted({a.get("src_ip") for a in alerts if a.get("src_ip")}),
            "dst_ips": sorted({a.get("dst_ip") for a in alerts if a.get("dst_ip")}),
            "categories": sorted({a.get("category") for a in alerts if a.get("category")}),
            "iocs": v.get("iocs", []),
        }
        brief = "\n".join(filter(None, [
            v.get("summary", ""),
            f"Why it matters: {v.get('why_it_matters')}" if v.get("why_it_matters") else "",
            f"Uncertainty: {v.get('uncertainty')}" if v.get("uncertainty") else "",
        ]))
        conn.execute(
            """INSERT INTO escalations
               (dedup_key, created_at, updated_at, tier, state, severity, title,
                brief, signals, alert_ids, alert_count, confidence, chain, ping_sent)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
            (
                key, now, now, 1, "open",
                (v.get("severity") or "high").lower(),
                (v.get("title") or "Escalated cluster")[:120],
                brief,
                json.dumps(signals),
                json.dumps([a["id"] for a in alerts]),
                len(alerts),
                _as_float(v.get("confidence"), 0.5),
                json.dumps([{
                    "tier": 0, "model": self.distill_model, "decision": "escalate",
                    "rationale": v.get("uncertainty") or v.get("summary", ""),
                    "confidence": _as_float(v.get("confidence"), 0.5),
                    "ts": now,
                }]),
            ),
        )

    def _merge_into_open(self, conn: sqlite3.Connection, key: str, alerts: list[dict]) -> None:
        row = conn.execute(
            "SELECT id, alert_ids, alert_count FROM escalations "
            "WHERE dedup_key=? AND state='open' ORDER BY id DESC LIMIT 1", (key,)
        ).fetchone()
        if not row:
            return
        existing = set(json.loads(row["alert_ids"] or "[]"))
        new_ids = existing | {a["id"] for a in alerts}
        if new_ids == existing:
            return
        conn.execute(
            "UPDATE escalations SET alert_ids=?, alert_count=?, updated_at=? WHERE id=?",
            (json.dumps(sorted(new_ids)), len(new_ids), _now_iso(), row["id"]),
        )

    # ── TIERS 1-3: Claude analysts ────────────────────────────────────────

    def run_tier(self, tier_name: str) -> dict:
        if tier_name not in self.tiers:
            raise ValueError(f"unknown tier {tier_name!r}")
        tier_num = _TIER_NUM[tier_name]
        tcfg = self.tiers[tier_name]
        conn = self._connect()
        try:
            cases = conn.execute(
                "SELECT * FROM escalations WHERE tier=? AND state='open' "
                "ORDER BY updated_at ASC LIMIT ?",
                (tier_num, tcfg.max_cases),
            ).fetchall()
            if not cases:
                log.info("tier %s: no open cases", tier_name)
                return {"tier": tier_name, "cases": 0}

            counts = {"dismiss": 0, "resolve": 0, "promote": 0, "ping": 0, "error": 0}
            for case in cases:
                try:
                    decision = self._judge(conn, tier_name, tcfg, case)
                    conn.commit()
                    counts[decision] = counts.get(decision, 0) + 1
                except BrainError as exc:
                    log.error("tier %s: brain error on case %s: %s",
                              tier_name, case["id"], exc)
                    counts["error"] += 1
                    # Leave the case open; the next scheduled run retries it.
                    break  # likely auth/systemic - stop hammering this run
                except Exception:
                    log.exception("tier %s: case %s failed", tier_name, case["id"])
                    counts["error"] += 1
            conn.commit()
            result = {"tier": tier_name, "cases": len(cases), **counts}
            log.info("ladder tier %s: %s", tier_name, result)
            return result
        finally:
            conn.close()

    def _judge(self, conn: sqlite3.Connection, tier_name: str, tcfg: _TierCfg,
               case: sqlite3.Row) -> str:
        alerts = self._load_case_alerts(conn, case)
        chain = json.loads(case["chain"] or "[]")
        schema = _SCHEMA_OPUS if tier_name == "opus" else _SCHEMA_DISMISS_PROMOTE
        user = _TIER_USER_TMPL.format(
            id=case["id"], severity=case["severity"], alert_count=case["alert_count"],
            confidence=round(case["confidence"] or 0, 2), title=case["title"],
            brief=case["brief"] or "(none)",
            signals=case["signals"] or "{}",
            chain=_render_chain(chain),
            alerts=_render_alerts(alerts, limit=20),
            schema=schema,
        )
        verdict = self.brain.ask_json(
            tcfg.model, _TIER_SYSTEM[tier_name], user,
            max_tokens=tcfg.max_tokens, timeout=tcfg.timeout,
        )
        decision = str(verdict.get("decision", "")).lower().strip()
        valid = {"dismiss", "resolve", "ping"} if tier_name == "opus" else \
                {"dismiss", "resolve", "promote"}
        if decision not in valid:
            # Be conservative: promote (or, at Opus, resolve without paging).
            decision = "promote" if tier_name != "opus" else "resolve"

        meta = verdict.get("_meta", {})
        chain.append({
            "tier": _TIER_NUM[tier_name], "model": tcfg.model, "decision": decision,
            "headline": verdict.get("headline", ""),
            "rationale": verdict.get("rationale", ""),
            "confidence": verdict.get("confidence"),
            "severity": verdict.get("severity"),
            "recommended_action": verdict.get("recommended_action", ""),
            "latency_ms": meta.get("latency_ms"), "cost_usd": meta.get("cost_usd"),
            "ts": _now_iso(),
        })
        self._apply_decision(conn, case, tier_name, decision, verdict, chain)
        return decision

    def _apply_decision(self, conn: sqlite3.Connection, case: sqlite3.Row,
                        tier_name: str, decision: str, verdict: dict,
                        chain: list) -> None:
        now = _now_iso()
        sev = (verdict.get("severity") or case["severity"] or "medium").lower()
        headline = verdict.get("headline", "") or case["title"]
        base = {
            "chain": json.dumps(chain), "updated_at": now, "severity": sev,
            "confidence": _as_float(verdict.get("confidence"),
                                    _as_float(case["confidence"], 0.5)),
        }
        if decision == "promote":
            self._update(conn, case["id"], {**base, "tier": case["tier"] + 1})
        elif decision in ("dismiss", "resolve"):
            self._update(conn, case["id"], {
                **base, "tier": 4,
                "state": "dismissed" if decision == "dismiss" else "resolved",
                "resolution": f"[{tier_name}] {headline}: {verdict.get('rationale', '')}"[:1000],
            })
        elif decision == "ping":
            self._update(conn, case["id"], {
                **base, "tier": 4, "state": "pinged", "ping_sent": 1,
                "resolution": f"[opus PING] {headline}: {verdict.get('rationale', '')}"[:1000],
            })
            self._ping(conn, case, verdict, chain)

    @staticmethod
    def _update(conn: sqlite3.Connection, esc_id: int, fields: dict) -> None:
        cols = ", ".join(f"{k}=?" for k in fields)
        conn.execute(f"UPDATE escalations SET {cols} WHERE id=?",
                     (*fields.values(), esc_id))

    def _load_case_alerts(self, conn: sqlite3.Connection, case: sqlite3.Row) -> list[dict]:
        ids = json.loads(case["alert_ids"] or "[]")[:60]
        if not ids:
            return []
        ph = ",".join("?" * len(ids))
        rows = conn.execute(
            f"""SELECT id, timestamp, severity, title, description, src_ip, dst_ip,
                       dst_port, proto, category, verdict, ai_reasoning
                FROM alerts WHERE id IN ({ph})""", ids,
        ).fetchall()
        return [dict(r) for r in rows]

    # ── operator ping ─────────────────────────────────────────────────────

    def _ping(self, conn: sqlite3.Connection, case: sqlite3.Row, verdict: dict,
              chain: list) -> None:
        headline = verdict.get("headline", "") or case["title"]
        body = "\n".join(filter(None, [
            verdict.get("rationale", ""),
            f"→ {verdict.get('recommended_action')}" if verdict.get("recommended_action") else "",
            f"Severity: {verdict.get('severity', case['severity'])} | "
            f"Case #{case['id']} | {case['alert_count']} alerts",
        ]))
        sev = (verdict.get("severity") or case["severity"] or "high").lower()

        # 1) Always record an in-system squawk (never lose the page).
        try:
            conn.execute(
                "INSERT INTO squawks (ts, severity, title, detail, alert_ids, dismissed) "
                "VALUES (?,?,?,?,?,0)",
                (_now_iso(), sev, f"[OPUS] {headline}"[:200], body,
                 case["alert_ids"] or "[]"),
            )
        except Exception:
            log.exception("ping: failed to write squawk")

        # 2) Push to the operator via ntfy if configured.
        self._ntfy(sev, f"🔺 {headline}", body)
        log.warning("LADDER PING (opus): case #%s - %s", case["id"], headline)

    def _ntfy(self, severity: str, title: str, body: str) -> None:
        ntfy = getattr(getattr(self.cfg, "alerting", None), "ntfy", None)
        topic = getattr(ntfy, "topic", "") if ntfy else ""
        # ladder.ping may override the alerting ntfy topic
        lc = self._lc
        topic = getattr(lc, "ping_ntfy_topic", "") or topic
        if not topic:
            log.info("ping: no ntfy topic configured - squawk only")
            return
        server = (getattr(lc, "ping_ntfy_server", "")
                  or getattr(ntfy, "server", "") or "https://ntfy.sh").rstrip("/")
        prio = {"critical": "5", "high": "4", "medium": "3"}.get(severity, "3")
        try:
            req = urllib.request.Request(
                f"{server}/{topic}", data=body.encode("utf-8"), method="POST",
                headers={"Title": title.encode("ascii", "ignore").decode(),
                         "Priority": prio, "Tags": "rotating_light,shield"},
            )
            token = getattr(ntfy, "token", "") if ntfy else ""
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            urllib.request.urlopen(req, timeout=10)
            log.info("ping: pushed to ntfy topic %s", topic)
        except Exception as exc:  # noqa: BLE001
            log.error("ping: ntfy push failed: %s", exc)

    # ── ollama ────────────────────────────────────────────────────────────

    def _ollama_json(self, system: str, user: str) -> dict:
        payload = json.dumps({
            "model": self.distill_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": "json",
            "think": False,
            "options": {"temperature": 0.2, "num_ctx": 8192},
        }).encode()
        req = urllib.request.Request(
            f"{self.ollama_url}/api/chat", data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode())
        content = (data.get("message") or {}).get("content", "")
        obj = json.loads(content) if content.strip().startswith("{") else None
        if obj is None:
            from shallots.ai.oauth_brain import _extract_json_object
            obj = _extract_json_object(content)
        if obj is None:
            raise ValueError(f"qwen returned non-JSON: {content[:200]!r}")
        return obj

    # ── status / diagnostics ──────────────────────────────────────────────

    def status(self) -> dict:
        conn = self._connect()
        try:
            by = {}
            for tier, state, n in conn.execute(
                "SELECT tier, state, COUNT(*) FROM escalations GROUP BY tier, state"
            ):
                by[f"tier{tier}/{state}"] = n
            open_cases = conn.execute(
                "SELECT id, tier, severity, title, alert_count FROM escalations "
                "WHERE state='open' ORDER BY tier DESC, updated_at ASC LIMIT 20"
            ).fetchall()
            pinged = conn.execute(
                "SELECT id, severity, title, resolution FROM escalations "
                "WHERE state='pinged' ORDER BY id DESC LIMIT 10"
            ).fetchall()
            return {
                "counts": by,
                "open": [dict(r) for r in open_cases],
                "pinged": [dict(r) for r in pinged],
                "brain_available": self.brain.available(),
                "creds_expiry_epoch": self.brain.creds_expiry_epoch(),
            }
        finally:
            conn.close()


# ── rendering helpers ──────────────────────────────────────────────────────

def _render_alerts(alerts: list[dict], limit: int = 20) -> str:
    lines = []
    for a in alerts[:limit]:
        ts = (a.get("timestamp") or "")[:19]
        route = ""
        if a.get("src_ip") or a.get("dst_ip"):
            route = f" {a.get('src_ip', '?')}→{a.get('dst_ip', '?')}"
            if a.get("dst_port"):
                route += f":{a.get('dst_port')}"
        cat = f" [{a['category']}]" if a.get("category") else ""
        lines.append(f"- {ts} ({a.get('severity', '?')}){cat} {a.get('title', '')}{route}")
        reason = a.get("ai_reasoning") or ""
        if reason:
            lines.append(f"    qwen: {reason[:160]}")
    extra = len(alerts) - limit
    if extra > 0:
        lines.append(f"  … and {extra} more")
    return "\n".join(lines) or "(none)"


def _render_chain(chain: list) -> str:
    if not chain:
        return "(none)"
    out = []
    for step in chain:
        model = step.get("model", "?")
        dec = step.get("decision", "?")
        head = step.get("headline") or step.get("rationale", "")
        out.append(f"- [{model}] {dec}: {head[:160]}")
    return "\n".join(out)
