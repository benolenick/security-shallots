"""Evidence-graph case ranker - the honest v1 of "causal land / feature elevation".

Composes the EXISTING pieces (NetworkGraph topology + kill-chain stage map) into the
one thing that was missing: scan the whole evidence graph, put an ELEVATION (danger
cost) on each node from facts we already have (reputation, category, verdict, rarity,
hard-threat keywords), group into connected components, find the worst short PATH inside
each, and emit a ranked list of top-N CASES with the exact evidence cited.

Design notes (per codex sanity-check 2026-07-16):
  * NOT a manifold. Plain weighted graph + component/path scoring. The curved-surface
    geodesic is deferred until there's dense enough provenance to justify it.
  * Honest name: TEMPORAL EVIDENCE graph, not causal provenance - with network/dns/auth/
    cron sensors (no eBPF process lineage) many edges are temporal-correlation-on-shared-
    identifier, not true causality. Degrades gracefully to host-centered stars.
  * Scoring is threat_gain-per-compactness, NOT vanilla shortest-path: a SHORT component
    that touches SEVERAL high-danger kill-chain stages is the worst. Long flat = benign.
  * The LLM never appears here. This layer is deterministic and cite-only. It squawks.
    It has NO bearing on what is/isn't an incident (per Ben's standing rule).

Run:  python3 -m shallots.analyze.case_ranker [--hours N] [--top N] [--json] [--db PATH]
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from collections import defaultdict
from typing import Any

from shallots.ai.graph_engine import NetworkGraph, _is_rfc1918
from shallots.ai.killchain import KILL_CHAIN_STAGES

# ── ELEVATION: how "dangerous/steep" a step is, from facts we already store ──────────
# Base danger per alert category (lowercased substring match, first hit wins).
_CATEGORY_ELEVATION = [
    ("c2", 0.92), ("command_control", 0.92), ("command and control", 0.92),
    ("ransomware", 0.95), ("malware", 0.90), ("exfil", 0.88),
    ("data_exfil", 0.88), ("collection", 0.72), ("lateral_movement", 0.75),
    ("lateral movement", 0.75), ("persistence", 0.70), ("privilege", 0.72),
    ("exploit", 0.80), ("brute", 0.65), ("credential", 0.65),
    ("bad traffic", 0.45), ("potentially bad", 0.45),
    ("information leak", 0.30), ("scan", 0.35), ("probe", 0.35),
    ("dns", 0.20), ("protocol command decode", 0.15),
    ("misc", 0.06), ("not suspicious", 0.03), ("syslog", 0.04),
    ("agent_health", 0.02), ("state_management", 0.05),
]

# HARD-THREAT keywords - a concrete threat signal in title/category. These FLOOR the
# node elevation high AND flag the case must-review. Same spirit as edge_triage's floor:
# a deterministic dumb layer that a fuzzy score can never talk down.
_HARD_THREAT = (
    "known-malware", "malware domain", "malware feed", "urlhaus", "known malware",
    "threat-intel", "brute force", "brute-force", "c2 ", " c2", "beacon",
    "command-and-control", "virustotal", "malicious", "ransomware", "exfil",
    "reverse shell", "abuseipdb",
)

_VERDICT_BONUS = {"escalate": 0.30, "investigate": 0.10, "suppress": 0.0, "": 0.0, None: 0.0}


def _cat_elevation(category: str) -> float:
    c = (category or "").lower()
    for key, val in _CATEGORY_ELEVATION:
        if key in c:
            return val
    return 0.10  # unknown category - mild


def _is_hard_threat(title: str, category: str, description: str) -> bool:
    t = f"{title} {category} {description}".lower()
    return any(m in t for m in _HARD_THREAT)


def _alert_elevation(alert: dict, rep: dict[str, dict]) -> tuple[float, bool]:
    """Elevation (0..1) for one alert + whether it's a hard-threat. Facts only."""
    title = alert.get("title") or ""
    cat = alert.get("category") or ""
    desc = alert.get("description") or ""
    elev = _cat_elevation(cat)
    hard = _is_hard_threat(title, cat, desc)

    # reputation of either endpoint = a cliff
    for ipf in ("src_ip", "dst_ip"):
        ip = alert.get(ipf) or ""
        r = rep.get(ip)
        if not r:
            continue
        if (r.get("vt_malicious") or 0) > 0 or (r.get("abuse_score") or 0) >= 50 \
                or (r.get("verdict") or "") == "malicious":
            elev = max(elev, 0.88)
            hard = True

    elev += _VERDICT_BONUS.get(alert.get("verdict"), 0.0)
    if hard:
        elev = max(elev, 0.85)
    return min(elev, 1.0), hard


def _alert_stage(alert: dict) -> str | None:
    """Map an alert to a kill-chain stage via the existing keyword map (labels only)."""
    hay = f"{alert.get('title','')} {alert.get('category','')} {alert.get('description','')}".lower()
    for stage_name, sdef in KILL_CHAIN_STAGES.items():
        for kw in sdef.get("keywords", []):
            if kw in hay:
                return stage_name
        for pat in sdef.get("patterns", []):
            if pat in hay:
                return stage_name
    return None


def _entities(alert: dict) -> list[str]:
    out = []
    for f in ("src_ip", "dst_ip"):
        v = alert.get(f) or ""
        if v and v not in (":0", "-"):
            out.append(v)
    for f in ("src_dns", "dst_dns"):
        v = alert.get(f) or ""
        if v and "." in v and not v.replace(".", "").isdigit():
            out.append(v)
    return out


def load_alerts(db_path: str, hours: int) -> list[dict]:
    c = sqlite3.connect(db_path)
    c.row_factory = sqlite3.Row
    if hours > 0:
        rows = c.execute(
            "SELECT * FROM alerts WHERE datetime(ingested_at) >= datetime('now', ?) "
            "ORDER BY id", (f"-{hours} hours",)).fetchall()
    else:
        rows = c.execute("SELECT * FROM alerts ORDER BY id").fetchall()
    alerts = [dict(r) for r in rows]
    rep = {r["ip"]: dict(r) for r in c.execute("SELECT * FROM ip_reputation").fetchall()}
    c.close()
    return alerts, rep


def rank_cases(alerts: list[dict], rep: dict[str, dict], top: int = 5) -> list[dict]:
    """Build the evidence graph, elevate nodes, score components, return top-N cases."""
    graph = NetworkGraph.__new__(NetworkGraph)  # topology only; skip async __init__ bits
    graph._nodes = {}
    graph._edges = defaultdict(lambda: defaultdict(dict))
    graph._reverse = defaultdict(set)
    graph._edge_count = 0

    # per-entity accumulators
    node_elev: dict[str, float] = defaultdict(float)   # peak elevation seen on the node
    node_hard: dict[str, bool] = defaultdict(bool)
    node_stages: dict[str, set] = defaultdict(set)
    node_alerts: dict[str, list] = defaultdict(list)

    for a in alerts:
        graph.ingest_alert(a)
        elev, hard = _alert_elevation(a, rep)
        stage = _alert_stage(a)
        for ent in _entities(a):
            node_elev[ent] = max(node_elev[ent], elev)
            node_hard[ent] = node_hard[ent] or hard
            if stage:
                node_stages[ent].add(stage)
            node_alerts[ent].append({
                "id": a.get("id"), "title": (a.get("title") or "")[:80],
                "category": a.get("category"), "verdict": a.get("verdict"),
                "elev": round(elev, 2), "stage": stage,
            })

    # group into connected components (reuse label-propagation)
    communities = graph.detect_communities() or []
    # singletons that detect_communities may drop but that carry elevation
    grouped = {n for comm in communities for n in comm}
    for n in node_elev:
        if n not in grouped:
            communities.append([n])

    cases: list[dict] = []
    for comm in communities:
        members = [m for m in comm if m in node_elev or m in graph._nodes]
        if not members:
            continue
        elevs = {m: node_elev.get(m, 0.0) for m in members}
        peak_node = max(elevs, key=elevs.get)
        peak = elevs[peak_node]
        if peak < 0.15:
            continue  # nothing interesting in this component - stays silent

        # distinct kill-chain stages present in the component (breadth of the chain)
        stages = set()
        for m in members:
            stages |= node_stages.get(m, set())
        n_elevated = sum(1 for m in members if elevs[m] >= 0.5)
        hard = any(node_hard.get(m) for m in members)

        # SCORE = threat_gain, boosted by multi-stage compactness (a short chain that
        # spans several kill-chain stages is the worst). NOT shortest-path-avoids-danger.
        stage_bonus = 0.15 * max(len(stages) - 1, 0)
        chain_bonus = 0.10 * max(n_elevated - 1, 0)
        score = min(peak + stage_bonus + chain_bonus, 1.0)

        # worst PATH inside the component (between the two most-elevated nodes)
        path = []
        if len(members) >= 2:
            ranked = sorted(members, key=lambda m: elevs[m], reverse=True)
            a_node, b_node = ranked[0], ranked[1]
            fp = graph.find_paths(a_node, b_node, max_depth=5) or graph.find_paths(b_node, a_node, max_depth=5)
            if fp:
                path = fp[0]

        # evidence: all alerts on member entities, worst first
        ev = []
        for m in members:
            ev.extend(node_alerts.get(m, []))
        ev.sort(key=lambda e: e["elev"], reverse=True)

        # order stages by kill-chain order for readable narration
        ordered_stages = sorted(
            stages, key=lambda s: KILL_CHAIN_STAGES.get(s, {}).get("order", 99))

        cases.append({
            "score": round(score, 3),
            "peak_elevation": round(peak, 3),
            "hard_threat": hard,
            "focus": peak_node,
            "members": members,
            "n_members": len(members),
            "n_elevated": n_elevated,
            "kill_chain_stages": ordered_stages,
            "n_stages": len(stages),
            "path": path,
            "evidence": ev[:8],
            "why": _why(peak_node, peak, ordered_stages, n_elevated, hard, path),
        })

    cases.sort(key=lambda c: (c["hard_threat"], c["score"]), reverse=True)
    return cases[:top]


def _why(focus, peak, stages, n_elevated, hard, path) -> str:
    bits = []
    if hard:
        bits.append("HARD THREAT signal (reputation / malware / C2 / brute-force keyword)")
    if len(stages) >= 2:
        bits.append("spans " + " → ".join(stages) + " (multi-stage)")
    elif stages:
        bits.append(f"kill-chain stage: {stages[0]}")
    if n_elevated >= 2:
        bits.append(f"{n_elevated} elevated entities in one component")
    if path and len(path) >= 2:
        bits.append("path " + " → ".join(path))
    if not bits:
        bits.append(f"elevated activity on {focus} (peak {peak:.2f})")
    return "; ".join(bits)


def render(cases: list[dict], hours: int) -> str:
    win = f"last {hours}h" if hours > 0 else "all history"
    if not cases:
        return f"✓ Evidence graph ({win}): no cases above threshold. Quiet."
    lines = [f"═══ TOP {len(cases)} CASES - evidence graph ({win}) ═══", ""]
    for i, c in enumerate(cases, 1):
        flag = "🔴" if c["hard_threat"] else ("🟠" if c["score"] >= 0.6 else "🟡")
        lines.append(f"{flag} CASE {i}  score={c['score']:.2f}  focus={c['focus']}  "
                     f"({c['n_members']} entities, {c['n_stages']} stage(s))")
        lines.append(f"   why: {c['why']}")
        if c["path"]:
            lines.append(f"   path: {' → '.join(c['path'])}")
        lines.append("   evidence:")
        for e in c["evidence"][:5]:
            lines.append(f"     • [{e['elev']:.2f}] {e['title']}  "
                         f"({e['category']}/{e['verdict']}"
                         + (f", {e['stage']}" if e["stage"] else "") + ")")
        lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=0, help="lookback window (0=all)")
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--db", default="shallots.db")
    args = ap.parse_args()
    alerts, rep = load_alerts(args.db, args.hours)
    cases = rank_cases(alerts, rep, top=args.top)
    if args.json:
        print(json.dumps({"window_hours": args.hours, "n_alerts": len(alerts),
                          "cases": cases}, indent=1))
    else:
        print(f"(analyzed {len(alerts)} alerts, {len(rep)} reputation records)\n")
        print(render(cases, args.hours))


if __name__ == "__main__":
    main()
