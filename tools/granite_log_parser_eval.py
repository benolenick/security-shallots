#!/usr/bin/env python3
"""Evaluate Granite as a grounded Security Shallots log parser."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO = Path("/home/user/security-shallots")
CORPUS = REPO / "data" / "fleet_context.db"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"


@dataclass(frozen=True)
class Case:
    name: str
    log: str
    query: str
    expect: dict[str, Any]
    context_terms: tuple[str, ...] = ()


CASES = [
    Case(
        name="host01_suricata_scope",
        log=(
            "2026-07-17T18:41:12Z suricata alert src=192.168.0.172:51544 "
            "dst=192.168.0.212:8000 proto=TCP signature_id=2210054 "
            "title='SURICATA STREAM excessive retransmissions' category='Generic Protocol Command Decode'"
        ),
        query="host01 Suricata HOME_NET coverage own traffic",
        expect={
            "source": "suricata",
            "src_ip": "192.168.0.172",
            "dst_ip": "192.168.0.212",
            "dst_port": 8000,
            "signature_id": 2210054,
        },
        context_terms=("own traffic", "HOME_NET", "192.168.0.0/24"),
    ),
    Case(
        name="dlink_syslog_noise",
        log=(
            "Jul 17 18:44:45 dlink COVR syslog user.notice src=192.168.0.1 "
            "message='Syslog [user] routine gateway status update'"
        ),
        query="D-Link router syslog noise 192.168.0.1 suppression",
        expect={"source": "syslog", "src_ip": "192.168.0.1"},
        context_terms=("D-Link", "router", "noise"),
    ),
    Case(
        name="argus_agent_offline",
        log=(
            "2026-07-17T18:50:03Z argus agent_health agent=host01 "
            "host=192.168.0.172 title='Agent offline: host01' severity=high"
        ),
        query="Argus host01 agent offline health alert",
        expect={"source": "argus", "src_ip": "192.168.0.172", "severity": "high"},
        context_terms=("Argus", "host01", "agent"),
    ),
    Case(
        name="ssh_scan_generic",
        log=(
            "2026-07-17T19:01:11Z suricata alert src=203.0.113.50:55321 "
            "dst=192.168.0.172:22 proto=TCP signature_id=2001219 "
            "title='ET SCAN Potential SSH Scan' category='Attempted Information Leak'"
        ),
        query="ET SCAN Potential SSH Scan port 22 knowledge",
        expect={
            "source": "suricata",
            "src_ip": "203.0.113.50",
            "dst_ip": "192.168.0.172",
            "dst_port": 22,
            "signature_id": 2001219,
        },
        context_terms=("SSH", "scan", "reconnaissance"),
    ),
]


SYSTEM = """You are a log parser for Security Shallots.
Return only valid JSON. Extract facts from the log exactly.
Use retrieved context only for analyst_notes and context_facts.
The source field must be one of: suricata, wazuh, crowdsec, syslog, pfsense,
pihole, argus, webapp. Source means the collector/log source type, not a
hostname, vendor, rule author, or device name.
Do not decide suppress/investigate/escalate; set verdict_recommendation to "none".
If a field is absent, use null."""

ENRICH_SYSTEM = """You enrich an already-parsed Security Shallots log record.
Return only valid JSON. Do not change extracted fields. Use retrieved context only
to write context_facts and analyst_notes. Prefer concrete fleet facts from the
retrieved context, such as sensor coverage, known noise, HOME_NET, or agent role.
Do not decide suppress/investigate/escalate;
set verdict_recommendation to "none"."""


def retrieve(query: str, limit: int = 4) -> str:
    if not CORPUS.exists():
        return ""
    fts_query = " ".join(
        f'"{token.replace("\"", "\"\"")}"'
        for token in re.findall(r"[A-Za-z0-9_.:-]+", query)
    )
    if not fts_query:
        return ""
    conn = sqlite3.connect(CORPUS)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT d.category, d.title, d.source,
                   snippet(documents_fts, 1, '[', ']', ' ... ', 30) AS snippet
            FROM documents_fts
            JOIN documents d ON d.rowid = documents_fts.rowid
            WHERE documents_fts MATCH ?
            ORDER BY bm25(documents_fts)
            LIMIT ?
            """,
            (fts_query, limit),
        ).fetchall()
    finally:
        conn.close()
    return "\n\n".join(
        f"[{r['category']}] {r['title']} ({r['source']})\n{r['snippet']}" for r in rows
    )


def call_ollama(model: str, prompt: str, system: str = SYSTEM) -> tuple[dict[str, Any], float]:
    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "format": "json",
            "keep_alive": -1,
            "options": {"temperature": 0, "num_predict": 420},
        }
    ).encode()
    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=180) as resp:
        body = json.loads(resp.read().decode())
    elapsed = time.perf_counter() - start
    raw = body.get("response", "{}")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, re.S)
        parsed = json.loads(match.group(0)) if match else {"_parse_error": raw}
    return parsed, elapsed


def prompt_for(case: Case, context: str) -> str:
    return f"""Retrieved context:
{context or "(none)"}

Log line:
{case.log}

Return JSON with these keys:
source, event_type, severity, src_ip, src_port, dst_ip, dst_port, proto,
signature_id, title, entities, context_facts, analyst_notes,
verdict_recommendation.

Rules:
- source is the collector type enum, not the emitting hostname.
- If a syslog line says "dlink COVR syslog", source is "syslog" and dlink/COVR
  belong in entities.
- If a Suricata line uses an Emerging Threats title, source is still "suricata".
- Retrieved context may not override src_ip, dst_ip, ports, proto, title, or source."""


def enrich_prompt(case: Case, parsed: dict[str, Any], context: str) -> str:
    return f"""Retrieved context:
{context or "(none)"}

Original log line:
{case.log}

Frozen extracted fields:
{json.dumps(parsed, indent=2, sort_keys=True)}

Return JSON with these keys:
context_facts, analyst_notes, verdict_recommendation."""


def score(case: Case, parsed: dict[str, Any]) -> dict[str, Any]:
    field_hits = 0
    field_total = len(case.expect)
    misses = []
    for key, expected in case.expect.items():
        actual = parsed.get(key)
        if str(actual).lower() == str(expected).lower():
            field_hits += 1
        else:
            misses.append({"field": key, "expected": expected, "actual": actual})

    text = json.dumps(parsed, sort_keys=True)
    context_hits = [term for term in case.context_terms if term.lower() in text.lower()]
    abstained = str(parsed.get("verdict_recommendation", "")).lower() == "none"
    return {
        "field_hits": field_hits,
        "field_total": field_total,
        "field_score": field_hits / field_total if field_total else 1,
        "misses": misses,
        "context_hits": context_hits,
        "context_total": len(case.context_terms),
        "abstained": abstained,
    }


def run(model: str) -> dict[str, Any]:
    results = []
    for case in CASES:
        parsed_no_context: dict[str, Any] | None = None
        no_context_latency = 0.0
        for mode in ("no_context", "with_corpus", "parse_then_enrich"):
            context = retrieve(case.query) if mode == "with_corpus" else ""
            if mode == "parse_then_enrich":
                context = retrieve(case.query)
                if parsed_no_context is None:
                    parsed_no_context, no_context_latency = call_ollama(model, prompt_for(case, ""))
                enrichment, second_latency = call_ollama(
                    model,
                    enrich_prompt(case, parsed_no_context, context),
                    system=ENRICH_SYSTEM,
                )
                parsed = dict(parsed_no_context)
                parsed["context_facts"] = enrichment.get("context_facts")
                parsed["analyst_notes"] = enrichment.get("analyst_notes")
                parsed["verdict_recommendation"] = enrichment.get("verdict_recommendation", "none")
                latency = no_context_latency + second_latency
            else:
                parsed, latency = call_ollama(model, prompt_for(case, context))
                if mode == "no_context":
                    parsed_no_context = parsed
                    no_context_latency = latency
            results.append(
                {
                    "case": case.name,
                    "mode": mode,
                    "latency_sec": round(latency, 3),
                    "parsed": parsed,
                    "score": score(case, parsed),
                }
            )

    summary = {
        "model": model,
        "cases": len(CASES),
        "results": results,
    }
    for mode in ("no_context", "with_corpus", "parse_then_enrich"):
        subset = [r for r in results if r["mode"] == mode]
        summary[f"{mode}_field_score"] = round(
            sum(r["score"]["field_score"] for r in subset) / len(subset), 3
        )
        summary[f"{mode}_context_hits"] = sum(len(r["score"]["context_hits"]) for r in subset)
        summary[f"{mode}_abstained"] = sum(1 for r in subset if r["score"]["abstained"])
        summary[f"{mode}_avg_latency_sec"] = round(
            sum(r["latency_sec"] for r in subset) / len(subset), 3
        )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="granite3.3:8b")
    parser.add_argument("--out", type=Path, default=REPO / "data" / "granite_log_parser_eval.json")
    args = parser.parse_args()

    # Ensure the corpus exists, but keep this non-fatal so no-context tests still run.
    if not CORPUS.exists():
        subprocess.run(["python3", str(REPO / "tools/shallot_fleet_corpus.py"), "build"], check=False)

    summary = run(args.model)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, indent=2, sort_keys=True))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
