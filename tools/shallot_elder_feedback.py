#!/usr/bin/env python3
"""Ask an elder model to critique Scout cards/squawks and store feedback.

This is a guarded tuning loop: it records labels and policy proposals, but it
does not edit prompts, rules, thresholds, or verdicts.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "shallots.db"
OUT_DIR = ROOT / "data" / "elder_feedback"

SYSTEM = """You are the elder reviewer for Security Shallots.
Your job is to critique edge Scout cards and Autopilot squawks so the smaller
edge system can be tuned.

You do not decide whether activity is benign or malicious. Label whether each
card/squawk is useful for preserving visibility under an upstream review budget.

Use only these labels:
- useful_candidate
- noisy_card
- missed_context
- duplicate_or_stale
- needs_policy_change
- insufficient_evidence

Return JSON only with:
{
  "reviews": [
    {
      "target_type": "scout_card|squawk",
      "target_id": "string",
      "alert_id": "string",
      "label": "one allowed label",
      "confidence": 0.0,
      "rationale": "short",
      "suggested_action": "keep|downgrade|dedupe|block_pattern|add_context|monitor",
      "suggested_policy": "short concrete policy suggestion"
    }
  ],
  "policy_proposals": [
    {
      "title": "short",
      "proposal_type": "policy|dedupe|threshold|context|test",
      "detail": "what to change",
      "patch_hint": "where/how, if known",
      "expected_effect": "short",
      "risk": "short",
      "source_target_ids": ["ids"]
    }
  ],
  "summary": "short verdict"
}

Be skeptical of novelty-only cards and repeated INFO DNS/TLD squawks. Preserve
management-plane, control-plane, source-integrity, persistence, and clearly
corroborated signals. Do not suggest autonomous code changes."""


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS scout_feedback (
            id TEXT PRIMARY KEY,
            target_type TEXT NOT NULL DEFAULT 'scout_card',
            target_id TEXT NOT NULL,
            alert_id TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            reviewer_model TEXT DEFAULT '',
            label TEXT NOT NULL,
            confidence REAL DEFAULT 0.0,
            rationale TEXT DEFAULT '',
            suggested_action TEXT DEFAULT '',
            suggested_policy TEXT DEFAULT '',
            raw_review TEXT DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_scout_feedback_target ON scout_feedback(target_type, target_id);
        CREATE INDEX IF NOT EXISTS idx_scout_feedback_label ON scout_feedback(label);
        CREATE INDEX IF NOT EXISTS idx_scout_feedback_created ON scout_feedback(created_at);

        CREATE TABLE IF NOT EXISTS scout_policy_proposals (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            source_feedback_ids TEXT DEFAULT '[]',
            status TEXT DEFAULT 'proposed',
            title TEXT NOT NULL,
            proposal_type TEXT DEFAULT 'policy',
            detail TEXT DEFAULT '',
            patch_hint TEXT DEFAULT '',
            expected_effect TEXT DEFAULT '',
            risk TEXT DEFAULT '',
            reviewer_model TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_scout_policy_proposals_status ON scout_policy_proposals(status);
        CREATE INDEX IF NOT EXISTS idx_scout_policy_proposals_created ON scout_policy_proposals(created_at);
        """
    )
    con.commit()


def load_targets(con: sqlite3.Connection, limit: int, since_minutes: int) -> dict[str, list[dict[str, Any]]]:
    scout = [
        dict(r)
        for r in con.execute(
            """
            SELECT sc.id AS target_id, sc.alert_id, sc.created_at, sc.model, sc.score,
                   sc.reasons, sc.context_facts, sc.scout_note,
                   a.source, a.severity, a.verdict, a.title, a.description,
                   a.src_ip, a.dst_ip, a.dst_port, a.category
            FROM scout_cards sc
            JOIN alerts a ON a.id = sc.alert_id
            LEFT JOIN scout_feedback fb
              ON fb.target_type = 'scout_card' AND fb.target_id = sc.id
            WHERE fb.id IS NULL
              AND sc.created_at >= datetime('now', ?)
            ORDER BY sc.created_at DESC
            LIMIT ?
            """,
            (f"-{since_minutes} minutes", limit),
        )
    ]
    squawks = [
        dict(r)
        for r in con.execute(
            """
            SELECT s.id AS target_id, s.ts AS created_at, s.severity, s.title,
                   s.detail, s.alert_ids, s.dismissed
            FROM squawks s
            LEFT JOIN scout_feedback fb
              ON fb.target_type = 'squawk' AND fb.target_id = s.id
            WHERE fb.id IS NULL
              AND s.dismissed = 0
              AND s.ts >= datetime('now', ?)
            ORDER BY s.ts DESC
            LIMIT ?
            """,
            (f"-{since_minutes} minutes", limit),
        )
    ]
    return {"scout_cards": scout, "squawks": squawks}


def call_elder(model: str, payload: dict[str, Any], timeout: int) -> tuple[dict[str, Any], float]:
    prompt = SYSTEM + "\n\nTargets:\n" + json.dumps(payload, indent=2, sort_keys=True)
    start = time.perf_counter()
    proc = subprocess.run(
        ["claude", "-p", "--model", model, "--output-format", "json"],
        input=prompt,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=True,
    )
    elapsed = time.perf_counter() - start
    raw = str(json.loads(proc.stdout).get("result", "{}")).strip()
    if raw.startswith("```"):
        raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    return json.loads(raw), elapsed


def store_review(con: sqlite3.Connection, model: str, review: dict[str, Any]) -> str:
    fid = str(uuid.uuid4())
    con.execute(
        """
        INSERT INTO scout_feedback
        (id, target_type, target_id, alert_id, created_at, reviewer_model,
         label, confidence, rationale, suggested_action, suggested_policy, raw_review)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            fid,
            str(review.get("target_type") or ""),
            str(review.get("target_id") or ""),
            str(review.get("alert_id") or ""),
            datetime.now(timezone.utc).isoformat(),
            model,
            str(review.get("label") or "insufficient_evidence"),
            float(review.get("confidence") or 0.0),
            str(review.get("rationale") or ""),
            str(review.get("suggested_action") or ""),
            str(review.get("suggested_policy") or ""),
            json.dumps(review, sort_keys=True),
        ),
    )
    return fid


def store_proposal(
    con: sqlite3.Connection,
    model: str,
    proposal: dict[str, Any],
    feedback_by_target: dict[str, str],
) -> str:
    source_targets = [str(x) for x in proposal.get("source_target_ids") or []]
    source_feedback = [feedback_by_target[t] for t in source_targets if t in feedback_by_target]
    pid = str(uuid.uuid4())
    con.execute(
        """
        INSERT INTO scout_policy_proposals
        (id, created_at, source_feedback_ids, status, title, proposal_type,
         detail, patch_hint, expected_effect, risk, reviewer_model)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            pid,
            datetime.now(timezone.utc).isoformat(),
            json.dumps(source_feedback),
            "proposed",
            str(proposal.get("title") or "Elder feedback proposal"),
            str(proposal.get("proposal_type") or "policy"),
            str(proposal.get("detail") or ""),
            str(proposal.get("patch_hint") or ""),
            str(proposal.get("expected_effect") or ""),
            str(proposal.get("risk") or ""),
            model,
        ),
    )
    return pid


def summarize(con: sqlite3.Connection, since_hours: int) -> dict[str, Any]:
    rows = con.execute(
        """
        SELECT label, COUNT(*) AS c
        FROM scout_feedback
        WHERE created_at >= datetime('now', ?)
        GROUP BY label
        ORDER BY c DESC
        """,
        (f"-{since_hours} hours",),
    ).fetchall()
    proposals = con.execute(
        """
        SELECT status, COUNT(*) AS c
        FROM scout_policy_proposals
        WHERE created_at >= datetime('now', ?)
        GROUP BY status
        """,
        (f"-{since_hours} hours",),
    ).fetchall()
    return {
        "feedback_by_label": {r["label"]: r["c"] for r in rows},
        "proposals_by_status": {r["status"]: r["c"] for r in proposals},
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    con = connect()
    try:
        ensure_schema(con)
        targets = load_targets(con, args.limit, args.since_minutes)
        target_count = len(targets["scout_cards"]) + len(targets["squawks"])
        if target_count == 0:
            result = {
                "status": "no_targets",
                "target_count": 0,
                "summary": summarize(con, args.summary_hours),
            }
        elif args.dry_run:
            result = {"status": "dry_run", "target_count": target_count, "targets": targets}
        else:
            review, latency = call_elder(args.model, targets, args.timeout)
            feedback_by_target: dict[str, str] = {}
            feedback_ids = []
            for item in review.get("reviews") or []:
                if not isinstance(item, dict):
                    continue
                fid = store_review(con, args.model, item)
                feedback_ids.append(fid)
                feedback_by_target[str(item.get("target_id") or "")] = fid
            proposal_ids = []
            for proposal in review.get("policy_proposals") or []:
                if isinstance(proposal, dict):
                    proposal_ids.append(store_proposal(con, args.model, proposal, feedback_by_target))
            con.commit()
            result = {
                "status": "reviewed",
                "target_count": target_count,
                "feedback_written": len(feedback_ids),
                "proposal_written": len(proposal_ids),
                "feedback_ids": feedback_ids,
                "proposal_ids": proposal_ids,
                "elder_summary": review.get("summary", ""),
                "latency_sec": round(latency, 3),
                "summary": summarize(con, args.summary_hours),
            }
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        out = OUT_DIR / f"elder-feedback-{int(time.time())}.json"
        result["output_path"] = str(out)
        out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return result
    finally:
        con.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="opus")
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--since-minutes", type=int, default=180)
    parser.add_argument("--summary-hours", type=int, default=24)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
