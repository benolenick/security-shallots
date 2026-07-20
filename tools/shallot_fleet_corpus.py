#!/usr/bin/env python3
"""Build and query a local fleet-context corpus for Shallots analysis.

This tool is intentionally read-only against production state. It creates a
separate SQLite FTS corpus that small local models can use for grounded context.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


DEFAULT_REPO = Path("/home/user/security-shallots")
DEFAULT_OUT = DEFAULT_REPO / "data" / "fleet_context.db"
DEFAULT_DB = DEFAULT_REPO / "shallots.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    source TEXT NOT NULL,
    content TEXT NOT NULL,
    collected_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
    title,
    content,
    category,
    source UNINDEXED,
    content=documents,
    content_rowid=rowid
);

CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
    INSERT INTO documents_fts(rowid, title, content, category, source)
    VALUES (new.rowid, new.title, new.content, new.category, new.source);
END;

CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, title, content, category, source)
    VALUES ('delete', old.rowid, old.title, old.content, old.category, old.source);
END;

CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
    INSERT INTO documents_fts(documents_fts, rowid, title, content, category, source)
    VALUES ('delete', old.rowid, old.title, old.content, old.category, old.source);
    INSERT INTO documents_fts(rowid, title, content, category, source)
    VALUES (new.rowid, new.title, new.content, new.category, new.source);
END;
"""

SECRET_RE = re.compile(
    r"(?i)(password|passwd|api[_-]?key|secret|token|hmac|authorization|bearer"
    r"|webhook|ntfy)[\"']?\s*[:=]\s*[\"']?[^\"'\n#]+"
)


@dataclass(frozen=True)
class Document:
    category: str
    title: str
    source: str
    content: str

    @property
    def id(self) -> str:
        raw = f"{self.category}:{self.source}:{self.title}"
        return re.sub(r"[^A-Za-z0-9_.:-]+", "_", raw)[:240]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact(text: str) -> str:
    return SECRET_RE.sub(lambda m: f"{m.group(1)}: REDACTED", text)


def read_text(path: Path, limit: int = 80_000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    return redact(text[:limit])


def doc_from_file(repo: Path, rel: str, category: str) -> Document | None:
    path = repo / rel
    text = read_text(path)
    if not text.strip():
        return None
    return Document(category, rel, str(path), text)


def db_connect(db_path: Path) -> sqlite3.Connection | None:
    if not db_path.exists():
        return None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def query_rows(
    conn: sqlite3.Connection,
    sql: str,
    params: tuple[object, ...] = (),
    limit: int = 200,
) -> list[dict[str, object]]:
    rows = conn.execute(sql, params).fetchmany(limit)
    return [dict(row) for row in rows]


def json_block(title: str, value: object) -> str:
    return f"{title}\n{json.dumps(value, indent=2, sort_keys=True, default=str)}"


def collect_static_docs(repo: Path) -> Iterable[Document]:
    specs = [
        ("SIGIL.md", "deployment"),
        ("AI_CONTEXT.md", "deployment"),
        ("docs/NETWORK_LOG_SOURCES.yaml", "deployment"),
        ("docs/EXPERIMENT_LOG.md", "experiments"),
        ("docs/EXPERIMENT_PLAN.md", "experiments"),
        ("THREAT_ENGINE_DESIGN.md", "architecture"),
        ("README.md", "project"),
        ("shallots/data/netsec_knowledge.json", "security_knowledge"),
    ]
    for rel, category in specs:
        doc = doc_from_file(repo, rel, category)
        if doc:
            yield doc

    config = doc_from_file(repo, "config.yaml", "deployment")
    if config:
        yield Document(
            config.category,
            "config.yaml redacted",
            config.source,
            config.content,
        )


def collect_db_docs(db_path: Path) -> Iterable[Document]:
    conn = db_connect(db_path)
    if conn is None:
        return
    try:
        if table_exists(conn, "agent_status"):
            agents = query_rows(
                conn,
                """
                SELECT agent_name, agent_type, os, ip, version, status,
                       last_heartbeat, last_alert, alert_count, health_data
                FROM agent_status
                ORDER BY agent_name
                """,
            )
            yield Document(
                "fleet_state",
                "registered agents and latest health",
                str(db_path),
                json_block("Registered Shallots/Argus agents", agents),
            )

        if table_exists(conn, "alerts"):
            totals = query_rows(
                conn,
                """
                SELECT source, severity, verdict, COUNT(*) AS count
                FROM alerts
                GROUP BY source, severity, verdict
                ORDER BY count DESC
                """,
            )
            recent = query_rows(
                conn,
                """
                SELECT timestamp, source, severity, verdict, title, category,
                       src_ip, src_port, dst_ip, dst_port, proto, signature_id
                FROM alerts
                ORDER BY COALESCE(ingested_at, timestamp) DESC
                LIMIT 100
                """,
            )
            top_signatures = query_rows(
                conn,
                """
                SELECT source, signature_id, title, category, COUNT(*) AS count,
                       MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
                FROM alerts
                GROUP BY source, signature_id, title, category
                ORDER BY count DESC
                LIMIT 100
                """,
            )
            yield Document(
                "alert_baseline",
                "alert volume by source severity verdict",
                str(db_path),
                json_block("Alert volume baseline", totals),
            )
            yield Document(
                "alert_baseline",
                "recent alerts",
                str(db_path),
                json_block("Most recent alerts", recent),
            )
            yield Document(
                "alert_baseline",
                "top alert signatures",
                str(db_path),
                json_block("Most frequent alert signatures", top_signatures),
            )

        if table_exists(conn, "silence_rules"):
            rows = query_rows(
                conn,
                """
                SELECT match_type, pattern, pattern2, reason, hit_count,
                       last_hit, created_at
                FROM silence_rules
                ORDER BY hit_count DESC, created_at DESC
                """,
            )
            yield Document(
                "noise_policy",
                "active silence rules",
                str(db_path),
                json_block("Configured silence/suppression rules", rows),
            )

        if table_exists(conn, "assets"):
            rows = query_rows(
                conn,
                """
                SELECT ip, mac, hostname, os, asset_type, criticality,
                       network_segment, first_seen, last_seen, alert_count,
                       notes, source
                FROM assets
                ORDER BY criticality DESC, alert_count DESC, last_seen DESC
                """,
                limit=500,
            )
            yield Document(
                "fleet_inventory",
                "asset inventory",
                str(db_path),
                json_block("Known assets and criticality", rows),
            )

        if table_exists(conn, "known_devices"):
            rows = query_rows(
                conn,
                """
                SELECT mac, ip, hostname, first_seen, last_seen, alert_generated
                FROM known_devices
                ORDER BY last_seen DESC
                """,
                limit=500,
            )
            yield Document(
                "fleet_inventory",
                "known devices",
                str(db_path),
                json_block("Known devices seen on the network", rows),
            )

        if table_exists(conn, "dhcp_history"):
            rows = query_rows(
                conn,
                """
                SELECT ip, mac, hostname, interface, lease_type,
                       MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen,
                       COUNT(*) AS lease_count
                FROM dhcp_history
                GROUP BY ip, mac, hostname, interface, lease_type
                ORDER BY last_seen DESC
                """,
                limit=500,
            )
            yield Document(
                "fleet_inventory",
                "dhcp lease history",
                str(db_path),
                json_block("DHCP lease history by device", rows),
            )

        if table_exists(conn, "device_baselines"):
            rows = query_rows(
                conn,
                """
                SELECT ip, asset_name, first_seen, last_seen, profile_json,
                       baseline_updated
                FROM device_baselines
                ORDER BY last_seen DESC
                """,
                limit=500,
            )
            yield Document(
                "fleet_baseline",
                "device behavior baselines",
                str(db_path),
                json_block("Device behavior baselines", rows),
            )

        if table_exists(conn, "graph_edges"):
            rows = query_rows(
                conn,
                """
                SELECT src, dst, edge_type, weight, first_seen, last_seen,
                       sample_alert_id
                FROM graph_edges
                ORDER BY weight DESC, last_seen DESC
                """,
                limit=500,
            )
            yield Document(
                "fleet_topology",
                "network graph edges",
                str(db_path),
                json_block("Observed graph edges and weights", rows),
            )

        if table_exists(conn, "incidents"):
            rows = query_rows(
                conn,
                """
                SELECT id, title, summary, severity, status, urgency, category,
                       affected_ips, affected_hosts, alert_count,
                       correlation_id, cluster_ids, created_at, updated_at,
                       resolved_at
                FROM incidents
                ORDER BY created_at DESC
                """,
                limit=200,
            )
            yield Document(
                "incident_history",
                "recent incidents",
                str(db_path),
                json_block("Recent incident records", rows),
            )

        if table_exists(conn, "correlations"):
            rows = query_rows(
                conn,
                """
                SELECT id, alert_ids, pattern, summary, severity, created_at
                FROM correlations
                ORDER BY created_at DESC
                """,
                limit=200,
            )
            yield Document(
                "incident_history",
                "alert correlations",
                str(db_path),
                json_block("Recent alert correlations", rows),
            )

        if table_exists(conn, "escalations"):
            rows = query_rows(
                conn,
                """
                SELECT created_at, updated_at, tier, state, severity, title,
                       brief, signals, alert_count, confidence, chain,
                       resolution
                FROM escalations
                ORDER BY updated_at DESC
                """,
                limit=200,
            )
            yield Document(
                "escalation_history",
                "escalation ladder cases",
                str(db_path),
                json_block("Recent escalation ladder cases", rows),
            )

        if table_exists(conn, "scout_cards"):
            rows = query_rows(
                conn,
                """
                SELECT created_at, model, score, reasons, extracted_json,
                       context_facts, scout_note, status
                FROM scout_cards
                ORDER BY created_at DESC
                """,
                limit=200,
            )
            yield Document(
                "scout_history",
                "edge scout cards",
                str(db_path),
                json_block("Recent non-judgmental edge scout cards", rows),
            )

        if table_exists(conn, "sigma_rules"):
            rows = query_rows(
                conn,
                """
                SELECT title, level, category, description, tags, filename,
                       enabled, hit_count, last_hit
                FROM sigma_rules
                ORDER BY enabled DESC, hit_count DESC, title
                """,
                limit=500,
            )
            yield Document(
                "detection_policy",
                "sigma detection rules",
                str(db_path),
                json_block("Loaded Sigma-style detection rules", rows),
            )

        if table_exists(conn, "ioc_indicators"):
            rows = query_rows(
                conn,
                """
                SELECT feed_name, indicator_type, COUNT(*) AS count,
                       MIN(added_at) AS first_added, MAX(added_at) AS last_added,
                       MIN(expires_at) AS earliest_expiry
                FROM ioc_indicators
                GROUP BY feed_name, indicator_type
                ORDER BY count DESC
                """,
                limit=200,
            )
            yield Document(
                "threat_intel",
                "ioc feed inventory",
                str(db_path),
                json_block("IoC feed counts by feed and type", rows),
            )

        if table_exists(conn, "edge_trials"):
            rows = query_rows(
                conn,
                """
                SELECT created_at, host, category, grounded_verdict,
                       grounded_conf, grounded_ms, plain_verdict, plain_conf,
                       plain_ms, ref_verdict, ref_model, operator_verdict,
                       retrieved_k, top_sim, memory_size
                FROM edge_trials
                ORDER BY created_at DESC
                """,
                limit=200,
            )
            yield Document(
                "evaluation_history",
                "edge ai trial results",
                str(db_path),
                json_block("Edge AI grounded/plain trial results", rows),
            )

        if table_exists(conn, "custom_rules"):
            rows = query_rows(
                conn,
                """
                SELECT name, enabled, match_field, match_op, match_value,
                       match_field2, match_op2, match_value2, action,
                       severity_override, hit_count, last_hit, description
                FROM custom_rules
                ORDER BY enabled DESC, hit_count DESC, name
                """,
            )
            yield Document(
                "detection_policy",
                "custom escalation rules",
                str(db_path),
                json_block("Configured custom rules", rows),
            )

        if table_exists(conn, "knowledge"):
            rows = query_rows(
                conn,
                """
                SELECT category, topic, source, content
                FROM knowledge
                ORDER BY category, topic
                """,
                limit=1000,
            )
            for row in rows:
                yield Document(
                    "security_knowledge",
                    f"{row.get('category', '')}: {row.get('topic', '')}",
                    str(db_path),
                    json_block("Knowledge entry", row),
                )
    finally:
        conn.close()


def build_corpus(repo: Path, db_path: Path, out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    docs = [*collect_static_docs(repo), *collect_db_docs(db_path)]

    conn = sqlite3.connect(out_path)
    try:
        conn.executescript(SCHEMA)
        conn.execute("DELETE FROM documents")
        collected_at = utc_now()
        conn.executemany(
            """
            INSERT INTO documents(id, category, title, source, content, collected_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (doc.id, doc.category, doc.title, doc.source, doc.content, collected_at)
                for doc in docs
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return len(docs)


def search_corpus(out_path: Path, query: str, limit: int) -> list[dict[str, object]]:
    fts_query = " ".join(
        f'"{token.replace(chr(34), chr(34) + chr(34))}"'
        for token in re.findall(r"[A-Za-z0-9_.:-]+", query)
    )
    if not fts_query:
        return []
    conn = sqlite3.connect(out_path)
    conn.row_factory = sqlite3.Row
    try:
        sql = """
        SELECT d.category, d.title, d.source,
               snippet(documents_fts, 1, '[', ']', ' ... ', 24) AS snippet
        FROM documents_fts
        JOIN documents d ON d.rowid = documents_fts.rowid
        WHERE documents_fts MATCH ?
        ORDER BY bm25(documents_fts)
        LIMIT ?
        """
        return [dict(row) for row in conn.execute(sql, (fts_query, limit))]
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build", help="rebuild the corpus")
    search = sub.add_parser("search", help="search the corpus")
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=8)
    args = parser.parse_args()

    if args.cmd == "build":
        count = build_corpus(args.repo, args.db, args.out)
        print(f"built {count} documents at {args.out}")
        return 0

    if args.cmd == "search":
        for row in search_corpus(args.out, args.query, args.limit):
            print(json.dumps(row, sort_keys=True))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
