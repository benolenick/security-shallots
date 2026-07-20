"""SQLite FTS5 storage backend."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import aiosqlite

from shallots.store.models import Alert, TriageResult, Correlation, QueryLog, now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    source_ref TEXT,
    severity TEXT DEFAULT 'medium',
    title TEXT,
    description TEXT,
    src_ip TEXT,
    src_port INTEGER DEFAULT 0,
    dst_ip TEXT,
    dst_port INTEGER DEFAULT 0,
    proto TEXT,
    category TEXT,
    signature_id INTEGER DEFAULT 0,
    raw TEXT,
    src_geo TEXT,
    dst_geo TEXT,
    src_dns TEXT,
    dst_dns TEXT,
    src_asset TEXT,
    dst_asset TEXT,
    verdict TEXT DEFAULT 'pending',
    confidence REAL DEFAULT 0.0,
    ai_reasoning TEXT,
    ingested_at TEXT,
    dedup_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip ON alerts(dst_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_verdict ON alerts(verdict);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(dedup_hash);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);
CREATE INDEX IF NOT EXISTS idx_alerts_ingested ON alerts(ingested_at);

-- FTS5 virtual table for full-text search over alerts
CREATE VIRTUAL TABLE IF NOT EXISTS alerts_fts USING fts5(
    id UNINDEXED,
    title,
    description,
    category,
    src_ip UNINDEXED,
    dst_ip UNINDEXED,
    content=alerts,
    content_rowid=rowid
);

-- Triggers to keep FTS in sync
CREATE TRIGGER IF NOT EXISTS alerts_ai AFTER INSERT ON alerts BEGIN
    INSERT INTO alerts_fts(rowid, id, title, description, category, src_ip, dst_ip)
    VALUES (new.rowid, new.id, new.title, new.description, new.category, new.src_ip, new.dst_ip);
END;

CREATE TRIGGER IF NOT EXISTS alerts_ad AFTER DELETE ON alerts BEGIN
    INSERT INTO alerts_fts(alerts_fts, rowid, id, title, description, category, src_ip, dst_ip)
    VALUES ('delete', old.rowid, old.id, old.title, old.description, old.category, old.src_ip, old.dst_ip);
END;

CREATE TRIGGER IF NOT EXISTS alerts_au AFTER UPDATE ON alerts BEGIN
    INSERT INTO alerts_fts(alerts_fts, rowid, id, title, description, category, src_ip, dst_ip)
    VALUES ('delete', old.rowid, old.id, old.title, old.description, old.category, old.src_ip, old.dst_ip);
    INSERT INTO alerts_fts(rowid, id, title, description, category, src_ip, dst_ip)
    VALUES (new.rowid, new.id, new.title, new.description, new.category, new.src_ip, new.dst_ip);
END;

CREATE TABLE IF NOT EXISTS triage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL REFERENCES alerts(id),
    verdict TEXT NOT NULL,
    confidence REAL DEFAULT 0.0,
    reasoning TEXT,
    iocs TEXT,           -- JSON array
    suggested_action TEXT,
    model TEXT,
    latency_ms INTEGER DEFAULT 0,
    created_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_triage_alert ON triage(alert_id);

CREATE TABLE IF NOT EXISTS correlations (
    id TEXT PRIMARY KEY,
    alert_ids TEXT,       -- JSON array of alert IDs
    pattern TEXT,
    summary TEXT,
    severity TEXT DEFAULT 'medium',
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS queries (
    id TEXT PRIMARY KEY,
    question TEXT,
    generated_sql TEXT,
    result_summary TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip TEXT PRIMARY KEY,
    vt_malicious INTEGER DEFAULT 0,
    vt_suspicious INTEGER DEFAULT 0,
    vt_total INTEGER DEFAULT 0,
    abuse_score INTEGER DEFAULT 0,
    country TEXT DEFAULT '',
    isp TEXT DEFAULT '',
    verdict TEXT DEFAULT '',
    details TEXT DEFAULT '',
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_alert ON alert_notes(alert_id);

CREATE TABLE IF NOT EXISTS saved_searches (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    query TEXT NOT NULL,
    search_type TEXT DEFAULT 'fts',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS silence_rules (
    id TEXT PRIMARY KEY,
    match_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    pattern2 TEXT DEFAULT '',
    reason TEXT DEFAULT '',
    hit_count INTEGER DEFAULT 0,
    last_hit TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_silence_pattern ON silence_rules(pattern);

CREATE TABLE IF NOT EXISTS custom_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    match_field TEXT NOT NULL,
    match_op TEXT DEFAULT 'contains',
    match_value TEXT NOT NULL,
    match_field2 TEXT DEFAULT '',
    match_op2 TEXT DEFAULT '',
    match_value2 TEXT DEFAULT '',
    action TEXT DEFAULT 'escalate',
    action_param TEXT DEFAULT '',
    severity_override TEXT DEFAULT '',
    description TEXT DEFAULT '',
    hit_count INTEGER DEFAULT 0,
    last_hit TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_custom_rules_enabled ON custom_rules(enabled);

CREATE TABLE IF NOT EXISTS agent_status (
    agent_name TEXT PRIMARY KEY,
    agent_type TEXT DEFAULT 'unknown',
    os TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    version TEXT DEFAULT '',
    status TEXT DEFAULT 'offline',
    last_heartbeat TEXT,
    last_alert TEXT,
    alert_count INTEGER DEFAULT 0,
    health_data TEXT DEFAULT '{}',
    registered_at TEXT,
    updated_at TEXT
);

-- Knowledge base for RAG context
CREATE TABLE IF NOT EXISTS knowledge (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    topic TEXT NOT NULL,
    content TEXT NOT NULL,
    source TEXT DEFAULT ''
);

CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
    topic, content, category,
    content=knowledge, content_rowid=rowid
);

CREATE TRIGGER IF NOT EXISTS knowledge_ai AFTER INSERT ON knowledge BEGIN
    INSERT INTO knowledge_fts(rowid, topic, content, category)
    VALUES (new.rowid, new.topic, new.content, new.category);
END;

CREATE TRIGGER IF NOT EXISTS knowledge_ad AFTER DELETE ON knowledge BEGIN
    INSERT INTO knowledge_fts(knowledge_fts, rowid, topic, content, category)
    VALUES ('delete', old.rowid, old.topic, old.content, old.category);
END;

-- Per-alert AI chat history
CREATE TABLE IF NOT EXISTS alert_chat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    action TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_alert ON alert_chat(alert_id);

-- Investigations (JTTW deep analysis)
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    since_window TEXT DEFAULT '24h',
    alert_count INTEGER DEFAULT 0,
    report_json TEXT DEFAULT '{}',
    verdicts_applied INTEGER DEFAULT 0,
    model TEXT DEFAULT '',
    latency_ms INTEGER DEFAULT 0
);

-- Stats/meta
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- AI autopilot decisions log
CREATE TABLE IF NOT EXISTS ai_decisions (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    mode TEXT NOT NULL,
    action TEXT NOT NULL,
    summary TEXT NOT NULL,
    detail TEXT DEFAULT '',
    alert_ids TEXT DEFAULT '',
    status TEXT DEFAULT 'done',
    resolved_by TEXT DEFAULT '',
    resolved_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ai_decisions_ts ON ai_decisions(ts);
CREATE INDEX IF NOT EXISTS idx_ai_decisions_status ON ai_decisions(status);

-- Non-judgmental edge scout cards. These surface candidate missed signals
-- without changing alert verdicts or creating suppress/escalate decisions.
CREATE TABLE IF NOT EXISTS scout_cards (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    model TEXT DEFAULT '',
    score INTEGER DEFAULT 0,
    reasons TEXT DEFAULT '[]',
    extracted_json TEXT DEFAULT '{}',
    context_facts TEXT DEFAULT '[]',
    scout_note TEXT DEFAULT '',
    status TEXT DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS idx_scout_cards_created ON scout_cards(created_at);
CREATE INDEX IF NOT EXISTS idx_scout_cards_status ON scout_cards(status);
CREATE INDEX IF NOT EXISTS idx_scout_cards_score ON scout_cards(score);

-- Elder/upstream reviewer feedback for tuning the edge scout. This records
-- labels and suggestions; it does not auto-apply policy changes.
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

-- Threat squawks (active critical alerts)
CREATE TABLE IF NOT EXISTS squawks (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT DEFAULT '',
    alert_ids TEXT DEFAULT '',
    dismissed INTEGER DEFAULT 0,
    dismissed_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_squawks_dismissed ON squawks(dismissed);

-- AI-learned verdict patterns
CREATE TABLE IF NOT EXISTS ai_verdicts (
    id TEXT PRIMARY KEY,
    pattern_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    sample_count INTEGER DEFAULT 1,
    last_seen TEXT NOT NULL,
    auto_rule_id TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ai_verdicts_pattern ON ai_verdicts(pattern_type, pattern);

-- Shift reports
CREATE TABLE IF NOT EXISTS shift_reports (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    summary TEXT NOT NULL,
    stats TEXT DEFAULT '',
    threats TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_shift_reports_ts ON shift_reports(ts);

-- Alert clusters (hard grouping by src_ip + title)
CREATE TABLE IF NOT EXISTS clusters (
    id TEXT PRIMARY KEY,
    cluster_key TEXT NOT NULL UNIQUE,
    src_ip TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    severity TEXT DEFAULT 'medium',
    verdict TEXT DEFAULT 'pending',
    alert_count INTEGER DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_clusters_key ON clusters(cluster_key);
CREATE INDEX IF NOT EXISTS idx_clusters_verdict ON clusters(verdict);
CREATE INDEX IF NOT EXISTS idx_clusters_last_seen ON clusters(last_seen);
CREATE INDEX IF NOT EXISTS idx_clusters_alert_count ON clusters(alert_count);
-- get_dashboard_stats() does GROUP BY src_ip, verdict on every /api/stats poll.
CREATE INDEX IF NOT EXISTS idx_clusters_src_verdict ON clusters(src_ip, verdict);

-- Incidents: actionable items for human operators
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    severity TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'new',
    urgency TEXT DEFAULT 'check',
    category TEXT DEFAULT '',
    affected_ips TEXT DEFAULT '[]',
    affected_hosts TEXT DEFAULT '[]',
    alert_count INTEGER DEFAULT 0,
    correlation_id TEXT,
    cluster_ids TEXT DEFAULT '[]',
    alert_ids TEXT DEFAULT '[]',
    runbook TEXT DEFAULT '[]',
    ai_analysis TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);

-- Learning: track user decisions on incidents for pattern learning
CREATE TABLE IF NOT EXISTS incident_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    pattern_key TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_decisions_pattern ON incident_decisions(pattern_key);
CREATE INDEX IF NOT EXISTS idx_incident_decisions_category ON incident_decisions(category);

-- Incident notes (analyst journal entries)
CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    note TEXT NOT NULL,
    author TEXT DEFAULT 'analyst',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_notes_incident ON incident_notes(incident_id);

-- Incident timeline events (auto-tracked lifecycle events)
CREATE TABLE IF NOT EXISTS incident_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    detail TEXT DEFAULT '',
    actor TEXT DEFAULT 'system',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id);

-- Audit log (tracks all user and system actions)
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT DEFAULT '',
    target_id TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    actor TEXT DEFAULT 'user',
    ip TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

-- Asset inventory (known network devices)
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    mac TEXT DEFAULT '',
    hostname TEXT DEFAULT '',
    os TEXT DEFAULT '',
    asset_type TEXT DEFAULT 'unknown',
    criticality TEXT DEFAULT 'medium',
    network_segment TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    alert_count INTEGER DEFAULT 0,
    notes TEXT DEFAULT '',
    source TEXT DEFAULT 'auto'
);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_assets_mac ON assets(mac);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);

-- Known devices (MAC address tracking for new device detection)
CREATE TABLE IF NOT EXISTS known_devices (
    mac TEXT PRIMARY KEY,
    ip TEXT DEFAULT '',
    hostname TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    alert_generated INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_known_devices_ip ON known_devices(ip);

-- TLS certificate monitoring
CREATE TABLE IF NOT EXISTS tls_certs (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    port INTEGER DEFAULT 443,
    subject TEXT,
    issuer TEXT,
    not_before TEXT,
    not_after TEXT,
    serial TEXT,
    days_remaining INTEGER,
    status TEXT DEFAULT 'ok',
    last_checked TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tls_certs_host_port ON tls_certs(host, port);

-- DHCP lease history (IP-to-MAC-to-hostname over time)
CREATE TABLE IF NOT EXISTS dhcp_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    hostname TEXT DEFAULT '',
    interface TEXT DEFAULT '',
    lease_type TEXT DEFAULT 'dynamic',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dhcp_ip ON dhcp_history(ip);
CREATE INDEX IF NOT EXISTS idx_dhcp_mac ON dhcp_history(mac);
CREATE INDEX IF NOT EXISTS idx_dhcp_last_seen ON dhcp_history(last_seen);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dhcp_ip_mac ON dhcp_history(ip, mac);

-- Scheduled report config
CREATE TABLE IF NOT EXISTS scheduled_reports (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    schedule TEXT NOT NULL DEFAULT 'daily',
    last_sent TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sigma_rules (
    id TEXT PRIMARY KEY,
    title TEXT,
    level TEXT,
    category TEXT,
    description TEXT,
    tags TEXT DEFAULT '[]',
    filename TEXT,
    enabled INTEGER DEFAULT 1,
    hit_count INTEGER DEFAULT 0,
    last_hit TEXT,
    loaded_at TEXT
);

-- IoC (Indicator of Compromise) feed indicators
CREATE TABLE IF NOT EXISTS ioc_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_name TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    value TEXT NOT NULL,
    context TEXT DEFAULT '',
    added_at TEXT NOT NULL,
    expires_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_feed_value ON ioc_indicators(feed_name, value);
CREATE INDEX IF NOT EXISTS idx_ioc_type_value ON ioc_indicators(indicator_type, value);

-- Clove lite agent alerts
CREATE TABLE IF NOT EXISTS clove_alerts (
    id TEXT PRIMARY KEY,
    agent_name TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    details TEXT DEFAULT '{}',
    source_ip TEXT,
    timestamp TEXT NOT NULL,
    resolved INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_clove_alerts_agent ON clove_alerts(agent_name);
CREATE INDEX IF NOT EXISTS idx_clove_alerts_ts ON clove_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_clove_alerts_resolved ON clove_alerts(resolved);

-- Clove agent heartbeats
CREATE TABLE IF NOT EXISTS agent_heartbeats (
    agent_name TEXT PRIMARY KEY,
    agent_type TEXT NOT NULL,
    os TEXT,
    ip TEXT,
    version TEXT,
    last_seen TEXT NOT NULL,
    health TEXT DEFAULT '{}',
    baselines TEXT DEFAULT '{}',
    update_requested INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Device behavioral baselines (threat engine)
CREATE TABLE IF NOT EXISTS device_baselines (
    ip TEXT PRIMARY KEY,
    asset_name TEXT,
    first_seen TEXT,
    last_seen TEXT,
    profile_json TEXT,
    baseline_updated TEXT,
    created_at TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_baselines_updated ON device_baselines(baseline_updated);

-- Network graph edges (threat engine)
CREATE TABLE IF NOT EXISTS graph_edges (
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    weight INTEGER DEFAULT 1,
    first_seen TEXT,
    last_seen TEXT,
    sample_alert_id TEXT,
    PRIMARY KEY (src, dst, edge_type)
);
CREATE INDEX IF NOT EXISTS idx_graph_src ON graph_edges(src);
CREATE INDEX IF NOT EXISTS idx_graph_dst ON graph_edges(dst);

-- ML anomaly predictions (threat engine)
CREATE TABLE IF NOT EXISTS ml_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT,
    model TEXT NOT NULL,
    is_anomaly INTEGER DEFAULT 0,
    anomaly_score REAL,
    explanation TEXT,
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_ml_alert ON ml_predictions(alert_id);
CREATE INDEX IF NOT EXISTS idx_ml_model ON ml_predictions(model);

-- ML model artifacts (threat engine)
CREATE TABLE IF NOT EXISTS ml_models (
    name TEXT PRIMARY KEY,
    version INTEGER DEFAULT 1,
    model_blob BLOB,
    metadata_json TEXT,
    trained_at TEXT,
    alert_count INTEGER
);
"""

# Column migration for existing databases
_MIGRATIONS = [
    "ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT DEFAULT NULL",
    "ALTER TABLE silence_rules ADD COLUMN pattern2 TEXT DEFAULT ''",
    "ALTER TABLE silence_rules ADD COLUMN hit_count INTEGER DEFAULT 0",
    "ALTER TABLE silence_rules ADD COLUMN last_hit TEXT DEFAULT ''",
    "ALTER TABLE alerts ADD COLUMN cluster_id TEXT DEFAULT NULL",
    "ALTER TABLE incidents ADD COLUMN urgency TEXT DEFAULT 'check'",
]


SQLITE_TIMEOUT_SECONDS = 30.0
SQLITE_BUSY_TIMEOUT_MS = int(SQLITE_TIMEOUT_SECONDS * 1000)


class AlertDB:
    """Async SQLite database for alert storage with FTS5."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        """Open database and create schema."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(
            self.db_path,
            timeout=SQLITE_TIMEOUT_SECONDS,
        )
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA cache_size=-64000")  # 64MB cache
        await self._db.executescript(SCHEMA)
        # Run column migrations (safe to re-run — ignores "duplicate column" errors)
        for migration in _MIGRATIONS:
            try:
                await self._db.execute(migration)
            except Exception:
                pass  # column already exists
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    # ── Alerts ──────────────────────────────────────────────

    async def insert_alert(self, alert: Alert) -> str:
        """Insert an alert, returns its ID."""
        if not alert.id:
            alert.id = str(uuid.uuid4())
        if not alert.ingested_at:
            alert.ingested_at = now_iso()
        if not alert.dedup_hash:
            alert.compute_dedup_hash()

        await self._db.execute(
            """INSERT OR IGNORE INTO alerts
            (id, timestamp, source, source_ref, severity, title, description,
             src_ip, src_port, dst_ip, dst_port, proto, category, signature_id,
             raw, src_geo, dst_geo, src_dns, dst_dns, src_asset, dst_asset,
             verdict, confidence, ai_reasoning, ingested_at, dedup_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.id, alert.timestamp, alert.source, alert.source_ref,
                alert.severity, alert.title, alert.description,
                alert.src_ip, alert.src_port, alert.dst_ip, alert.dst_port,
                alert.proto, alert.category, alert.signature_id,
                alert.raw, alert.src_geo, alert.dst_geo, alert.src_dns, alert.dst_dns,
                alert.src_asset, alert.dst_asset,
                alert.verdict, alert.confidence, alert.ai_reasoning,
                alert.ingested_at, alert.dedup_hash,
            ),
        )
        await self._db.commit()
        return alert.id

    async def check_dedup(self, dedup_hash: str, window_minutes: int = 10) -> bool:
        """Check if a dedup hash exists within the window. Returns True if duplicate."""
        cursor = await self._db.execute(
            """SELECT 1 FROM alerts WHERE dedup_hash = ?
            AND ingested_at > datetime('now', ?)""",
            (dedup_hash, f"-{window_minutes} minutes"),
        )
        row = await cursor.fetchone()
        return row is not None

    async def update_verdict(self, alert_id: str, verdict: str, confidence: float,
                             reasoning: str) -> None:
        """Update alert verdict after AI triage."""
        await self._db.execute(
            "UPDATE alerts SET verdict = ?, confidence = ?, ai_reasoning = ? WHERE id = ?",
            (verdict, confidence, reasoning, alert_id),
        )
        await self._db.commit()

    async def get_alert(self, alert_id: str) -> dict | None:
        cursor = await self._db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_alerts_by_ids(self, alert_ids: list[str]) -> list[dict]:
        """Fetch multiple alerts by their IDs. Returns them in the order given."""
        if not alert_ids:
            return []
        results = []
        for i in range(0, len(alert_ids), 100):
            batch = alert_ids[i:i + 100]
            placeholders = ",".join("?" for _ in batch)
            cursor = await self._db.execute(
                f"SELECT * FROM alerts WHERE id IN ({placeholders})", batch
            )
            results.extend(dict(r) for r in await cursor.fetchall())
        # Preserve requested order
        by_id = {r["id"]: r for r in results}
        return [by_id[aid] for aid in alert_ids if aid in by_id]

    async def get_alerts(self, limit: int = 50, offset: int = 0, source: str = None,
                         severity: str = None, verdict: str = None,
                         since: str = None, src_ip: str = None,
                         title: str = None) -> list[dict]:
        """Get alerts with optional filters.

        Args:
            since: Time filter — either an ISO timestamp or a relative
                   duration like "1h", "24h", "7d", "30d".
            src_ip: Filter by source IP address.
            title: Filter by exact alert title.
        """
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list = []
        if source:
            query += " AND source = ?"
            params.append(source)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if verdict:
            if verdict.startswith("!"):
                query += " AND verdict != ?"
                params.append(verdict[1:])
            else:
                query += " AND verdict = ?"
                params.append(verdict)
        if since:
            sqlite_interval = self._parse_since(since)
            if sqlite_interval:
                query += " AND timestamp > datetime('now', ?)"
                params.append(sqlite_interval)
        if src_ip:
            query += " AND src_ip = ?"
            params.append(src_ip)
        if title:
            query += " AND title = ?"
            params.append(title)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor = await self._db.execute(query, params)
        return [dict(row) for row in await cursor.fetchall()]

    @staticmethod
    def _parse_since(since: str) -> str | None:
        """Convert a relative duration to a SQLite datetime modifier.

        Accepts: "1h", "24h", "7d", "30d" or an ISO timestamp (passed through).
        Returns a string like "-24 hours" or "-7 days".
        """
        import re
        m = re.match(r"^(\d+)\s*(h|d)$", since.strip().lower())
        if m:
            n, unit = int(m.group(1)), m.group(2)
            if unit == "h":
                return f"-{n} hours"
            elif unit == "d":
                return f"-{n} days"
        return None

    async def get_pending_alerts(self, limit: int = 20) -> list[dict]:
        """Get alerts awaiting AI triage."""
        cursor = await self._db.execute(
            "SELECT * FROM alerts WHERE verdict = 'pending' ORDER BY timestamp ASC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_unscouted_alerts(
        self,
        limit: int = 20,
        lookback_hours: int = 24,
    ) -> list[dict]:
        """Get recent alerts that do not yet have a scout card."""
        cursor = await self._db.execute(
            """
            SELECT alerts.* FROM alerts
            LEFT JOIN scout_cards ON scout_cards.alert_id = alerts.id
            WHERE scout_cards.alert_id IS NULL
              AND COALESCE(alerts.ingested_at, alerts.timestamp) > datetime('now', ?)
            ORDER BY COALESCE(alerts.ingested_at, alerts.timestamp) DESC
            LIMIT ?
            """,
            (f"-{lookback_hours} hours", limit),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def count_alerts_matching(
        self,
        *,
        source: str = "",
        signature_id: int = 0,
        title: str = "",
        src_ip: str = "",
        dst_ip: str = "",
        dst_port: int = 0,
        proto: str = "",
        lookback_hours: int = 24 * 30,
    ) -> int:
        """Count historical alerts matching a signature/title or flow tuple."""
        query = (
            "SELECT COUNT(*) FROM alerts WHERE "
            "COALESCE(ingested_at, timestamp) > datetime('now', ?)"
        )
        params: list = [f"-{lookback_hours} hours"]
        for field, value in (
            ("source", source),
            ("signature_id", signature_id),
            ("title", title),
            ("src_ip", src_ip),
            ("dst_ip", dst_ip),
            ("dst_port", dst_port),
            ("proto", proto),
        ):
            if value not in ("", 0, None):
                query += f" AND {field} = ?"
                params.append(value)
        cursor = await self._db.execute(query, params)
        row = await cursor.fetchone()
        return int(row[0]) if row else 0

    async def insert_scout_card(
        self,
        *,
        alert_id: str,
        model: str,
        score: int,
        reasons: list[str],
        extracted: dict,
        context_facts: list[str] | dict | str,
        scout_note: str,
        status: str = "new",
    ) -> str:
        """Insert a non-judgmental scout card for an alert."""
        card_id = str(uuid.uuid4())
        await self._db.execute(
            """
            INSERT OR IGNORE INTO scout_cards
            (id, alert_id, created_at, model, score, reasons, extracted_json,
             context_facts, scout_note, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                card_id,
                alert_id,
                now_iso(),
                model,
                score,
                json.dumps(reasons),
                json.dumps(extracted),
                json.dumps(context_facts),
                scout_note,
                status,
            ),
        )
        await self._db.commit()
        return card_id

    async def get_scout_cards(
        self,
        limit: int = 50,
        status: str | None = None,
    ) -> list[dict]:
        """Fetch recent scout cards."""
        query = "SELECT * FROM scout_cards"
        params: list = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        cursor = await self._db.execute(query, params)
        return [dict(row) for row in await cursor.fetchall()]

    async def add_scout_feedback(
        self,
        *,
        target_type: str,
        target_id: str,
        alert_id: str = "",
        reviewer_model: str = "",
        label: str,
        confidence: float = 0.0,
        rationale: str = "",
        suggested_action: str = "",
        suggested_policy: str = "",
        raw_review: dict | str = "",
    ) -> str:
        feedback_id = str(uuid.uuid4())
        if not isinstance(raw_review, str):
            raw_review = json.dumps(raw_review)
        await self._db.execute(
            """
            INSERT INTO scout_feedback
            (id, target_type, target_id, alert_id, created_at, reviewer_model,
             label, confidence, rationale, suggested_action, suggested_policy,
             raw_review)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                feedback_id,
                target_type,
                target_id,
                alert_id,
                now_iso(),
                reviewer_model,
                label,
                confidence,
                rationale,
                suggested_action,
                suggested_policy,
                raw_review,
            ),
        )
        await self._db.commit()
        return feedback_id

    async def add_scout_policy_proposal(
        self,
        *,
        title: str,
        source_feedback_ids: list[str] | str = "",
        proposal_type: str = "policy",
        detail: str = "",
        patch_hint: str = "",
        expected_effect: str = "",
        risk: str = "",
        reviewer_model: str = "",
        status: str = "proposed",
    ) -> str:
        proposal_id = str(uuid.uuid4())
        if isinstance(source_feedback_ids, list):
            source_feedback_ids = json.dumps(source_feedback_ids)
        await self._db.execute(
            """
            INSERT INTO scout_policy_proposals
            (id, created_at, source_feedback_ids, status, title, proposal_type,
             detail, patch_hint, expected_effect, risk, reviewer_model)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                proposal_id,
                now_iso(),
                source_feedback_ids,
                status,
                title,
                proposal_type,
                detail,
                patch_hint,
                expected_effect,
                risk,
                reviewer_model,
            ),
        )
        await self._db.commit()
        return proposal_id

    async def search_alerts(self, query: str, limit: int = 50) -> list[dict]:
        """Full-text search across alerts."""
        cursor = await self._db.execute(
            """SELECT alerts.* FROM alerts_fts
            JOIN alerts ON alerts_fts.id = alerts.id
            WHERE alerts_fts MATCH ?
            ORDER BY rank LIMIT ?""",
            (query, limit),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def execute_sql(self, sql: str, params: tuple = (),
                          max_rows: int = 200,
                          timeout_sec: float = SQLITE_TIMEOUT_SECONDS,
                          commit: bool = False) -> list[dict]:
        """Execute SQL. By default read-only (SELECT). Set commit=True for writes.

        For SELECT: enforces row limit and query timeout.
        For writes (commit=True): allows INSERT/UPDATE/DELETE from internal modules.
        """
        stripped = sql.strip().upper()
        is_select = stripped.startswith("SELECT")

        if not is_select and not commit:
            raise ValueError("Only SELECT queries are allowed (use commit=True for writes)")

        import asyncio
        try:
            cursor = await asyncio.wait_for(
                self._db.execute(sql, params),
                timeout=timeout_sec,
            )
            if is_select:
                rows = await cursor.fetchmany(max_rows)
                return [dict(row) for row in rows]
            else:
                if commit:
                    await self._db.commit()
                return []
        except asyncio.TimeoutError:
            raise ValueError(f"Query timed out after {timeout_sec}s")

    # ── Bulk operations ────────────────────────────────────

    async def bulk_update_verdict(self, alert_ids: list[str], verdict: str,
                                   confidence: float = 1.0,
                                   reasoning: str = "Bulk verdict via dashboard") -> int:
        """Update verdict for multiple alerts. Chunks in batches of 100.

        Returns count of rows updated.
        """
        updated = 0
        for i in range(0, len(alert_ids), 100):
            batch = alert_ids[i:i + 100]
            placeholders = ",".join("?" for _ in batch)
            cursor = await self._db.execute(
                f"UPDATE alerts SET verdict = ?, confidence = ?, ai_reasoning = ? "
                f"WHERE id IN ({placeholders})",
                [verdict, confidence, reasoning] + batch,
            )
            updated += cursor.rowcount
        await self._db.commit()
        return updated

    async def suppress_filtered(self, source: str = None, severity: str = None,
                                 verdict: str = None, since: str = None) -> int:
        """Suppress all alerts matching the given filters (no LIMIT).

        Returns count of rows updated.
        """
        query = "UPDATE alerts SET verdict = 'suppress', confidence = 1.0, " \
                "ai_reasoning = 'Bulk suppress via dashboard filters' WHERE 1=1"
        params: list = []
        if source:
            query += " AND source = ?"
            params.append(source)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if verdict:
            query += " AND verdict = ?"
            params.append(verdict)
        if since:
            sqlite_interval = self._parse_since(since)
            if sqlite_interval:
                query += " AND timestamp > datetime('now', ?)"
                params.append(sqlite_interval)
        cursor = await self._db.execute(query, params)
        await self._db.commit()
        return cursor.rowcount

    # ── Triage ──────────────────────────────────────────────

    async def insert_triage(self, result: TriageResult) -> None:
        d = result.to_dict()
        await self._db.execute(
            """INSERT INTO triage (alert_id, verdict, confidence, reasoning, iocs,
            suggested_action, model, latency_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (d["alert_id"], d["verdict"], d["confidence"], d["reasoning"],
             d["iocs"], d["suggested_action"], d["model"], d["latency_ms"],
             d["created_at"] or now_iso()),
        )
        await self._db.commit()

    async def get_triage(self, alert_id: str) -> dict | None:
        """Get the most recent triage result for an alert."""
        cursor = await self._db.execute(
            "SELECT * FROM triage WHERE alert_id = ? ORDER BY created_at DESC LIMIT 1",
            (alert_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_ip_alert_summary(self, ip: str) -> dict:
        """Get alert counts and top titles for an IP (as src or dst)."""
        # Total count (all time)
        c1 = await self._db.execute(
            "SELECT COUNT(*) FROM alerts WHERE src_ip = ? OR dst_ip = ?", (ip, ip)
        )
        total = (await c1.fetchone())[0]
        # Count in last 24h
        since = (datetime.utcnow() - timedelta(hours=24)).isoformat() + "Z"
        c2 = await self._db.execute(
            "SELECT COUNT(*) FROM alerts WHERE (src_ip = ? OR dst_ip = ?) AND timestamp >= ?",
            (ip, ip, since)
        )
        last_24h = (await c2.fetchone())[0]
        # Top 5 alert titles from this IP
        c3 = await self._db.execute(
            """SELECT title, COUNT(*) as cnt FROM alerts
               WHERE src_ip = ? OR dst_ip = ?
               GROUP BY title ORDER BY cnt DESC LIMIT 5""",
            (ip, ip)
        )
        top_titles = [{"title": r["title"], "count": r["cnt"]} for r in await c3.fetchall()]
        return {"ip": ip, "total": total, "last_24h": last_24h, "top_titles": top_titles}

    # ── Correlations ────────────────────────────────────────

    async def insert_correlation(self, corr: Correlation) -> str:
        if not corr.id:
            corr.id = str(uuid.uuid4())
        await self._db.execute(
            """INSERT INTO correlations (id, alert_ids, pattern, summary, severity, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (corr.id, json.dumps(corr.alert_ids), corr.pattern, corr.summary,
             corr.severity, corr.created_at or now_iso()),
        )
        await self._db.commit()
        return corr.id

    # ── Queries ─────────────────────────────────────────────

    async def log_query(self, q: QueryLog) -> None:
        if not q.id:
            q.id = str(uuid.uuid4())
        await self._db.execute(
            """INSERT INTO queries (id, question, generated_sql, result_summary, created_at)
            VALUES (?, ?, ?, ?, ?)""",
            (q.id, q.question, q.generated_sql, q.result_summary,
             q.created_at or now_iso()),
        )
        await self._db.commit()

    # ── Retention ─────────────────────────────────────────────

    async def retention_cleanup(self, max_age_days: int = 30) -> int:
        """Delete alerts older than max_age_days. Returns count deleted."""
        cursor = await self._db.execute(
            "DELETE FROM alerts WHERE ingested_at < datetime('now', ?)",
            (f"-{max_age_days} days",),
        )
        deleted = cursor.rowcount
        if deleted:
            # Clean orphaned triage rows
            await self._db.execute(
                "DELETE FROM triage WHERE alert_id NOT IN (SELECT id FROM alerts)"
            )
            await self._db.commit()
        return deleted

    # ── IP Reputation ────────────────────────────────────────

    async def upsert_ip_reputation(self, ip: str, data: dict) -> None:
        """Insert or update IP reputation data."""
        await self._db.execute(
            """INSERT INTO ip_reputation
            (ip, vt_malicious, vt_suspicious, vt_total, abuse_score,
             country, isp, verdict, details, checked_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                vt_malicious=excluded.vt_malicious,
                vt_suspicious=excluded.vt_suspicious,
                vt_total=excluded.vt_total,
                abuse_score=excluded.abuse_score,
                country=excluded.country,
                isp=excluded.isp,
                verdict=excluded.verdict,
                details=excluded.details,
                checked_at=excluded.checked_at,
                expires_at=excluded.expires_at""",
            (
                ip,
                data.get("vt_malicious", 0),
                data.get("vt_suspicious", 0),
                data.get("vt_total", 0),
                data.get("abuse_score", 0),
                data.get("country", ""),
                data.get("isp", ""),
                data.get("verdict", "unknown"),
                data.get("details", ""),
                data.get("checked_at", now_iso()),
                data.get("expires_at", now_iso()),
            ),
        )
        await self._db.commit()

    async def get_ip_reputation(self, ip: str) -> dict | None:
        """Get reputation data for an IP."""
        cursor = await self._db.execute(
            "SELECT * FROM ip_reputation WHERE ip = ?", (ip,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_ips_needing_reputation(self, limit: int = 50) -> list[str]:
        """Get unique public IPs from recent alerts that haven't been checked or are expired."""
        cursor = await self._db.execute(
            """SELECT DISTINCT ip FROM (
                SELECT src_ip AS ip FROM alerts
                WHERE timestamp > datetime('now', '-7 days')
                  AND src_ip != '' AND src_ip IS NOT NULL
                UNION
                SELECT dst_ip AS ip FROM alerts
                WHERE timestamp > datetime('now', '-7 days')
                  AND dst_ip != '' AND dst_ip IS NOT NULL
            )
            WHERE ip NOT IN (
                SELECT ip FROM ip_reputation
                WHERE expires_at > datetime('now')
            )
            LIMIT ?""",
            (limit,),
        )
        return [row[0] for row in await cursor.fetchall()]

    # ── IoC Feed Indicators ────────────────────────────────

    async def upsert_ioc_indicator(
        self, feed_name: str, indicator_type: str, value: str,
        context: str = "", ttl_hours: int = 48,
    ) -> None:
        """Insert or update an IoC indicator with expiry."""
        added = now_iso()
        expires = (
            datetime.utcnow() + timedelta(hours=ttl_hours)
        ).isoformat() + "Z"
        await self._db.execute(
            """INSERT INTO ioc_indicators
            (feed_name, indicator_type, value, context, added_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(feed_name, value) DO UPDATE SET
                indicator_type=excluded.indicator_type,
                context=excluded.context,
                added_at=excluded.added_at,
                expires_at=excluded.expires_at""",
            (feed_name, indicator_type, value, context, added, expires),
        )
        await self._db.commit()

    async def get_ioc_indicators(
        self, indicator_type: str | None = None, limit: int = 500,
    ) -> list[dict]:
        """List IoC indicators, optionally filtered by type."""
        if indicator_type:
            cursor = await self._db.execute(
                """SELECT * FROM ioc_indicators
                WHERE indicator_type = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
                ORDER BY added_at DESC LIMIT ?""",
                (indicator_type, limit),
            )
        else:
            cursor = await self._db.execute(
                """SELECT * FROM ioc_indicators
                WHERE expires_at IS NULL OR expires_at > datetime('now')
                ORDER BY added_at DESC LIMIT ?""",
                (limit,),
            )
        return [dict(row) for row in await cursor.fetchall()]

    async def check_ioc(self, value: str) -> list[dict]:
        """Find matching IoC indicators for a given value (IP, domain, hash)."""
        cursor = await self._db.execute(
            """SELECT * FROM ioc_indicators
            WHERE value = ? AND (expires_at IS NULL OR expires_at > datetime('now'))""",
            (value,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_ioc_feed_stats(self) -> list[dict]:
        """Get indicator count per feed."""
        cursor = await self._db.execute(
            """SELECT feed_name, indicator_type, COUNT(*) as count,
                      MIN(added_at) as oldest, MAX(added_at) as newest
            FROM ioc_indicators
            WHERE expires_at IS NULL OR expires_at > datetime('now')
            GROUP BY feed_name, indicator_type
            ORDER BY count DESC"""
        )
        return [dict(row) for row in await cursor.fetchall()]

    # ── Acknowledge ─────────────────────────────────────────

    async def acknowledge_alert(self, alert_id: str) -> None:
        await self._db.execute(
            "UPDATE alerts SET acknowledged_at = ? WHERE id = ?",
            (now_iso(), alert_id),
        )
        await self._db.commit()

    async def unacknowledge_alert(self, alert_id: str) -> None:
        await self._db.execute(
            "UPDATE alerts SET acknowledged_at = NULL WHERE id = ?",
            (alert_id,),
        )
        await self._db.commit()

    # ── Notes ────────────────────────────────────────────────

    async def add_note(self, alert_id: str, note: str) -> int:
        cursor = await self._db.execute(
            "INSERT INTO alert_notes (alert_id, note, created_at) VALUES (?, ?, ?)",
            (alert_id, note, now_iso()),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_notes(self, alert_id: str) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY created_at ASC",
            (alert_id,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    # ── Saved Searches ───────────────────────────────────────

    async def save_search(self, name: str, query: str,
                          search_type: str = "fts") -> str:
        sid = str(uuid.uuid4())
        await self._db.execute(
            "INSERT INTO saved_searches (id, name, query, search_type, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (sid, name, query, search_type, now_iso()),
        )
        await self._db.commit()
        return sid

    async def get_saved_searches(self) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM saved_searches ORDER BY created_at DESC"
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def delete_saved_search(self, search_id: str) -> bool:
        cursor = await self._db.execute(
            "DELETE FROM saved_searches WHERE id = ?", (search_id,)
        )
        await self._db.commit()
        return cursor.rowcount > 0

    # ── Dashboard Aggregates ─────────────────────────────────

    async def get_top_talkers(self, since: str = "24h",
                              limit: int = 10) -> dict:
        interval = self._parse_since(since) or "-24 hours"
        result = {}
        for label, col in [("src_ips", "src_ip"), ("dst_ips", "dst_ip")]:
            cursor = await self._db.execute(
                f"SELECT {col} as ip, COUNT(*) as cnt, "
                f"MAX(src_dns) as dns, MAX(src_asset) as asset "
                f"FROM alerts WHERE timestamp > datetime('now', ?) "
                f"AND {col} != '' AND {col} IS NOT NULL "
                f"GROUP BY {col} ORDER BY cnt DESC LIMIT ?",
                (interval, limit),
            )
            result[label] = [dict(row) for row in await cursor.fetchall()]
        # Top signatures
        cursor = await self._db.execute(
            "SELECT title, COUNT(*) as cnt, severity "
            "FROM alerts WHERE timestamp > datetime('now', ?) "
            "AND title != '' GROUP BY title ORDER BY cnt DESC LIMIT ?",
            (interval, limit),
        )
        result["signatures"] = [dict(row) for row in await cursor.fetchall()]
        return result

    async def get_timeline(self, since: str = "24h",
                           buckets: int = 24) -> list[dict]:
        interval = self._parse_since(since) or "-24 hours"
        cursor = await self._db.execute(
            "SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as bucket, "
            "COUNT(*) as cnt, "
            "SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical, "
            "SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high "
            "FROM alerts WHERE timestamp > datetime('now', ?) "
            "GROUP BY bucket ORDER BY bucket",
            (interval,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_unique_connections(self, since: str = "24h",
                                      limit: int = 20) -> dict:
        interval = self._parse_since(since) or "-24 hours"
        cursor = await self._db.execute(
            "SELECT src_ip, dst_ip, dst_port, proto, COUNT(*) as cnt, "
            "MAX(src_dns) as src_dns, MAX(dst_dns) as dst_dns "
            "FROM alerts WHERE timestamp > datetime('now', ?) "
            "AND src_ip != '' AND dst_ip != '' "
            "GROUP BY src_ip, dst_ip, dst_port, proto "
            "ORDER BY cnt DESC LIMIT ?",
            (interval, limit),
        )
        connections = [dict(row) for row in await cursor.fetchall()]
        # Total unique count
        cursor2 = await self._db.execute(
            "SELECT COUNT(DISTINCT src_ip || ':' || dst_ip) as total "
            "FROM alerts WHERE timestamp > datetime('now', ?) "
            "AND src_ip != '' AND dst_ip != ''",
            (interval,),
        )
        row = await cursor2.fetchone()
        return {"connections": connections, "total_unique": row[0] if row else 0}

    async def get_network_hosts(self, since: str = "7d") -> list[dict]:
        interval = self._parse_since(since) or "-7 days"
        cursor = await self._db.execute(
            """SELECT ip, dns, asset, geo, COUNT(*) as alert_count,
                      MAX(last_seen) as last_seen,
                      SUM(CASE WHEN severity IN ('critical','high') THEN 1 ELSE 0 END) as high_alerts
            FROM (
                SELECT src_ip as ip, src_dns as dns, src_asset as asset, src_geo as geo,
                       timestamp as last_seen, severity
                FROM alerts WHERE timestamp > datetime('now', ?)
                  AND src_ip != '' AND src_ip IS NOT NULL
                UNION ALL
                SELECT dst_ip, dst_dns, dst_asset, dst_geo, timestamp, severity
                FROM alerts WHERE timestamp > datetime('now', ?)
                  AND dst_ip != '' AND dst_ip IS NOT NULL
            )
            GROUP BY ip
            ORDER BY alert_count DESC""",
            (interval, interval),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_vulnerability_summary(self, since: str = "30d") -> dict:
        interval = self._parse_since(since) or "-30 days"
        # CVEs from Wazuh alerts (description contains "CVE:")
        cursor = await self._db.execute(
            "SELECT description, severity, src_ip, src_asset, timestamp "
            "FROM alerts WHERE source = 'wazuh' "
            "AND description LIKE '%CVE:%' "
            "AND timestamp > datetime('now', ?) "
            "ORDER BY timestamp DESC LIMIT 200",
            (interval,),
        )
        rows = [dict(row) for row in await cursor.fetchall()]

        import re
        cves: dict[str, dict] = {}
        for row in rows:
            m = re.search(r"CVE[- :](\d{4}[- ]\d+)", row["description"])
            if not m:
                continue
            cve_id = "CVE-" + m.group(1).replace(" ", "-")
            if cve_id not in cves:
                cves[cve_id] = {
                    "cve": cve_id, "severity": row["severity"],
                    "hosts": set(), "count": 0,
                    "last_seen": row["timestamp"],
                    "description": row["description"][:120],
                }
            cves[cve_id]["count"] += 1
            if row["src_ip"]:
                cves[cve_id]["hosts"].add(row["src_ip"])

        # Convert sets to lists for JSON
        result = sorted(cves.values(), key=lambda x: x["count"], reverse=True)
        for r in result:
            r["hosts"] = list(r["hosts"])

        return {"vulnerabilities": result, "total_cves": len(result)}

    async def get_vuln_alert_correlation(self, days: int = 30) -> dict:
        """Cross-reference Wazuh CVE alerts with Suricata exploit alerts on same hosts."""
        import re
        interval = f"-{days} days"

        # 1. Wazuh alerts mentioning CVEs
        cursor = await self._db.execute(
            "SELECT id, description, severity, src_ip, dst_ip, timestamp "
            "FROM alerts WHERE source = 'wazuh' "
            "AND description LIKE '%CVE%' "
            "AND timestamp > datetime('now', ?) "
            "ORDER BY timestamp DESC",
            (interval,),
        )
        wazuh_rows = [dict(row) for row in await cursor.fetchall()]

        # 2. Suricata exploit alerts (category or title mentions exploit/CVE)
        cursor = await self._db.execute(
            "SELECT id, title, category, severity, src_ip, dst_ip, timestamp "
            "FROM alerts WHERE source = 'suricata' "
            "AND (category LIKE '%exploit%' OR category LIKE '%CVE%' OR title LIKE '%CVE%') "
            "AND timestamp > datetime('now', ?) "
            "ORDER BY timestamp DESC",
            (interval,),
        )
        suricata_rows = [dict(row) for row in await cursor.fetchall()]

        # Build host->CVE mappings from Wazuh
        # host_cves: {ip: {cve_id: {severity, count, last_seen}}}
        host_cves: dict[str, dict[str, dict]] = {}
        for row in wazuh_rows:
            m = re.search(r"(CVE[- :]\d{4}[- ]\d+)", row["description"])
            if not m:
                continue
            cve_id = "CVE-" + m.group(1).replace("CVE", "").replace(":", "").replace(" ", "").replace("-", "", 1).replace("-", "-", 1)
            # Normalise to CVE-YYYY-NNNNN
            cve_raw = m.group(1)
            cve_id = "CVE-" + re.sub(r"CVE[- :]", "", cve_raw).replace(" ", "-")
            host_ip = row["src_ip"] or row["dst_ip"]
            if not host_ip:
                continue
            if host_ip not in host_cves:
                host_cves[host_ip] = {}
            if cve_id not in host_cves[host_ip]:
                host_cves[host_ip][cve_id] = {
                    "severity": row["severity"],
                    "count": 0,
                    "last_seen": row["timestamp"],
                }
            host_cves[host_ip][cve_id]["count"] += 1
            if row["timestamp"] > host_cves[host_ip][cve_id]["last_seen"]:
                host_cves[host_ip][cve_id]["last_seen"] = row["timestamp"]

        # Build set of hosts targeted by Suricata exploit alerts
        # suricata_hosts: {ip: count}
        suricata_hosts: dict[str, int] = {}
        for row in suricata_rows:
            for ip in (row["src_ip"], row["dst_ip"]):
                if ip:
                    suricata_hosts[ip] = suricata_hosts.get(ip, 0) + 1

        # 3. Correlate: find hosts that appear in both Wazuh vuln data and Suricata exploit data
        correlations: list[dict] = []
        for host_ip, cves in host_cves.items():
            suricata_count = suricata_hosts.get(host_ip, 0)
            for cve_id, info in cves.items():
                if suricata_count > 0:
                    # Both vulnerability AND active exploit on same host
                    risk_level = "critical"
                elif info["count"] > 0:
                    # Vulnerability exists + exploit attempts seen (but on other hosts)
                    any_exploit = len(suricata_rows) > 0
                    risk_level = "high" if any_exploit else "medium"
                else:
                    risk_level = "medium"

                correlations.append({
                    "cve_id": cve_id,
                    "host_ip": host_ip,
                    "wazuh_alert_count": info["count"],
                    "suricata_alert_count": suricata_count,
                    "severity": info["severity"],
                    "last_seen": info["last_seen"],
                    "risk_level": risk_level,
                })

        # Sort by risk: critical first, then high, then medium
        risk_order = {"critical": 0, "high": 1, "medium": 2}
        correlations.sort(key=lambda x: (risk_order.get(x["risk_level"], 9), -x["wazuh_alert_count"]))

        return {
            "correlations": correlations,
            "total": len(correlations),
            "hosts_with_active_exploits": len([
                h for h in host_cves if suricata_hosts.get(h, 0) > 0
            ]),
        }

    async def get_filtered_count(self, source: str = None, severity: str = None,
                                  verdict: str = None, since: str = None) -> int:
        query = "SELECT COUNT(*) FROM alerts WHERE 1=1"
        params: list = []
        if source:
            query += " AND source = ?"
            params.append(source)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if verdict:
            if verdict.startswith("!"):
                query += " AND verdict != ?"
                params.append(verdict[1:])
            else:
                query += " AND verdict = ?"
                params.append(verdict)
        if since:
            sqlite_interval = self._parse_since(since)
            if sqlite_interval:
                query += " AND timestamp > datetime('now', ?)"
                params.append(sqlite_interval)
        cursor = await self._db.execute(query, params)
        row = await cursor.fetchone()
        return row[0] if row else 0

    # ── Silence Rules ───────────────────────────────────────

    async def add_silence_rule(self, match_type: str, pattern: str,
                                reason: str = "", pattern2: str = "") -> str:
        """Add a user-created silence rule.

        match_type: title, sig_id, src_ip, category, src_ip+title, src_cidr
        pattern2: secondary pattern for combo rules (e.g. title for src_ip+title)
        """
        rid = str(uuid.uuid4())
        await self._db.execute(
            "INSERT INTO silence_rules (id, match_type, pattern, pattern2, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (rid, match_type, pattern, pattern2, reason, now_iso()),
        )
        await self._db.commit()
        return rid

    async def get_silence_rule(
        self, match_type: str, pattern: str, pattern2: str = ""
    ) -> dict | None:
        """Fetch a specific silence rule if it already exists."""
        cursor = await self._db.execute(
            "SELECT * FROM silence_rules WHERE match_type = ? AND pattern = ? AND pattern2 = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (match_type, pattern, pattern2),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_silence_rules(self) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM silence_rules ORDER BY created_at DESC"
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def delete_silence_rule(self, rule_id: str) -> bool:
        cursor = await self._db.execute(
            "DELETE FROM silence_rules WHERE id = ?", (rule_id,)
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def bump_silence_rule_hit(self, rule_id: str) -> None:
        """Increment hit_count and set last_hit for a silence rule."""
        await self._db.execute(
            "UPDATE silence_rules SET hit_count = hit_count + 1, last_hit = ? WHERE id = ?",
            (now_iso(), rule_id),
        )
        # Commit batched — caller should commit periodically

    # ── Custom Detection Rules ────────────────────────────────

    async def add_custom_rule(self, name: str, match_field: str, match_op: str,
                               match_value: str, action: str = "escalate",
                               match_field2: str = "", match_op2: str = "",
                               match_value2: str = "", action_param: str = "",
                               severity_override: str = "",
                               description: str = "") -> str:
        rid = str(uuid.uuid4())
        await self._db.execute(
            "INSERT INTO custom_rules (id, name, match_field, match_op, match_value, "
            "match_field2, match_op2, match_value2, action, action_param, "
            "severity_override, description, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (rid, name, match_field, match_op, match_value,
             match_field2, match_op2, match_value2, action, action_param,
             severity_override, description, now_iso()),
        )
        await self._db.commit()
        return rid

    async def get_custom_rules(self, enabled_only: bool = False) -> list[dict]:
        sql = "SELECT * FROM custom_rules"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY created_at DESC"
        cursor = await self._db.execute(sql)
        return [dict(row) for row in await cursor.fetchall()]

    async def update_custom_rule(self, rule_id: str, **kwargs) -> bool:
        allowed = {"name", "enabled", "match_field", "match_op", "match_value",
                    "match_field2", "match_op2", "match_value2", "action",
                    "action_param", "severity_override", "description"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        sets = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [rule_id]
        cursor = await self._db.execute(
            f"UPDATE custom_rules SET {sets} WHERE id = ?", vals
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def delete_custom_rule(self, rule_id: str) -> bool:
        cursor = await self._db.execute(
            "DELETE FROM custom_rules WHERE id = ?", (rule_id,)
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def bump_custom_rule_hit(self, rule_id: str) -> None:
        await self._db.execute(
            "UPDATE custom_rules SET hit_count = hit_count + 1, last_hit = ? WHERE id = ?",
            (now_iso(), rule_id),
        )

    def match_custom_rule(self, rule: dict, alert: dict) -> bool:
        """Check if an alert matches a custom rule's conditions."""
        if not self._match_field(rule["match_field"], rule["match_op"],
                                  rule["match_value"], alert):
            return False
        # Second condition (AND)
        if rule.get("match_field2") and rule.get("match_value2"):
            if not self._match_field(rule["match_field2"], rule["match_op2"],
                                      rule["match_value2"], alert):
                return False
        return True

    @staticmethod
    def _match_field(field: str, op: str, value: str, alert: dict) -> bool:
        alert_val = str(alert.get(field, "") or "").lower()
        value = value.lower()
        if op == "equals":
            return alert_val == value
        elif op == "contains":
            return value in alert_val
        elif op == "startswith":
            return alert_val.startswith(value)
        elif op == "regex":
            import re
            try:
                return bool(re.search(value, alert_val, re.IGNORECASE))
            except re.error:
                return False
        elif op == "gt":
            try:
                return float(alert_val) > float(value)
            except (ValueError, TypeError):
                return False
        elif op == "lt":
            try:
                return float(alert_val) < float(value)
            except (ValueError, TypeError):
                return False
        return False

    # ── Sigma Rules ────────────────────────────────────────

    async def upsert_sigma_rule(self, rule_data: dict) -> None:
        """Insert or update a Sigma rule record."""
        await self._db.execute(
            "INSERT INTO sigma_rules (id, title, level, category, description, tags, filename, enabled, loaded_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?) "
            "ON CONFLICT(id) DO UPDATE SET title=excluded.title, level=excluded.level, "
            "category=excluded.category, description=excluded.description, tags=excluded.tags, "
            "filename=excluded.filename, loaded_at=excluded.loaded_at",
            (
                rule_data.get("id", ""),
                rule_data.get("title", ""),
                rule_data.get("level", "medium"),
                rule_data.get("category", ""),
                rule_data.get("description", ""),
                json.dumps(rule_data.get("tags", [])),
                rule_data.get("filename", ""),
                now_iso(),
            ),
        )
        await self._db.commit()

    async def get_sigma_rules(self, enabled_only: bool = False) -> list[dict]:
        """Return all sigma rules, optionally filtered to enabled only."""
        sql = "SELECT * FROM sigma_rules"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY title"
        cursor = await self._db.execute(sql)
        rows = [dict(row) for row in await cursor.fetchall()]
        for row in rows:
            try:
                row["tags"] = json.loads(row.get("tags", "[]"))
            except (json.JSONDecodeError, TypeError):
                row["tags"] = []
        return rows

    async def bump_sigma_rule_hit(self, rule_id: str) -> None:
        """Increment hit_count and set last_hit for a sigma rule."""
        await self._db.execute(
            "UPDATE sigma_rules SET hit_count = hit_count + 1, last_hit = ? WHERE id = ?",
            (now_iso(), rule_id),
        )

    # ── Grouped Alerts ──────────────────────────────────────

    async def get_grouped_alerts(self, limit: int = 50, offset: int = 0,
                                  source: str = None, severity: str = None,
                                  verdict: str = None, since: str = None) -> list[dict]:
        """Get alerts grouped by (src_ip, title). Returns condensed rows."""
        query = """SELECT
            title, src_ip, dst_ip, source, category,
            MAX(severity) as severity,
            GROUP_CONCAT(severity) as severity_list,
            GROUP_CONCAT(DISTINCT verdict) as verdicts,
            COUNT(*) as cnt,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen,
            MAX(src_dns) as src_dns, MAX(dst_dns) as dst_dns,
            MAX(src_asset) as src_asset, MAX(dst_asset) as dst_asset,
            MAX(src_geo) as src_geo, MAX(dst_geo) as dst_geo,
            MAX(id) as latest_id
        FROM alerts WHERE 1=1"""
        params: list = []
        if source:
            query += " AND source = ?"
            params.append(source)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if verdict:
            if verdict.startswith("!"):
                query += " AND verdict != ?"
                params.append(verdict[1:])
            else:
                query += " AND verdict = ?"
                params.append(verdict)
        if since:
            sqlite_interval = self._parse_since(since)
            if sqlite_interval:
                query += " AND timestamp > datetime('now', ?)"
                params.append(sqlite_interval)
        query += " GROUP BY src_ip, title ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor = await self._db.execute(query, params)
        return [dict(row) for row in await cursor.fetchall()]

    # ── Agent Status ──────────────────────────────────────────

    async def upsert_agent_heartbeat(self, agent_name: str, agent_type: str = "unknown",
                                      os: str = "", ip: str = "", version: str = "",
                                      health_data: str = "{}") -> None:
        """Insert or update agent heartbeat, setting status to online."""
        now = now_iso()
        await self._db.execute(
            """INSERT INTO agent_status
            (agent_name, agent_type, os, ip, version, status, last_heartbeat,
             health_data, registered_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'online', ?, ?, ?, ?)
            ON CONFLICT(agent_name) DO UPDATE SET
                agent_type=excluded.agent_type,
                os=CASE WHEN excluded.os != '' THEN excluded.os ELSE agent_status.os END,
                ip=CASE WHEN excluded.ip != '' THEN excluded.ip ELSE agent_status.ip END,
                version=CASE WHEN excluded.version != '' THEN excluded.version ELSE agent_status.version END,
                status='online',
                last_heartbeat=excluded.last_heartbeat,
                health_data=excluded.health_data,
                updated_at=excluded.updated_at""",
            (agent_name, agent_type, os, ip, version, now, health_data, now, now),
        )
        await self._db.commit()

    async def get_agents(self) -> list[dict]:
        """Get all registered agents, ordered by status then name."""
        cursor = await self._db.execute(
            """SELECT * FROM agent_status
            ORDER BY
                CASE status WHEN 'offline' THEN 0 WHEN 'degraded' THEN 1 ELSE 2 END,
                agent_name"""
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def update_agent_status(self, agent_name: str, status: str) -> None:
        """Update agent status (online/degraded/offline)."""
        await self._db.execute(
            "UPDATE agent_status SET status = ?, updated_at = ? WHERE agent_name = ?",
            (status, now_iso(), agent_name),
        )
        await self._db.commit()

    async def update_agent_alert_count(self, agent_name: str) -> None:
        """Increment alert count and set last_alert timestamp."""
        await self._db.execute(
            "UPDATE agent_status SET alert_count = alert_count + 1, last_alert = ?, updated_at = ? WHERE agent_name = ?",
            (now_iso(), now_iso(), agent_name),
        )
        await self._db.commit()

    # ── Clove Agent ────────────────────────────────────────

    async def insert_clove_alert(self, agent_name: str, alert_type: str,
                                 severity: str, title: str, details: str,
                                 source_ip: str, timestamp: str) -> str:
        """Insert a clove agent alert, returns its ID."""
        alert_id = str(uuid.uuid4())
        await self._db.execute(
            """INSERT INTO clove_alerts
            (id, agent_name, alert_type, severity, title, details, source_ip, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (alert_id, agent_name, alert_type, severity, title, details,
             source_ip, timestamp),
        )
        await self._db.commit()
        return alert_id

    async def get_clove_alerts(self, agent_name: str | None = None,
                               resolved: int | None = None,
                               limit: int = 100) -> list[dict]:
        """Query clove alerts with optional filters."""
        sql = "SELECT * FROM clove_alerts WHERE 1=1"
        params: list = []
        if agent_name is not None:
            sql += " AND agent_name = ?"
            params.append(agent_name)
        if resolved is not None:
            sql += " AND resolved = ?"
            params.append(resolved)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cursor = await self._db.execute(sql, params)
        return [dict(row) for row in await cursor.fetchall()]

    async def resolve_clove_alert(self, alert_id: str) -> None:
        """Mark a clove alert as resolved."""
        await self._db.execute(
            "UPDATE clove_alerts SET resolved = 1 WHERE id = ?",
            (alert_id,),
        )
        await self._db.commit()

    async def upsert_clove_heartbeat(self, agent_name: str, agent_type: str,
                                     os: str, ip: str, version: str,
                                     health: str, baselines: str) -> dict:
        """Insert or replace agent heartbeat, returns commands for the agent."""
        now = now_iso()
        # Check if update was requested before upserting
        cursor = await self._db.execute(
            "SELECT update_requested FROM agent_heartbeats WHERE agent_name = ?",
            (agent_name,),
        )
        row = await cursor.fetchone()
        send_update = bool(row and row["update_requested"])

        await self._db.execute(
            """INSERT INTO agent_heartbeats
            (agent_name, agent_type, os, ip, version, last_seen, health, baselines, update_requested)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            ON CONFLICT(agent_name) DO UPDATE SET
                agent_type=excluded.agent_type,
                os=CASE WHEN excluded.os IS NOT NULL AND excluded.os != '' THEN excluded.os ELSE agent_heartbeats.os END,
                ip=CASE WHEN excluded.ip IS NOT NULL AND excluded.ip != '' THEN excluded.ip ELSE agent_heartbeats.ip END,
                version=CASE WHEN excluded.version IS NOT NULL AND excluded.version != '' THEN excluded.version ELSE agent_heartbeats.version END,
                last_seen=excluded.last_seen,
                health=excluded.health,
                baselines=excluded.baselines,
                update_requested=0""",
            (agent_name, agent_type, os, ip, version, now, health, baselines),
        )
        await self._db.commit()
        return {"update": send_update}

    async def get_agent_heartbeats(self) -> list[dict]:
        """Return all agent heartbeats."""
        cursor = await self._db.execute(
            "SELECT * FROM agent_heartbeats ORDER BY last_seen DESC"
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_stale_agents(self, stale_minutes: int = 10) -> list[dict]:
        """Return agents where last_seen is older than stale_minutes ago."""
        cutoff = (datetime.utcnow() - timedelta(minutes=stale_minutes)).isoformat()
        cursor = await self._db.execute(
            "SELECT * FROM agent_heartbeats WHERE last_seen < ?",
            (cutoff,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def request_agent_update(self, agent_name: str) -> None:
        """Flag an agent for update on next heartbeat."""
        await self._db.execute(
            "UPDATE agent_heartbeats SET update_requested = 1 WHERE agent_name = ?",
            (agent_name,),
        )
        await self._db.commit()

    # ── Knowledge Base ──────────────────────────────────────

    async def search_knowledge(self, query: str, limit: int = 5) -> list[dict]:
        """FTS5 search over knowledge base, returns top matches for RAG."""
        try:
            cursor = await self._db.execute(
                """SELECT knowledge.* FROM knowledge_fts
                JOIN knowledge ON knowledge_fts.rowid = knowledge.rowid
                WHERE knowledge_fts MATCH ?
                ORDER BY rank LIMIT ?""",
                (query, limit),
            )
            return [dict(row) for row in await cursor.fetchall()]
        except Exception:
            return []

    async def seed_knowledge(self, facts: list[dict], version: str = "1") -> int:
        """Bulk insert knowledge facts. Skips if already seeded at this version."""
        cursor = await self._db.execute(
            "SELECT value FROM meta WHERE key = 'knowledge_version'"
        )
        row = await cursor.fetchone()
        if row and row[0] == version:
            return 0  # already seeded

        # Clear and re-seed
        await self._db.execute("DELETE FROM knowledge")
        count = 0
        for fact in facts:
            await self._db.execute(
                "INSERT INTO knowledge (category, topic, content, source) VALUES (?, ?, ?, ?)",
                (fact.get("category", ""), fact.get("topic", ""),
                 fact.get("content", ""), fact.get("source", "")),
            )
            count += 1

        await self._db.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('knowledge_version', ?)",
            (version,),
        )
        await self._db.commit()
        return count

    # ── Alert Chat ──────────────────────────────────────────

    async def add_chat_message(self, alert_id: str, role: str,
                                content: str, action: str = "") -> int:
        """Insert a chat message for an alert."""
        cursor = await self._db.execute(
            "INSERT INTO alert_chat (alert_id, role, content, action, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (alert_id, role, content, action, now_iso()),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_chat_history(self, alert_id: str, limit: int = 20) -> list[dict]:
        """Get recent chat messages for an alert."""
        cursor = await self._db.execute(
            "SELECT * FROM alert_chat WHERE alert_id = ? ORDER BY created_at ASC LIMIT ?",
            (alert_id, limit),
        )
        return [dict(row) for row in await cursor.fetchall()]

    # ── Investigations ──────────────────────────────────────

    async def insert_investigation(self, report) -> str:
        """Store an investigation report."""
        await self._db.execute(
            """INSERT INTO investigations
            (id, created_at, since_window, alert_count, report_json, verdicts_applied, model, latency_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report.id, report.created_at, report.since_window,
                report.alert_count, json.dumps(report.to_dict(), default=str),
                1 if report.verdicts_applied else 0,
                report.model, report.latency_ms,
            ),
        )
        await self._db.commit()
        return report.id

    async def get_investigation(self, investigation_id: str) -> dict | None:
        cursor = await self._db.execute(
            "SELECT * FROM investigations WHERE id = ?", (investigation_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["report"] = json.loads(d.get("report_json", "{}"))
        except (json.JSONDecodeError, TypeError):
            d["report"] = {}
        return d

    async def get_recent_investigations(self, limit: int = 10) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT id, created_at, since_window, alert_count, verdicts_applied, model, latency_ms "
            "FROM investigations ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    # ── Stats ───────────────────────────────────────────────

    async def get_stats(self) -> dict:
        """Get summary statistics."""
        stats = {}
        for label, query in [
            ("total_alerts", "SELECT COUNT(*) FROM alerts"),
            ("pending_triage", "SELECT COUNT(*) FROM alerts WHERE verdict = 'pending'"),
            ("suppressed", "SELECT COUNT(*) FROM alerts WHERE verdict = 'suppress'"),
            ("investigate", "SELECT COUNT(*) FROM alerts WHERE verdict = 'investigate'"),
            ("escalated", "SELECT COUNT(*) FROM alerts WHERE verdict = 'escalate'"),
            ("correlations", "SELECT COUNT(*) FROM correlations"),
        ]:
            cursor = await self._db.execute(query)
            row = await cursor.fetchone()
            stats[label] = row[0]

        # Source breakdown
        cursor = await self._db.execute(
            "SELECT source, COUNT(*) as cnt FROM alerts GROUP BY source"
        )
        stats["by_source"] = {row[0]: row[1] for row in await cursor.fetchall()}

        # Severity breakdown
        cursor = await self._db.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
        )
        stats["by_severity"] = {row[0]: row[1] for row in await cursor.fetchall()}

        # Agent counts
        try:
            cursor = await self._db.execute("SELECT COUNT(*) FROM agent_status")
            row = await cursor.fetchone()
            stats["agents_total"] = row[0]
            cursor = await self._db.execute(
                "SELECT COUNT(*) FROM agent_status WHERE status = 'online'"
            )
            row = await cursor.fetchone()
            stats["agents_online"] = row[0]
            stats["agents_offline"] = stats["agents_total"] - stats["agents_online"]
        except Exception:
            stats["agents_total"] = 0
            stats["agents_online"] = 0
            stats["agents_offline"] = 0

        return stats

    async def get_dashboard_stats(self, home_cidr: str = "192.168.0.0/16") -> dict:
        """Cluster-based dashboard stats split by internal vs external source IP.

        Returns new UX fields plus all legacy fields for backward compat.
        """
        import ipaddress
        network = ipaddress.ip_network(home_cidr, strict=False)

        # Get all cluster verdicts + src_ip
        cursor = await self._db.execute(
            "SELECT src_ip, verdict, COUNT(*) as cnt FROM clusters GROUP BY src_ip, verdict"
        )
        rows = await cursor.fetchall()

        needs_review = 0      # external pending+investigate clusters
        threats_external = 0  # external escalated clusters
        auto_handled = 0      # all suppressed clusters
        your_activity = 0     # all clusters from home IPs

        for row in rows:
            src_ip = row[0] or ""
            verdict = row[1] or "pending"
            cnt = row[2]

            try:
                is_home = ipaddress.ip_address(src_ip) in network if src_ip else False
            except ValueError:
                is_home = False

            if is_home:
                your_activity += cnt
            else:
                if verdict == "investigate":
                    needs_review += cnt
                elif verdict == "escalate":
                    threats_external += cnt
                # NOTE: 'pending' (AI hasn't triaged yet) is the engine's backlog,
                # not the operator's queue — deliberately excluded from needs_review.

            if verdict == "suppress":
                auto_handled += cnt

        # Start with legacy stats for backward compat
        stats = await self.get_stats()

        # Add new dashboard fields
        stats["needs_review"] = needs_review
        stats["threats_external"] = threats_external
        stats["auto_handled"] = auto_handled
        stats["your_activity"] = your_activity

        # SLA / alert age metrics
        sla = await self.get_sla_stats()
        stats.update(sla)

        return stats

    async def get_sla_stats(self) -> dict:
        """Compute alert SLA / age metrics from existing data."""
        now = now_iso()

        # Oldest pending alert age (minutes)
        cursor = await self._db.execute(
            "SELECT MIN(ingested_at) FROM alerts WHERE verdict = 'pending' AND ingested_at IS NOT NULL"
        )
        row = await cursor.fetchone()
        oldest_pending_min = 0
        if row and row[0]:
            try:
                oldest = datetime.fromisoformat(row[0].replace("Z", "+00:00"))
                oldest_pending_min = int((datetime.now(oldest.tzinfo) - oldest).total_seconds() / 60)
            except Exception:
                pass

        # Stale alerts: pending for > 24h
        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM alerts WHERE verdict = 'pending' "
            "AND ingested_at IS NOT NULL AND ingested_at < datetime('now', '-1 day')"
        )
        row = await cursor.fetchone()
        stale_count = row[0] if row else 0

        # Average age of pending alerts (minutes)
        cursor = await self._db.execute(
            "SELECT AVG((julianday('now') - julianday(ingested_at)) * 1440) "
            "FROM alerts WHERE verdict = 'pending' AND ingested_at IS NOT NULL"
        )
        row = await cursor.fetchone()
        avg_pending_min = int(row[0]) if row and row[0] else 0

        # MTTR: average minutes from ingested_at to audit_log verdict entry
        # Use audit_log entries where action='verdict' to estimate resolution time
        cursor = await self._db.execute(
            "SELECT AVG((julianday(a.ts) - julianday(al.ingested_at)) * 1440) "
            "FROM audit_log a "
            "JOIN alerts al ON al.id = a.target_id "
            "WHERE a.action = 'verdict' AND al.ingested_at IS NOT NULL "
            "AND a.ts > datetime('now', '-7 day')"
        )
        row = await cursor.fetchone()
        mttr_min = int(row[0]) if row and row[0] else 0

        return {
            "sla_oldest_pending_min": oldest_pending_min,
            "sla_stale_count": stale_count,
            "sla_avg_pending_min": avg_pending_min,
            "sla_mttr_min": mttr_min,
        }

    # ── AI Decisions ──────────────────────────────────────────

    async def add_ai_decision(self, mode: str, action: str, summary: str,
                               detail: str = "", alert_ids: str = "",
                               status: str = "done") -> str:
        did = str(uuid.uuid4())
        if not isinstance(alert_ids, str):
            alert_ids = json.dumps(alert_ids)
        await self._db.execute(
            "INSERT INTO ai_decisions (id, ts, mode, action, summary, detail, alert_ids, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (did, now_iso(), mode, action, summary, detail, alert_ids, status),
        )
        await self._db.commit()
        return did

    async def get_ai_decisions(self, limit: int = 50, offset: int = 0,
                                status: str = None) -> list[dict]:
        query = "SELECT * FROM ai_decisions WHERE 1=1"
        params: list = []
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor = await self._db.execute(query, params)
        return [dict(row) for row in await cursor.fetchall()]

    async def resolve_ai_decision(self, decision_id: str, resolved_by: str) -> bool:
        cursor = await self._db.execute(
            "UPDATE ai_decisions SET status = 'done', resolved_by = ?, resolved_at = ? WHERE id = ?",
            (resolved_by, now_iso(), decision_id),
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def reject_ai_decision(self, decision_id: str) -> bool:
        cursor = await self._db.execute(
            "UPDATE ai_decisions SET status = 'rejected', resolved_by = 'human', resolved_at = ? WHERE id = ?",
            (now_iso(), decision_id),
        )
        await self._db.commit()
        return cursor.rowcount > 0

    # ── Squawks ──────────────────────────────────────────────

    async def add_squawk(self, severity: str, title: str, detail: str = "",
                          alert_ids: str | list[str] = "") -> str:
        if isinstance(alert_ids, list):
            alert_ids = json.dumps(alert_ids)
        existing = await self._db.execute(
            """
            SELECT id FROM squawks
            WHERE dismissed = 0 AND title = ? AND alert_ids = ?
            ORDER BY ts DESC LIMIT 1
            """,
            (title, alert_ids),
        )
        row = await existing.fetchone()
        if row:
            return row["id"]
        sid = str(uuid.uuid4())
        await self._db.execute(
            "INSERT INTO squawks (id, ts, severity, title, detail, alert_ids) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (sid, now_iso(), severity, title, detail, alert_ids),
        )
        await self._db.commit()
        return sid

    async def get_active_squawks(self) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM squawks WHERE dismissed = 0 ORDER BY ts DESC"
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_squawks(self, limit: int = 50) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM squawks ORDER BY ts DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def dismiss_squawk(self, squawk_id: str) -> bool:
        cursor = await self._db.execute(
            "UPDATE squawks SET dismissed = 1, dismissed_at = ? WHERE id = ?",
            (now_iso(), squawk_id),
        )
        await self._db.commit()
        return cursor.rowcount > 0

    # ── AI Verdicts ──────────────────────────────────────────

    async def upsert_ai_verdict(self, pattern_type: str, pattern: str,
                                 verdict: str, confidence: float = 0.5,
                                 auto_rule_id: str = "") -> str:
        """Insert or update a learned verdict pattern."""
        now = now_iso()
        # Check existing
        cursor = await self._db.execute(
            "SELECT id, sample_count FROM ai_verdicts WHERE pattern_type = ? AND pattern = ?",
            (pattern_type, pattern),
        )
        row = await cursor.fetchone()
        if row:
            vid = row["id"]
            new_count = row["sample_count"] + 1
            await self._db.execute(
                "UPDATE ai_verdicts SET verdict = ?, confidence = ?, sample_count = ?, "
                "last_seen = ?, auto_rule_id = CASE WHEN ? != '' THEN ? ELSE auto_rule_id END "
                "WHERE id = ?",
                (verdict, confidence, new_count, now, auto_rule_id, auto_rule_id, vid),
            )
        else:
            vid = str(uuid.uuid4())
            await self._db.execute(
                "INSERT INTO ai_verdicts (id, pattern_type, pattern, verdict, confidence, "
                "sample_count, last_seen, auto_rule_id) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                (vid, pattern_type, pattern, verdict, confidence, now, auto_rule_id),
            )
        await self._db.commit()
        return vid

    async def get_ai_verdicts(self, limit: int = 100) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM ai_verdicts ORDER BY sample_count DESC, last_seen DESC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_verdict_for_pattern(self, pattern_type: str, pattern: str) -> dict | None:
        cursor = await self._db.execute(
            "SELECT * FROM ai_verdicts WHERE pattern_type = ? AND pattern = ?",
            (pattern_type, pattern),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ── Shift Reports ────────────────────────────────────────

    async def add_shift_report(self, period_start: str, period_end: str,
                                summary: str, stats: str = "", threats: str = "") -> str:
        rid = str(uuid.uuid4())
        await self._db.execute(
            "INSERT INTO shift_reports (id, ts, period_start, period_end, summary, stats, threats) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rid, now_iso(), period_start, period_end, summary, stats, threats),
        )
        await self._db.commit()
        return rid

    async def get_shift_reports(self, limit: int = 10) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM shift_reports ORDER BY ts DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_shift_report(self, report_id: str) -> dict | None:
        cursor = await self._db.execute(
            "SELECT * FROM shift_reports WHERE id = ?", (report_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ── Clusters ────────────────────────────────────────────

    @staticmethod
    def _cluster_key(src_ip: str, title: str) -> str:
        """Deterministic cluster key from (src_ip, title)."""
        import hashlib
        return hashlib.sha256(f"{src_ip or ''}|{title or ''}".encode()).hexdigest()[:16]

    async def assign_alert_to_cluster(self, alert_id: str, src_ip: str, title: str,
                                       severity: str = "medium",
                                       timestamp: str = "") -> str:
        """Assign an alert to a cluster by (src_ip, title). Creates or updates the cluster.

        Returns the cluster_id.
        """
        now = now_iso()
        ts = timestamp or now
        key = self._cluster_key(src_ip, title)

        # Check if cluster exists
        cursor = await self._db.execute(
            "SELECT id, alert_count, severity FROM clusters WHERE cluster_key = ?", (key,)
        )
        row = await cursor.fetchone()

        if row:
            cluster_id = row["id"]
            old_count = row["alert_count"]
            # Keep the highest severity
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            best_sev = severity if sev_order.get(severity, 0) > sev_order.get(row["severity"], 0) else row["severity"]
            await self._db.execute(
                """UPDATE clusters SET alert_count = ?, severity = ?,
                   last_seen = MAX(last_seen, ?), updated_at = ?
                   WHERE id = ?""",
                (old_count + 1, best_sev, ts, now, cluster_id),
            )
        else:
            cluster_id = str(uuid.uuid4())
            await self._db.execute(
                """INSERT INTO clusters (id, cluster_key, src_ip, title, severity,
                   verdict, alert_count, first_seen, last_seen, updated_at)
                   VALUES (?, ?, ?, ?, ?, 'pending', 1, ?, ?, ?)""",
                (cluster_id, key, src_ip or "", title or "", severity, ts, ts, now),
            )

        # Tag the alert with its cluster
        await self._db.execute(
            "UPDATE alerts SET cluster_id = ? WHERE id = ?", (cluster_id, alert_id)
        )
        await self._db.commit()
        return cluster_id

    async def get_clusters(self, limit: int = 50, offset: int = 0,
                            verdict: str = None, sort: str = "last_seen") -> list[dict]:
        """Get clusters with optional verdict filter, paginated."""
        query = "SELECT * FROM clusters WHERE 1=1"
        params: list = []
        if verdict:
            if verdict.startswith("!"):
                query += " AND verdict != ?"
                params.append(verdict[1:])
            else:
                query += " AND verdict = ?"
                params.append(verdict)
        valid_sorts = {"last_seen", "alert_count", "severity", "first_seen"}
        sort_col = sort if sort in valid_sorts else "last_seen"
        query += f" ORDER BY {sort_col} DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor = await self._db.execute(query, params)
        return [dict(row) for row in await cursor.fetchall()]

    async def get_cluster(self, cluster_id: str) -> dict | None:
        cursor = await self._db.execute("SELECT * FROM clusters WHERE id = ?", (cluster_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_cluster_alerts(self, cluster_id: str, limit: int = 100) -> list[dict]:
        """Get member alerts of a cluster."""
        cursor = await self._db.execute(
            "SELECT * FROM alerts WHERE cluster_id = ? ORDER BY timestamp DESC LIMIT ?",
            (cluster_id, limit),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def set_cluster_verdict(self, cluster_id: str, verdict: str,
                                   reasoning: str = "") -> int:
        """Set verdict on a cluster and propagate to all member alerts.

        Returns count of alerts updated.
        """
        now = now_iso()
        await self._db.execute(
            "UPDATE clusters SET verdict = ?, updated_at = ? WHERE id = ?",
            (verdict, now, cluster_id),
        )
        reason = reasoning or f"Cluster verdict: {verdict}"
        cursor = await self._db.execute(
            "UPDATE alerts SET verdict = ?, confidence = 1.0, ai_reasoning = ? WHERE cluster_id = ?",
            (verdict, reason, cluster_id),
        )
        updated = cursor.rowcount
        await self._db.commit()
        return updated

    async def get_cluster_count(self, verdict: str = None) -> int:
        """Count clusters, optionally filtered by verdict."""
        if verdict:
            cursor = await self._db.execute(
                "SELECT COUNT(*) FROM clusters WHERE verdict = ?", (verdict,)
            )
        else:
            cursor = await self._db.execute("SELECT COUNT(*) FROM clusters")
        row = await cursor.fetchone()
        return row[0]

    async def get_noisy_clusters(
        self, min_count: int = 5, window_minutes: int = 0
    ) -> list[dict]:
        """Get recent high-volume pending clusters for autopilot noise detection."""
        query = (
            "SELECT * FROM clusters "
            "WHERE alert_count >= ? AND verdict = 'pending'"
        )
        params: list = [min_count]
        if window_minutes and window_minutes > 0:
            query += " AND datetime(last_seen) >= datetime('now', ?)"
            params.append(f"-{int(window_minutes)} minutes")
        query += " ORDER BY alert_count DESC"
        cursor = await self._db.execute(query, params)
        return [dict(row) for row in await cursor.fetchall()]

    async def backfill_clusters(self) -> int:
        """Assign all unassigned alerts to clusters. Returns count of alerts assigned."""
        cursor = await self._db.execute(
            """SELECT id, src_ip, title, severity, timestamp
               FROM alerts WHERE cluster_id IS NULL
               ORDER BY timestamp ASC"""
        )
        rows = await cursor.fetchall()
        count = 0
        for row in rows:
            await self.assign_alert_to_cluster(
                alert_id=row["id"],
                src_ip=row["src_ip"] or "",
                title=row["title"] or "",
                severity=row["severity"] or "medium",
                timestamp=row["timestamp"] or "",
            )
            count += 1
        return count

    # ── AI Stats (for autopilot status) ──────────────────────

    async def get_ai_stats(self) -> dict:
        """Get AI autopilot statistics."""
        stats = {}
        for label, query in [
            ("decisions_total", "SELECT COUNT(*) FROM ai_decisions"),
            ("decisions_today", "SELECT COUNT(*) FROM ai_decisions WHERE ts > datetime('now', '-1 day')"),
            ("pending_suggestions", "SELECT COUNT(*) FROM ai_decisions WHERE status = 'pending'"),
            ("active_squawks", "SELECT COUNT(*) FROM squawks WHERE dismissed = 0"),
            ("verdicts_learned", "SELECT COUNT(*) FROM ai_verdicts"),
            ("noise_verdicts", "SELECT COUNT(*) FROM ai_verdicts WHERE verdict = 'noise'"),
            ("threat_verdicts", "SELECT COUNT(*) FROM ai_verdicts WHERE verdict = 'threat'"),
        ]:
            try:
                cursor = await self._db.execute(query)
                row = await cursor.fetchone()
                stats[label] = row[0]
            except Exception:
                stats[label] = 0
        return stats

    # ── Incidents ──────────────────────────────────────────────

    async def insert_incident(self, incident: dict) -> str:
        """Insert a new incident. Returns the incident ID."""
        iid = incident.get("id") or str(uuid.uuid4())
        now = now_iso()
        await self._db.execute(
            """INSERT OR IGNORE INTO incidents
               (id, title, summary, severity, status, urgency, category,
                affected_ips, affected_hosts, alert_count,
                correlation_id, cluster_ids, alert_ids,
                runbook, ai_analysis, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (iid, incident.get("title", ""),
             incident.get("summary", ""), incident.get("severity", "medium"),
             incident.get("status", "new"), incident.get("urgency", "check"),
             incident.get("category", ""),
             json.dumps(incident.get("affected_ips", [])),
             json.dumps(incident.get("affected_hosts", [])),
             incident.get("alert_count", 0),
             incident.get("correlation_id"),
             json.dumps(incident.get("cluster_ids", [])),
             json.dumps(incident.get("alert_ids", [])),
             json.dumps(incident.get("runbook", [])),
             incident.get("ai_analysis", ""),
             incident.get("created_at", now), now),
        )
        await self._db.commit()
        return iid

    async def get_incidents(self, status: str = None, limit: int = 50,
                             offset: int = 0) -> list[dict]:
        """Get incidents, optionally filtered by status."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params: list = []
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor = await self._db.execute(query, params)
        rows = [dict(row) for row in await cursor.fetchall()]
        # Parse JSON fields
        for row in rows:
            for field in ("affected_ips", "affected_hosts", "cluster_ids", "alert_ids", "runbook"):
                try:
                    row[field] = json.loads(row[field]) if row[field] else []
                except (json.JSONDecodeError, TypeError):
                    row[field] = []
        return rows

    async def get_incident(self, incident_id: str) -> dict | None:
        """Get a single incident by ID."""
        cursor = await self._db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        for field in ("affected_ips", "affected_hosts", "cluster_ids", "alert_ids", "runbook"):
            try:
                d[field] = json.loads(d[field]) if d[field] else []
            except (json.JSONDecodeError, TypeError):
                d[field] = []
        return d

    async def update_incident_status(self, incident_id: str, status: str,
                                      resolved_by: str = "") -> bool:
        """Update incident status. Returns True if updated."""
        now = now_iso()
        resolved_at = now if status in ("resolved", "false_positive") else None
        cursor = await self._db.execute(
            """UPDATE incidents SET status = ?, updated_at = ?,
               resolved_at = COALESCE(?, resolved_at),
               resolved_by = COALESCE(NULLIF(?, ''), resolved_by)
               WHERE id = ?""",
            (status, now, resolved_at, resolved_by, incident_id),
        )
        await self._db.commit()
        updated = cursor.rowcount > 0
        if updated:
            try:
                await self.add_incident_event(
                    incident_id, "status_change",
                    f"Status changed to {status}",
                    resolved_by or "", resolved_by or "system",
                )
            except Exception:
                pass
        return updated

    async def get_incident_counts(self) -> dict:
        """Get incident counts by status."""
        cursor = await self._db.execute(
            "SELECT status, COUNT(*) as cnt FROM incidents GROUP BY status"
        )
        rows = await cursor.fetchall()
        counts = {"new": 0, "investigating": 0, "resolved": 0, "false_positive": 0, "total": 0}
        for row in rows:
            counts[row[0]] = row[1]
            counts["total"] += row[1]
        return counts

    async def get_existing_incident_keys(self) -> set[str]:
        """Get set of (correlation_id or cluster_id combo) keys for dedup."""
        keys = set()
        cursor = await self._db.execute(
            "SELECT correlation_id, cluster_ids FROM incidents WHERE status NOT IN ('resolved', 'false_positive')"
        )
        for row in await cursor.fetchall():
            if row[0]:
                keys.add(f"corr:{row[0]}")
            try:
                cids = json.loads(row[1]) if row[1] else []
                for cid in cids:
                    keys.add(f"cluster:{cid}")
            except (json.JSONDecodeError, TypeError):
                pass
        return keys

    async def record_incident_decision(self, incident_id: str, category: str,
                                        pattern_key: str, decision: str) -> None:
        """Record a user's decision on an incident for pattern learning."""
        await self._db.execute(
            """INSERT INTO incident_decisions (incident_id, category, pattern_key, decision, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (incident_id, category, pattern_key, decision, now_iso()),
        )
        await self._db.commit()

    async def get_pattern_history(self, pattern_key: str, limit: int = 20) -> list[dict]:
        """Get decision history for a pattern."""
        cursor = await self._db.execute(
            """SELECT decision, COUNT(*) as cnt FROM incident_decisions
               WHERE pattern_key = ? GROUP BY decision ORDER BY cnt DESC""",
            (pattern_key,),
        )
        return [{"decision": row[0], "count": row[1]} for row in await cursor.fetchall()]

    async def get_auto_dismiss_candidates(self) -> list[dict]:
        """Get patterns that have been false-positive'd 3+ times — candidates for auto-dismiss."""
        cursor = await self._db.execute(
            """SELECT pattern_key, category, COUNT(*) as fp_count
               FROM incident_decisions
               WHERE decision = 'false_positive'
               GROUP BY pattern_key
               HAVING fp_count >= 3
               ORDER BY fp_count DESC"""
        )
        return [{"pattern_key": row[0], "category": row[1], "fp_count": row[2]}
                for row in await cursor.fetchall()]

    # ── Incident Notes & Timeline ────────────────────────────

    async def add_incident_note(self, incident_id: str, note: str,
                                 author: str = "analyst") -> int:
        """Add a note to an incident. Returns note ID."""
        cursor = await self._db.execute(
            "INSERT INTO incident_notes (incident_id, note, author, created_at) VALUES (?, ?, ?, ?)",
            (incident_id, note, author, now_iso()),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_incident_notes(self, incident_id: str) -> list[dict]:
        """Get all notes for an incident."""
        cursor = await self._db.execute(
            "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at DESC",
            (incident_id,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def add_incident_event(self, incident_id: str, event_type: str,
                                  description: str, detail: str = "",
                                  actor: str = "system") -> int:
        """Add a timeline event to an incident."""
        cursor = await self._db.execute(
            """INSERT INTO incident_events
               (incident_id, event_type, description, detail, actor, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (incident_id, event_type, description, detail, actor, now_iso()),
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_incident_timeline(self, incident_id: str) -> list[dict]:
        """Get full timeline for an incident (events + notes merged, chronological)."""
        events = []

        # Timeline events
        cursor = await self._db.execute(
            "SELECT * FROM incident_events WHERE incident_id = ? ORDER BY created_at",
            (incident_id,),
        )
        for row in await cursor.fetchall():
            events.append({
                "type": "event",
                "event_type": row["event_type"],
                "description": row["description"],
                "detail": row["detail"] or "",
                "actor": row["actor"],
                "created_at": row["created_at"],
            })

        # Notes as timeline entries
        cursor = await self._db.execute(
            "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at",
            (incident_id,),
        )
        for row in await cursor.fetchall():
            events.append({
                "type": "note",
                "event_type": "note",
                "description": row["note"],
                "detail": "",
                "actor": row["author"],
                "created_at": row["created_at"],
            })

        events.sort(key=lambda e: e["created_at"])
        return events

    # ── Audit Log ─────────────────────────────────────────────

    async def insert_audit(self, action: str, target_type: str = "",
                            target_id: str = "", detail: str = "",
                            actor: str = "user", ip: str = "") -> None:
        """Record an action in the audit log."""
        await self._db.execute(
            """INSERT INTO audit_log (ts, action, target_type, target_id, detail, actor, ip)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (now_iso(), action, target_type, target_id, detail, actor, ip),
        )
        await self._db.commit()

    async def get_audit_log(self, limit: int = 100, offset: int = 0,
                             action: str = None) -> list[dict]:
        """Get audit log entries."""
        sql = "SELECT * FROM audit_log"
        params: list = []
        if action:
            sql += " WHERE action = ?"
            params.append(action)
        sql += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor = await self._db.execute(sql, params)
        return [dict(row) for row in await cursor.fetchall()]

    async def get_audit_count(self) -> int:
        cursor = await self._db.execute("SELECT COUNT(*) FROM audit_log")
        row = await cursor.fetchone()
        return row[0] if row else 0

    # ── Asset Inventory ───────────────────────────────────────

    async def upsert_asset(self, ip: str, mac: str = "", hostname: str = "",
                            os: str = "", asset_type: str = "unknown",
                            source: str = "auto") -> str:
        """Insert or update an asset. Returns asset ID."""
        now = now_iso()

        # Check if asset with this IP exists
        cursor = await self._db.execute(
            "SELECT id, alert_count FROM assets WHERE ip = ?", (ip,)
        )
        existing = await cursor.fetchone()

        if existing:
            # Update last_seen and any new info
            updates = ["last_seen = ?"]
            params: list = [now]
            if mac:
                updates.append("mac = ?")
                params.append(mac)
            if hostname:
                updates.append("hostname = ?")
                params.append(hostname)
            if os:
                updates.append("os = ?")
                params.append(os)
            params.append(ip)
            await self._db.execute(
                f"UPDATE assets SET {', '.join(updates)} WHERE ip = ?",
                params,
            )
            await self._db.commit()
            return existing["id"]
        else:
            aid = str(uuid.uuid4())
            await self._db.execute(
                """INSERT INTO assets (id, ip, mac, hostname, os, asset_type,
                   criticality, first_seen, last_seen, source)
                   VALUES (?, ?, ?, ?, ?, ?, 'medium', ?, ?, ?)""",
                (aid, ip, mac, hostname, os, asset_type, now, now, source),
            )
            await self._db.commit()
            return aid

    async def get_assets(self, limit: int = 200) -> list[dict]:
        """Get all assets."""
        cursor = await self._db.execute(
            "SELECT * FROM assets ORDER BY last_seen DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_asset(self, asset_id: str) -> dict | None:
        cursor = await self._db.execute(
            "SELECT * FROM assets WHERE id = ?", (asset_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def update_asset(self, asset_id: str, **kwargs) -> bool:
        """Update asset fields."""
        allowed = {"hostname", "os", "asset_type", "criticality",
                    "network_segment", "notes", "mac"}
        updates = []
        params = []
        for k, v in kwargs.items():
            if k in allowed:
                updates.append(f"{k} = ?")
                params.append(v)
        if not updates:
            return False
        params.append(asset_id)
        cursor = await self._db.execute(
            f"UPDATE assets SET {', '.join(updates)} WHERE id = ?", params
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def increment_asset_alerts(self, ip: str) -> None:
        """Bump alert count for an asset by IP."""
        await self._db.execute(
            "UPDATE assets SET alert_count = alert_count + 1, last_seen = ? WHERE ip = ?",
            (now_iso(), ip),
        )
        await self._db.commit()

    # ── Known Devices (new device detection) ──────────────────

    async def check_and_register_device(self, mac: str, ip: str = "",
                                         hostname: str = "") -> bool:
        """Register a device by MAC. Returns True if device is NEW (never seen before)."""
        if not mac or mac == "00:00:00:00:00:00":
            return False
        now = now_iso()
        cursor = await self._db.execute(
            "SELECT mac, alert_generated FROM known_devices WHERE mac = ?", (mac,)
        )
        existing = await cursor.fetchone()
        if existing:
            await self._db.execute(
                "UPDATE known_devices SET last_seen = ?, ip = ?, hostname = ? WHERE mac = ?",
                (now, ip or existing["ip"] if hasattr(existing, '__getitem__') else ip, hostname, mac),
            )
            await self._db.commit()
            return False
        else:
            await self._db.execute(
                "INSERT INTO known_devices (mac, ip, hostname, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                (mac, ip, hostname, now, now),
            )
            await self._db.commit()
            return True

    async def mark_device_alerted(self, mac: str) -> None:
        await self._db.execute(
            "UPDATE known_devices SET alert_generated = 1 WHERE mac = ?", (mac,)
        )
        await self._db.commit()

    async def get_known_devices(self, limit: int = 200) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM known_devices ORDER BY last_seen DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in await cursor.fetchall()]

    # ── TLS Certificate Monitoring ────────────────────────────

    async def upsert_tls_cert(self, host: str, port: int, cert_data: dict) -> None:
        """Insert or update a TLS certificate record."""
        await self._db.execute(
            """INSERT INTO tls_certs (id, host, port, subject, issuer,
                   not_before, not_after, serial, days_remaining, status, last_checked)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(host, port) DO UPDATE SET
                   subject=excluded.subject, issuer=excluded.issuer,
                   not_before=excluded.not_before, not_after=excluded.not_after,
                   serial=excluded.serial, days_remaining=excluded.days_remaining,
                   status=excluded.status, last_checked=excluded.last_checked""",
            (
                cert_data.get("id", str(uuid.uuid4())),
                host, port,
                cert_data.get("subject", ""),
                cert_data.get("issuer", ""),
                cert_data.get("not_before", ""),
                cert_data.get("not_after", ""),
                cert_data.get("serial", ""),
                cert_data.get("days_remaining", -1),
                cert_data.get("status", "ok"),
                cert_data.get("last_checked", now_iso()),
            ),
        )
        await self._db.commit()

    async def get_tls_certs(self) -> list[dict]:
        """Return all TLS certificate records."""
        cursor = await self._db.execute(
            "SELECT * FROM tls_certs ORDER BY days_remaining ASC"
        )
        return [dict(row) for row in await cursor.fetchall()]

    # ── Database Backup ───────────────────────────────────────

    async def backup_database(self, backup_dir: str = None) -> str:
        """Create a backup of the database. Returns backup file path."""
        import shutil
        src = Path(self.db_path)
        if backup_dir:
            dst_dir = Path(backup_dir)
        else:
            dst_dir = src.parent / "backups"
        dst_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst = dst_dir / f"shallots_{ts}.db"

        # Use SQLite backup API via checkpoint first
        await self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        # Copy the file
        shutil.copy2(str(src), str(dst))
        return str(dst)

    async def get_db_stats(self) -> dict:
        """Get database size and table statistics."""
        import os
        db_path = Path(self.db_path)
        db_size = db_path.stat().st_size if db_path.exists() else 0
        wal_path = Path(str(self.db_path) + "-wal")
        wal_size = wal_path.stat().st_size if wal_path.exists() else 0

        tables = {}
        for table in ["alerts", "triage", "correlations", "incidents",
                       "clusters", "audit_log", "assets", "known_devices",
                       "silence_rules", "ip_reputation", "dhcp_history"]:
            try:
                cursor = await self._db.execute(f"SELECT COUNT(*) FROM {table}")
                row = await cursor.fetchone()
                tables[table] = row[0] if row else 0
            except Exception:
                tables[table] = 0

        return {
            "db_size_bytes": db_size,
            "db_size_mb": round(db_size / (1024 * 1024), 2),
            "wal_size_bytes": wal_size,
            "wal_size_mb": round(wal_size / (1024 * 1024), 2),
            "tables": tables,
        }

    # ── DHCP Lease History ─────────────────────────────────────

    async def upsert_dhcp_lease(self, ip: str, mac: str, hostname: str = "",
                                 interface: str = "", lease_type: str = "dynamic") -> bool:
        """Track a DHCP lease. Returns True if this is a new IP-MAC pair."""
        now = now_iso()
        cursor = await self._db.execute(
            "SELECT id FROM dhcp_history WHERE ip = ? AND mac = ?", (ip, mac)
        )
        existing = await cursor.fetchone()
        if existing:
            await self._db.execute(
                "UPDATE dhcp_history SET hostname = ?, last_seen = ?, interface = ?, "
                "lease_type = ? WHERE ip = ? AND mac = ?",
                (hostname, now, interface, lease_type, ip, mac),
            )
            await self._db.commit()
            return False
        else:
            await self._db.execute(
                "INSERT INTO dhcp_history (ip, mac, hostname, interface, lease_type, "
                "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ip, mac, hostname, interface, lease_type, now, now),
            )
            await self._db.commit()
            return True

    async def get_dhcp_history(self, ip: str = None, mac: str = None,
                                limit: int = 200) -> list[dict]:
        """Get DHCP lease history, optionally filtered by IP or MAC."""
        if ip:
            cursor = await self._db.execute(
                "SELECT * FROM dhcp_history WHERE ip = ? ORDER BY last_seen DESC LIMIT ?",
                (ip, limit),
            )
        elif mac:
            cursor = await self._db.execute(
                "SELECT * FROM dhcp_history WHERE mac = ? ORDER BY last_seen DESC LIMIT ?",
                (mac, limit),
            )
        else:
            cursor = await self._db.execute(
                "SELECT * FROM dhcp_history ORDER BY last_seen DESC LIMIT ?", (limit,)
            )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_dhcp_ip_changes(self, days: int = 7) -> list[dict]:
        """Find IPs that changed MAC address recently (possible spoofing)."""
        cursor = await self._db.execute(
            """SELECT ip, COUNT(DISTINCT mac) as mac_count,
                      GROUP_CONCAT(DISTINCT mac) as macs,
                      GROUP_CONCAT(DISTINCT hostname) as hostnames
               FROM dhcp_history
               WHERE last_seen > datetime('now', ?)
               GROUP BY ip HAVING mac_count > 1
               ORDER BY mac_count DESC""",
            (f"-{days} days",),
        )
        return [dict(row) for row in await cursor.fetchall()]

    # ── Protocol / DNS Analytics ───────────────────────────────

    async def get_protocol_distribution(self, since: str = None) -> list[dict]:
        """Get alert counts by protocol."""
        sql = "SELECT proto, COUNT(*) as count FROM alerts WHERE proto IS NOT NULL AND proto != ''"
        params = []
        if since:
            sql += " AND ingested_at > ?"
            params.append(since)
        sql += " GROUP BY proto ORDER BY count DESC LIMIT 20"
        cursor = await self._db.execute(sql, params)
        return [dict(row) for row in await cursor.fetchall()]

    async def get_port_distribution(self, since: str = None) -> list[dict]:
        """Get alert counts by destination port."""
        sql = "SELECT dst_port, COUNT(*) as count FROM alerts WHERE dst_port > 0"
        params = []
        if since:
            sql += " AND ingested_at > ?"
            params.append(since)
        sql += " GROUP BY dst_port ORDER BY count DESC LIMIT 20"
        cursor = await self._db.execute(sql, params)
        return [dict(row) for row in await cursor.fetchall()]

    async def get_category_distribution(self, since: str = None) -> list[dict]:
        """Get alert counts by category."""
        sql = "SELECT category, COUNT(*) as count FROM alerts WHERE category IS NOT NULL AND category != ''"
        params = []
        if since:
            sql += " AND ingested_at > ?"
            params.append(since)
        sql += " GROUP BY category ORDER BY count DESC LIMIT 20"
        cursor = await self._db.execute(sql, params)
        return [dict(row) for row in await cursor.fetchall()]

    async def get_source_distribution(self, since: str = None) -> list[dict]:
        """Get alert counts by source (suricata, wazuh, etc)."""
        sql = "SELECT source, COUNT(*) as count FROM alerts"
        params = []
        if since:
            sql += " WHERE ingested_at > ?"
            params.append(since)
        sql += " GROUP BY source ORDER BY count DESC"
        cursor = await self._db.execute(sql, params)
        return [dict(row) for row in await cursor.fetchall()]

    async def get_dns_analytics(self, since: str = None) -> dict:
        """Get DNS-related alert analytics (queries, DGA suspects, top domains)."""
        params = []
        time_filter = ""
        if since:
            time_filter = " AND ingested_at > ?"
            params.append(since)

        # DNS alert count
        cursor = await self._db.execute(
            f"SELECT COUNT(*) FROM alerts WHERE category LIKE '%dns%'{time_filter}",
            params,
        )
        row = await cursor.fetchone()
        dns_count = row[0] if row else 0

        # DGA suspects
        cursor = await self._db.execute(
            f"SELECT COUNT(*) FROM alerts WHERE (title LIKE '%DGA%' OR title LIKE '%DNS Query for .%' OR category LIKE '%dns%dga%'){time_filter}",
            params,
        )
        row = await cursor.fetchone()
        dga_count = row[0] if row else 0

        # Top queried domains from DNS alerts (extract from title/description)
        cursor = await self._db.execute(
            f"SELECT title, COUNT(*) as count FROM alerts WHERE category LIKE '%dns%'{time_filter} GROUP BY title ORDER BY count DESC LIMIT 15",
            params,
        )
        top_dns = [dict(r) for r in await cursor.fetchall()]

        return {
            "dns_alert_count": dns_count,
            "dga_suspect_count": dga_count,
            "top_dns_alerts": top_dns,
        }

    # ── Scheduled Reports ──────────────────────────────────────

    async def get_scheduled_reports(self) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM scheduled_reports ORDER BY created_at DESC"
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def upsert_scheduled_report(self, report_id: str, name: str,
                                        schedule: str = "daily") -> None:
        await self._db.execute(
            "INSERT INTO scheduled_reports (id, name, schedule, enabled, created_at) "
            "VALUES (?, ?, ?, 1, ?) ON CONFLICT(id) DO UPDATE SET "
            "name=excluded.name, schedule=excluded.schedule",
            (report_id, name, schedule, now_iso()),
        )
        await self._db.commit()

    async def mark_report_sent(self, report_id: str) -> None:
        await self._db.execute(
            "UPDATE scheduled_reports SET last_sent = ? WHERE id = ?",
            (now_iso(), report_id),
        )
        await self._db.commit()

    async def get_report_summary(self, hours: int = 24) -> dict:
        """Generate a summary of activity over the last N hours for email digest."""
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

        # Alert counts by severity
        cursor = await self._db.execute(
            "SELECT severity, COUNT(*) as count FROM alerts WHERE ingested_at > ? "
            "GROUP BY severity ORDER BY count DESC", (since,)
        )
        by_severity = {r["severity"]: r["count"] for r in await cursor.fetchall()}

        # Total new
        total = sum(by_severity.values())

        # Escalated
        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM alerts WHERE verdict = 'escalate' AND ingested_at > ?",
            (since,),
        )
        escalated = (await cursor.fetchone())[0]

        # New incidents
        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM incidents WHERE created_at > ?", (since,)
        )
        new_incidents = (await cursor.fetchone())[0]

        # Top alert titles
        cursor = await self._db.execute(
            "SELECT title, COUNT(*) as count FROM alerts WHERE ingested_at > ? "
            "GROUP BY title ORDER BY count DESC LIMIT 10", (since,)
        )
        top_alerts = [dict(r) for r in await cursor.fetchall()]

        # Unique source IPs
        cursor = await self._db.execute(
            "SELECT COUNT(DISTINCT src_ip) FROM alerts WHERE ingested_at > ? "
            "AND src_ip IS NOT NULL", (since,)
        )
        unique_src_ips = (await cursor.fetchone())[0]

        return {
            "period_hours": hours,
            "total_alerts": total,
            "by_severity": by_severity,
            "escalated": escalated,
            "new_incidents": new_incidents,
            "top_alerts": top_alerts,
            "unique_src_ips": unique_src_ips,
        }
