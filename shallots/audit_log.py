"""Append-only audit log.

Records who did what, when, against which target, with optional details.
Used by the web API to log state-changing operations (acks, suppressions,
restarts), and by the CLI for token lifecycle events.

Append-only is enforced at the schema level: rows are never updated or
deleted by the application. (A future retention policy may delete rows
older than N days; that path is gated behind explicit operator action.)

Usage::

    from shallots.audit_log import AuditLog
    audit = AuditLog(conn)
    audit.record(
        principal="alice",
        action="alert.ack",
        target_type="alert",
        target_id="abc123",
        ip="10.0.0.5",
        details={"note": "false positive"},
    )
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

AUDIT_LOG_DDL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    principal TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_principal ON audit_log(principal);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_type, target_id);
"""


@dataclass(frozen=True)
class AuditEntry:
    id: int
    ts: str
    principal: str
    action: str
    target_type: str
    target_id: str
    ip: str
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_row(cls, row: sqlite3.Row | tuple) -> AuditEntry:
        if isinstance(row, sqlite3.Row):
            return cls(
                id=row["id"],
                ts=row["ts"],
                principal=row["principal"],
                action=row["action"],
                target_type=row["target_type"],
                target_id=row["target_id"],
                ip=row["ip"],
                details=json.loads(row["details_json"] or "{}"),
            )
        # Tuple fallback
        return cls(
            id=row[0],
            ts=row[1],
            principal=row[2],
            action=row[3],
            target_type=row[4],
            target_id=row[5],
            ip=row[6],
            details=json.loads(row[7] or "{}"),
        )


class AuditLog:
    """Thin wrapper around the audit_log table."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(AUDIT_LOG_DDL)
        self.conn.commit()

    def record(
        self,
        *,
        principal: str,
        action: str,
        target_type: str = "",
        target_id: str = "",
        ip: str = "",
        details: dict[str, Any] | None = None,
        ts: str | None = None,
    ) -> int:
        """Append an audit entry. Returns the new row id."""
        if not principal:
            raise ValueError("principal is required")
        if not action:
            raise ValueError("action is required")
        ts = ts or datetime.now(timezone.utc).isoformat()
        cur = self.conn.execute(
            """
            INSERT INTO audit_log(ts, principal, action, target_type, target_id, ip, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                principal,
                action,
                target_type,
                target_id,
                ip,
                json.dumps(details or {}, sort_keys=True),
            ),
        )
        self.conn.commit()
        return cur.lastrowid or 0

    def query(
        self,
        *,
        principal: str | None = None,
        action: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Query entries with optional filters. Newest first."""
        clauses: list[str] = []
        params: list[Any] = []
        if principal:
            clauses.append("principal = ?")
            params.append(principal)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if target_type:
            clauses.append("target_type = ?")
            params.append(target_type)
        if target_id:
            clauses.append("target_id = ?")
            params.append(target_id)
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if until:
            clauses.append("ts <= ?")
            params.append(until)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"""
            SELECT id, ts, principal, action, target_type, target_id, ip, details_json
            FROM audit_log
            {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """
        params.extend([int(limit), int(offset)])
        rows = self.conn.execute(sql, params).fetchall()
        return [AuditEntry.from_row(r) for r in rows]

    def count(self, **filters: Any) -> int:
        """Count entries matching the same filters as ``query``."""
        # Reuse query without limit by hand-rolling a count
        clauses: list[str] = []
        params: list[Any] = []
        for k in ("principal", "action", "target_type", "target_id"):
            v = filters.get(k)
            if v:
                clauses.append(f"{k} = ?")
                params.append(v)
        if filters.get("since"):
            clauses.append("ts >= ?")
            params.append(filters["since"])
        if filters.get("until"):
            clauses.append("ts <= ?")
            params.append(filters["until"])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        row = self.conn.execute(
            f"SELECT count(*) FROM audit_log {where}", params
        ).fetchone()
        return int(row[0])
