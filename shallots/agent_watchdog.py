"""Agent-offline watchdog.

Detects Argus / Clove / Wazuh agents that have stopped sending heartbeats and
emits an `agent.offline.heartbeat_lost` alert per agent. Dedupes via an
``agent_alert_state`` row so a single offline agent fires once, not on every
poll cycle.

Designed to be called periodically from ``daemon.py``::

    while running:
        await asyncio.sleep(300)
        for alert in await detect_offline_agents(db_conn, cfg):
            await pipeline.handle(alert)

The module is intentionally pure-ish: it queries via an injected DB callable
so tests can pass an in-memory connection.
"""
from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from shallots.store.models import Alert, AlertSource, Severity, TriageVerdict

# Default thresholds in seconds. Argus is heavyweight + Windows, Clove is
# lightweight + Linux; Argus may legitimately go quiet a little longer.
DEFAULT_THRESHOLDS = {
    "argus": 60 * 60,   # 60 minutes
    "clove": 30 * 60,   # 30 minutes
    "wazuh": 30 * 60,   # 30 minutes
}

AGENT_OFFLINE_SIG_ID = 900_500
AGENT_OFFLINE_SIGNATURE = "agent.offline.heartbeat_lost"


@dataclass(frozen=True)
class OfflineAgent:
    name: str
    kind: str
    last_seen: str  # ISO timestamp
    age_seconds: int


WATCHDOG_STATE_DDL = """
CREATE TABLE IF NOT EXISTS agent_alert_state (
    agent_name TEXT PRIMARY KEY,
    last_offline_alert_at TEXT NOT NULL,
    last_offline_alert_id TEXT NOT NULL
);
"""


def ensure_state_table(conn: sqlite3.Connection) -> None:
    conn.executescript(WATCHDOG_STATE_DDL)
    conn.commit()


def _parse_iso(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        # Accept Z or offset
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _query_agents(conn: sqlite3.Connection) -> list[tuple[str, str, str | None]]:
    """Return list of (agent_name, agent_type, last_seen_iso) from both tables.

    `agent_status.last_heartbeat` and `agent_heartbeats.last_seen` are the two
    sources of truth in the schema today.
    """
    rows: list[tuple[str, str, str | None]] = []
    for sql in (
        "SELECT agent_name, COALESCE(agent_type,'unknown'), last_heartbeat FROM agent_status",
        "SELECT agent_name, COALESCE(agent_type,'unknown'), last_seen FROM agent_heartbeats",
    ):
        try:
            for r in conn.execute(sql):
                rows.append((r[0], r[1] or "unknown", r[2]))
        except sqlite3.OperationalError:
            # Table missing in this DB - fine, the other source may have it.
            continue
    return rows


def detect_offline_agents(
    conn: sqlite3.Connection,
    *,
    thresholds: dict[str, int] | None = None,
    now: float | None = None,
) -> list[OfflineAgent]:
    """Return agents whose heartbeat is older than the threshold for their kind."""
    thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    now = now if now is not None else time.time()

    seen: dict[str, OfflineAgent] = {}
    for name, kind, last_seen in _query_agents(conn):
        ts = _parse_iso(last_seen)
        if ts is None:
            # Unknown last_seen - treat as offline at age 0 for surfacing once
            seen[name] = OfflineAgent(name=name, kind=kind, last_seen="", age_seconds=0)
            continue
        age = int(now - ts)
        threshold = thresholds.get(kind.lower(), thresholds.get("clove", 1800))
        if age >= threshold:
            existing = seen.get(name)
            if existing is None or age > existing.age_seconds:
                seen[name] = OfflineAgent(
                    name=name, kind=kind, last_seen=last_seen, age_seconds=age
                )
    return sorted(seen.values(), key=lambda a: a.name)


def make_alert(agent: OfflineAgent, *, now_iso: str | None = None) -> Alert:
    ts = now_iso or datetime.now(timezone.utc).isoformat()
    minutes = agent.age_seconds // 60
    desc = (
        f"No heartbeat received from {agent.kind} agent '{agent.name}' for "
        f"{minutes} minutes (last_seen={agent.last_seen or 'never'})."
    )
    a = Alert(
        timestamp=ts,
        source=AlertSource.ARGUS.value if agent.kind.lower() == "argus" else "agent",
        source_ref=f"watchdog:{agent.name}",
        # Agent-offline is an operational-health signal, not a threat. It belongs
        # in the agent-health view, not screaming up the escalation ladder - a
        # HIGH/ESCALATE here buries real criticals (esp. with flaky/test agents).
        # LOW + SUPPRESS keeps it recorded without polluting the threat pipeline.
        # (Future: elevate for a whitelist of critical security agents - an EDR
        #  going dark mid-attack IS worth escalating.)
        severity=Severity.LOW.value,
        title=f"Agent offline: {agent.name}",
        description=desc,
        src_asset=agent.name,
        category="agent_health",
        signature_id=AGENT_OFFLINE_SIG_ID,
        raw=json.dumps(
            {
                "signature": AGENT_OFFLINE_SIGNATURE,
                "agent_name": agent.name,
                "agent_kind": agent.kind,
                "last_seen": agent.last_seen,
                "age_seconds": agent.age_seconds,
            }
        ),
        verdict=TriageVerdict.SUPPRESS.value,
        confidence=0.8,
        ai_reasoning="Agent watchdog: heartbeat threshold exceeded (health signal, not threat)",
        ingested_at=ts,
    )
    a.dedup_hash = f"agent-offline:{agent.name}"
    return a


def offline_alerts_to_emit(
    conn: sqlite3.Connection,
    offline: Iterable[OfflineAgent],
    *,
    cooldown_seconds: int = 6 * 60 * 60,
    now: float | None = None,
) -> list[Alert]:
    """Return Alert objects for offline agents, suppressing duplicates within
    ``cooldown_seconds`` of the previous alert.

    Updates ``agent_alert_state`` so subsequent calls skip the same agent
    until the cooldown elapses. When the agent comes back online, the caller
    is expected to delete the state row (see ``mark_recovered``).
    """
    ensure_state_table(conn)
    now = now if now is not None else time.time()
    now_iso = datetime.fromtimestamp(now, timezone.utc).isoformat()
    out: list[Alert] = []
    for a in offline:
        row = conn.execute(
            "SELECT last_offline_alert_at FROM agent_alert_state WHERE agent_name = ?",
            (a.name,),
        ).fetchone()
        if row:
            last_ts = _parse_iso(row[0]) or 0
            if (now - last_ts) < cooldown_seconds:
                continue
        alert = make_alert(a, now_iso=now_iso)
        out.append(alert)
        conn.execute(
            """
            INSERT INTO agent_alert_state(agent_name, last_offline_alert_at, last_offline_alert_id)
            VALUES (?, ?, ?)
            ON CONFLICT(agent_name) DO UPDATE SET
                last_offline_alert_at = excluded.last_offline_alert_at,
                last_offline_alert_id = excluded.last_offline_alert_id
            """,
            (a.name, now_iso, alert.dedup_hash),
        )
    conn.commit()
    return out


def mark_recovered(conn: sqlite3.Connection, agent_name: str) -> None:
    """Clear watchdog state when an agent's heartbeat returns."""
    ensure_state_table(conn)
    conn.execute("DELETE FROM agent_alert_state WHERE agent_name = ?", (agent_name,))
    conn.commit()
