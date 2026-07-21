"""Data-source health watchdog.

shallots/health.py already has most of a real source-liveness monitor (file
growth checks, process checks, reachability checks) - but check_all() was
only ever called from the CLI by hand. A standard SIEM treats a silently
dead log source as a first-class alert (Splunk forwarder health, Elastic
Fleet agent status, Wazuh agent status); Shallots had the mechanism and
never wired it up. This module turns health.check_all() results into
Alerts on a cooldown, following the same pattern as agent_watchdog.py:
operational-health signal, not a threat - LOW severity, suppressed verdict,
recorded so it is visible without polluting the escalation ladder.
"""
from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterable
from datetime import datetime, timezone

from shallots.store.models import Alert, TriageVerdict

SOURCE_HEALTH_SIG_ID = 900_501
SOURCE_HEALTH_SIGNATURE = "source.health.stalled"

STATE_DDL = """
CREATE TABLE IF NOT EXISTS source_health_state (
    check_name TEXT PRIMARY KEY,
    last_alert_at TEXT NOT NULL,
    last_alert_id TEXT NOT NULL
);
"""


def ensure_state_table(conn: sqlite3.Connection) -> None:
    conn.executescript(STATE_DDL)
    conn.commit()


def _parse_iso(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def make_alert(check_name: str, detail: str, *, now_iso: str | None = None) -> Alert:
    ts = now_iso or datetime.now(timezone.utc).isoformat()
    a = Alert(
        timestamp=ts,
        source="shallots",
        source_ref=f"source_watchdog:{check_name}",
        severity="low",
        title=f"Data source stalled: {check_name}",
        description=f"Health check '{check_name}' has been failing: {detail}",
        category="source_health",
        signature_id=SOURCE_HEALTH_SIG_ID,
        raw=json.dumps({
            "signature": SOURCE_HEALTH_SIGNATURE,
            "check_name": check_name,
            "detail": detail,
        }),
        verdict=TriageVerdict.SUPPRESS.value,
        confidence=0.8,
        ai_reasoning="Source watchdog: health check failing (operational signal, not a threat)",
        ingested_at=ts,
    )
    a.dedup_hash = f"source-stalled:{check_name}"
    return a


def results_to_alerts(
    conn: sqlite3.Connection,
    results: Iterable[tuple[str, bool, str]],
    *,
    cooldown_seconds: int = 6 * 60 * 60,
    now: float | None = None,
) -> list[Alert]:
    """Turn health.check_all() results into Alerts, on a cooldown per check.

    A passing check clears any prior state, so a check that fails again
    later re-alerts immediately rather than staying suppressed forever.
    """
    ensure_state_table(conn)
    now = now if now is not None else time.time()
    now_iso = datetime.fromtimestamp(now, timezone.utc).isoformat()
    out: list[Alert] = []

    for name, ok, detail in results:
        if ok:
            conn.execute("DELETE FROM source_health_state WHERE check_name = ?", (name,))
            continue

        row = conn.execute(
            "SELECT last_alert_at FROM source_health_state WHERE check_name = ?",
            (name,),
        ).fetchone()
        if row:
            last_ts = _parse_iso(row[0]) or 0
            if (now - last_ts) < cooldown_seconds:
                continue

        alert = make_alert(name, detail, now_iso=now_iso)
        out.append(alert)
        conn.execute(
            """
            INSERT INTO source_health_state(check_name, last_alert_at, last_alert_id)
            VALUES (?, ?, ?)
            ON CONFLICT(check_name) DO UPDATE SET
                last_alert_at = excluded.last_alert_at,
                last_alert_id = excluded.last_alert_id
            """,
            (name, now_iso, alert.dedup_hash),
        )

    conn.commit()
    return out
