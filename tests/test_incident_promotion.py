"""Regression tests for local (ladder-free) deterministic incident promotion."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from shallots.ai.incidents import IncidentWorker


class _FakeDB:
    """Minimal async AlertDB stand-in for the deterministic-escalation path."""

    def __init__(self, esc_rows, cluster_alerts, existing_keys=None,
                 clusters_with_incidents=None):
        self._esc_rows = esc_rows
        self._cluster_alerts = cluster_alerts
        self._existing = existing_keys or set()
        self._clusters_with_incidents = set(clusters_with_incidents or set())
        self.inserted = []
        self.events = []
        self.audits = []

    async def get_existing_incident_keys(self):
        return set(self._existing)

    async def execute_sql(self, sql, params=()):
        if "verdict = 'escalate'" in sql:
            return list(self._esc_rows)
        if "FROM incidents WHERE cluster_ids LIKE" in sql:
            like = params[0].strip("%")  # '"c-1"'
            cid = like.strip('"')
            return [{"1": 1}] if cid in self._clusters_with_incidents else []
        return []

    async def get_cluster_alerts(self, cluster_id, limit=100):
        return list(self._cluster_alerts.get(cluster_id, []))

    async def get_ip_reputation(self, ip):
        return None

    async def get_pattern_history(self, pattern_key, limit=20):
        return []

    async def insert_incident(self, incident):
        iid = f"iid-{len(self.inserted)}"
        self.inserted.append((iid, incident))
        return iid

    async def add_incident_event(self, iid, event_type, description, detail="", actor="system"):
        self.events.append((iid, event_type, description))
        return len(self.events)

    async def insert_audit(self, *a, **k):
        self.audits.append(a)


def _cfg():
    # tier="none" -> no Ollama client, uses rule-based incident generation (no GPU in tests)
    return SimpleNamespace(tier="none", ollama_url=None, ollama_model="granite3.3:8b")


def _worker(db):
    return IncidentWorker(_cfg(), db, ws_broadcast=None, alerter=None)


def test_deterministic_escalation_creates_incident():
    esc = [{"cluster_id": "c-1", "c": 2, "last_seen": "2026-07-19T00:00:00+00:00"}]
    alerts = {"c-1": [
        {"id": "a1", "title": "Protected file changed", "src_ip": "", "dst_ip": "",
         "verdict": "escalate", "severity": "high"},
        {"id": "a2", "title": "Protected file changed", "src_ip": "", "dst_ip": "",
         "verdict": "escalate", "severity": "high"},
    ]}
    db = _FakeDB(esc, alerts)
    asyncio.run(_worker(db)._scan_deterministic_escalations(set()))
    assert len(db.inserted) == 1
    iid, inc = db.inserted[0]
    assert inc["cluster_ids"] == ["c-1"]
    assert inc["alert_ids"] == ["a1", "a2"]
    assert inc["severity"] in ("high", "critical")  # deterministic -> never lands low
    assert any(e[1] == "created" for e in db.events)  # timeline seeded


def test_dedup_skips_already_linked_cluster():
    esc = [{"cluster_id": "c-1", "c": 1, "last_seen": "2026-07-19T00:00:00+00:00"}]
    alerts = {"c-1": [{"id": "a1", "title": "x", "verdict": "escalate"}]}
    db = _FakeDB(esc, alerts, existing_keys={"cluster:c-1"})
    # Pass the same existing set the scan would receive.
    asyncio.run(_worker(db)._scan_deterministic_escalations({"cluster:c-1"}))
    assert db.inserted == []


def test_no_repromotion_of_resolved_cluster():
    """A resolved incident's cluster must not be re-promoted (alerts stay escalate)."""
    esc = [{"cluster_id": "c-1", "c": 2, "last_seen": "2026-07-19T00:00:00+00:00"}]
    alerts = {"c-1": [{"id": "a1", "title": "Protected file changed", "verdict": "escalate"}]}
    # existing_keys is empty (resolved incidents are excluded from it), but the
    # cluster already has an incident on record -> must still be skipped.
    db = _FakeDB(esc, alerts, existing_keys=set(), clusters_with_incidents={"c-1"})
    asyncio.run(_worker(db)._scan_deterministic_escalations(set()))
    assert db.inserted == []


def test_per_cycle_cap_bounds_creation():
    esc = [{"cluster_id": f"c-{i}", "c": 1, "last_seen": "2026-07-19T00:00:00+00:00"}
           for i in range(12)]
    alerts = {f"c-{i}": [{"id": f"a{i}", "title": "Protected file changed", "verdict": "escalate"}]
              for i in range(12)}
    db = _FakeDB(esc, alerts)
    asyncio.run(_worker(db)._scan_deterministic_escalations(set()))
    assert len(db.inserted) == 5  # _MAX_INCIDENTS_PER_CYCLE
