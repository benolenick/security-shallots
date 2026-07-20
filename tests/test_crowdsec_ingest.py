"""CrowdSec ingest behavior tests."""

from __future__ import annotations

import asyncio

from shallots.config import CrowdSecConfig
from shallots.ingest.crowdsec import CrowdSecIngestor


class FakeResponse:
    status = 200

    def __init__(self, decisions: list[dict]):
        self._decisions = decisions

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def json(self):
        return self._decisions


class FakeSession:
    def __init__(self, decisions: list[dict]):
        self.decisions = decisions

    def get(self, *args, **kwargs):
        return FakeResponse(self.decisions)


def test_seed_existing_decisions_marks_active_ids_without_queueing() -> None:
    queue: asyncio.Queue = asyncio.Queue()
    ingestor = CrowdSecIngestor(CrowdSecConfig(), queue)

    asyncio.run(ingestor._seed_existing_decisions(FakeSession([{"id": 1}, {"id": 2}])))

    assert ingestor._seen_decision_ids == {"1", "2"}
    assert queue.empty()


def test_poll_skips_seen_decisions_and_enqueues_new() -> None:
    queue: asyncio.Queue = asyncio.Queue()
    ingestor = CrowdSecIngestor(CrowdSecConfig(), queue)
    ingestor._last_poll = "2026-07-18T22:00:00+00:00"
    ingestor._seen_decision_ids = {"1"}
    decisions = [
        {"id": 1, "type": "ban", "value": "1.1.1.1", "scope": "Ip"},
        {"id": 2, "type": "ban", "value": "2.2.2.2", "scope": "Ip", "origin": "local"},
    ]

    asyncio.run(ingestor._poll(FakeSession(decisions)))

    assert queue.qsize() == 1
    assert ingestor._seen_decision_ids == {"1", "2"}


def test_capi_decisions_are_not_enqueued_as_alerts() -> None:
    queue: asyncio.Queue = asyncio.Queue()
    ingestor = CrowdSecIngestor(CrowdSecConfig(), queue)
    ingestor._last_poll = "2026-07-18T22:00:00+00:00"
    decisions = [
        {"id": 3, "type": "ban", "value": "3.3.3.3", "scope": "Ip", "origin": "CAPI"},
    ]

    asyncio.run(ingestor._poll(FakeSession(decisions)))

    assert queue.empty()
    assert ingestor._seen_decision_ids == {"3"}
