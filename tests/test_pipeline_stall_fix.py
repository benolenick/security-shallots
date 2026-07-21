"""Regression tests for the alert-pipeline stall found live on 2026-07-21:
every ingestor shares one queue feeding one serial DB-writer
(_pipeline_worker); a slow/contended insert_alert() call stalled that one
writer for up to SQLite's busy_timeout (was 30s) per failed attempt, and
because everything shares the same queue, ALL sources backed up in
lockstep - 22+ minutes with zero new alerts from anything, while the
dashboard and /api/health stayed fully responsive the whole time."""
from __future__ import annotations

from shallots.daemon import _pipeline_stall_check
from shallots.store.db import SQLITE_TIMEOUT_SECONDS


def test_busy_timeout_bounded_well_below_the_incident_value():
    # Was 30.0 - a single contended write could tie up the pipeline's only
    # consumer for up to 30s each, and lock-step backpressure meant every
    # other source froze too. Assert it stays well below that, not a
    # specific number, so a reasonable future tune doesn't break this test.
    assert SQLITE_TIMEOUT_SECONDS <= 10.0


def test_pipeline_ok_when_queue_empty_regardless_of_last_insert_age():
    # A quiet network with nothing to report is not a stall.
    ok, detail = _pipeline_stall_check(qdepth=0, stalled_sec=99999)
    assert ok is True


def test_pipeline_ok_when_recently_inserted_even_with_backlog():
    ok, detail = _pipeline_stall_check(qdepth=200, stalled_sec=5)
    assert ok is True


def test_pipeline_fails_on_backlog_plus_no_recent_insert():
    ok, detail = _pipeline_stall_check(qdepth=200, stalled_sec=300)
    assert ok is False
    assert "queue_depth=200" in detail
    assert "300s ago" in detail


def test_pipeline_ok_at_small_queue_depth_even_if_stalled():
    # A handful of queued items with no progress for a while could just be
    # normal jitter; only a genuine backlog (> threshold) should fire.
    ok, detail = _pipeline_stall_check(qdepth=3, stalled_sec=300)
    assert ok is True
