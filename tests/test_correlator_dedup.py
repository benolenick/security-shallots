"""Regression test for the correlation-dedup bug found live on 2026-07-20:
the same ongoing bash->203.0.113.9:4444 event generated 10 duplicate
incidents in under an hour because dedup keyed on AI-reworded summary
text[:80], which almost never matched itself twice."""
from __future__ import annotations

from shallots.ai.correlator import _entity_signature


def test_same_entities_produce_the_same_signature_regardless_of_order():
    alerts_by_id = {
        "a1": {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "dst_port": 4444},
        "a2": {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "dst_port": 4444},
    }
    sig1 = _entity_signature(["a1", "a2"], alerts_by_id)
    sig2 = _entity_signature(["a2", "a1"], alerts_by_id)
    assert sig1 == sig2
    assert "10.0.0.5>203.0.113.9:4444" in sig1


def test_different_entities_produce_different_signatures():
    alerts_by_id = {
        "a1": {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "dst_port": 4444},
        "a2": {"src_ip": "10.0.0.6", "dst_ip": "203.0.113.9", "dst_port": 4444},
    }
    sig1 = _entity_signature(["a1"], alerts_by_id)
    sig2 = _entity_signature(["a2"], alerts_by_id)
    assert sig1 != sig2


def test_missing_alert_ids_are_skipped_not_erroring():
    alerts_by_id = {"a1": {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "dst_port": 4444}}
    sig = _entity_signature(["a1", "missing"], alerts_by_id)
    assert sig == "10.0.0.5>203.0.113.9:4444"


def test_empty_alert_ids_gives_empty_signature():
    assert _entity_signature([], {}) == ""
