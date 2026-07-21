"""Regression tests for the correlation-dedup bug found live on 2026-07-20/21:

Round 1: the same ongoing bash->203.0.113.9:4444 event generated 10
duplicate incidents in under an hour because dedup keyed on
pattern + AI-reworded summary text[:80], which almost never matched
itself twice.

Round 2: even after keying on a deterministic src/dst IP+port signature,
two MORE duplicates appeared for the exact same two alerts, because they
were host-local auditd exec captures with empty src_ip/dst_ip columns -
every such alert's IP signature was trivially "", so the (still-varying)
AI pattern label was all that was left to key on. Fixed by falling back
to the sorted alert IDs themselves when there's no IP data, and by
dropping pattern from the dedup key entirely."""
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
    assert _entity_signature([], {}) == "ids:"


def test_host_local_alerts_with_no_ip_data_fall_back_to_alert_ids():
    # auditd/execmon command captures never populate src_ip/dst_ip.
    alerts_by_id = {"a1": {"src_ip": "", "dst_ip": "", "dst_port": 0}}
    sig = _entity_signature(["a1"], alerts_by_id)
    assert sig == "ids:a1"


def test_same_host_local_alerts_recur_to_the_same_signature():
    alerts_by_id = {
        "a1": {"src_ip": "", "dst_ip": "", "dst_port": 0},
        "a2": {"src_ip": "", "dst_ip": "", "dst_port": 0},
    }
    sig1 = _entity_signature(["a1", "a2"], alerts_by_id)
    sig2 = _entity_signature(["a2", "a1"], alerts_by_id)
    assert sig1 == sig2 == "ids:a1|a2"


def test_different_host_local_alert_sets_differ():
    alerts_by_id = {
        "a1": {"src_ip": "", "dst_ip": "", "dst_port": 0},
        "a2": {"src_ip": "", "dst_ip": "", "dst_port": 0},
    }
    assert _entity_signature(["a1"], alerts_by_id) != _entity_signature(["a2"], alerts_by_id)
