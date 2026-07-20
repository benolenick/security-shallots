import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shallots.ai.autopilot import _should_raise_squawk


def _alert(**kw):
    base = {"title": "Suspicious binary executed", "category": "exploit", "severity": "high", "verdict": "pending"}
    base.update(kw)
    return base


def test_suppressed_alert_never_squawks_even_if_critical():
    # A suppressed alert must not page the operator, even at critical severity.
    a = _alert(severity="critical", verdict="suppress")
    assert _should_raise_squawk(a, "critical", True) is False


def test_ended_abnormally_is_blocked():
    a = _alert(title="Auditd: Process ended abnormally. (Jagg)", severity="high", verdict="pending")
    assert _should_raise_squawk(a, "high", True) is False


def test_genuine_critical_still_squawks():
    a = _alert(title="HNAP command injection", category="exploit", severity="critical", verdict="pending")
    assert _should_raise_squawk(a, "critical", True) is True
