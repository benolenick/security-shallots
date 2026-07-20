"""No-AI / Pi mode: the rule-based disposition must give every pending alert a
final verdict (never leave it pending) so a GPU-less deployment still works."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shallots.ai.triage import _rule_based_verdict
from shallots.store.models import TriageVerdict


def _a(**kw):
    base = {"title": "x", "category": "", "severity": "medium", "src_ip": ""}
    base.update(kw); return base


def test_critical_escalates():
    v, _, _ = _rule_based_verdict(_a(severity="critical", title="unknown exploit"))
    assert v == TriageVerdict.ESCALATE

def test_high_investigates():
    v, _, _ = _rule_based_verdict(_a(severity="high", title="odd thing"))
    assert v == TriageVerdict.INVESTIGATE

def test_low_suppresses():
    v, _, _ = _rule_based_verdict(_a(severity="low", title="informational"))
    assert v == TriageVerdict.SUPPRESS

def test_internal_lan_low_medium_suppressed():
    v, _, _ = _rule_based_verdict(_a(severity="medium", src_ip="192.168.0.50", title="chatter"))
    assert v == TriageVerdict.SUPPRESS

def test_medium_external_investigates():
    v, _, _ = _rule_based_verdict(_a(severity="medium", src_ip="8.8.8.8", title="unknown"))
    assert v == TriageVerdict.INVESTIGATE

def test_never_returns_pending():
    # The whole point of no-AI mode: nothing is left pending.
    for sev in ("low", "medium", "high", "critical"):
        for ip in ("", "192.168.0.5", "1.2.3.4"):
            v, _, _ = _rule_based_verdict(_a(severity=sev, src_ip=ip))
            assert v != TriageVerdict.PENDING and v is not None
