"""Regression tests for the 2026-07-20 security hardening pass."""
from __future__ import annotations

import types

import pytest

from shallots.pipeline.classifier import Classifier
from shallots.store.models import Alert, TriageVerdict


# --- Exposure guard: no unauthenticated LAN-exposed dashboard --------------

def _fake_daemon(host, user, pw):
    web = types.SimpleNamespace(username=user, password=pw, host=host)
    cfg = types.SimpleNamespace(web=web)
    return types.SimpleNamespace(cfg=cfg)


def test_create_app_refuses_exposed_without_auth():
    from shallots.web.app import create_app
    with pytest.raises(RuntimeError, match="Refusing to start"):
        create_app(_fake_daemon("0.0.0.0", "", ""))


def test_create_app_allows_loopback_without_auth():
    # Should not raise on the exposure guard for loopback (may fail later on
    # route setup with a bare fake daemon — we only assert the guard passes).
    from shallots.web.app import create_app
    try:
        create_app(_fake_daemon("127.0.0.1", "", ""))
    except RuntimeError as e:
        assert "Refusing to start" not in str(e)
    except Exception:
        pass  # later route-setup failure is fine; the guard did not fire


# --- Classifier must not suppress real attack signatures -------------------

def _alert(title):
    return Alert(source="suricata", severity="high", title=title,
                 src_ip="203.0.113.9", dst_ip="192.168.1.10", category="ET WEB_SERVER")


def test_classifier_does_not_suppress_rce_or_bruteforce():
    for title in (
        "ET WEB_SERVER PHP Remote Code Execution",
        "ET WEB_SERVER Wordpress Login Brute Force",
        "ET SCAN Nmap Scripting Engine",
    ):
        out = Classifier().classify(_alert(title))
        assert out.verdict != TriageVerdict.SUPPRESS, f"{title} must not be title-suppressed"


def test_classifier_still_suppresses_benign_noise():
    out = Classifier().classify(_alert("LLMNR query"))
    assert out.verdict == TriageVerdict.SUPPRESS


# --- Clove ingest: field fallback + IP validation --------------------------

def test_valid_ip_helper():
    from shallots.web.api.agents import _valid_ip
    assert _valid_ip("192.168.1.5") == "192.168.1.5"
    assert _valid_ip("2001:db8::1") == "2001:db8::1"
    assert _valid_ip("'><script>alert(1)</script>") == ""
    assert _valid_ip("not-an-ip") == ""
    assert _valid_ip("") == ""


# --- Argus webhook verifies TLS by default ---------------------------------

def test_argus_webhook_verifies_tls_by_default():
    try:
        from argus.argus.sinks.webhook import WebhookSink
    except ModuleNotFoundError:
        from argus.sinks.webhook import WebhookSink  # when argus/ is on sys.path
    s = WebhookSink(enabled=True, url="https://manager.example:8855/api/ingest/argus", secret="x")
    assert s.verify_tls is True
    s2 = WebhookSink(enabled=True, url="https://m:8855/x", secret="x", verify_tls=False)
    assert s2.verify_tls is False


# --- DB write coerces untrusted IP fields (XSS defense-in-depth) -----------

@pytest.mark.asyncio
async def test_insert_alert_coerces_bad_ip(tmp_db):
    a = Alert(source="clove", severity="high", title="x",
              src_ip="'><img src=x onerror=alert(1)>", dst_ip="10.0.0.1")
    await tmp_db.insert_alert(a)
    got = await tmp_db.get_alert(a.id)
    assert got["src_ip"] == ""            # markup stripped
    assert got["dst_ip"] == "10.0.0.1"    # valid IP preserved


# --- DNS-rebinding / Host guard (round 2) ----------------------------------

def test_host_only_strips_port():
    from shallots.web.app import _host_only
    assert _host_only("127.0.0.1:8844") == "127.0.0.1"
    assert _host_only("[::1]:8844") == "::1"
    assert _host_only("evil.example.com:8844") == "evil.example.com"
    assert _host_only("192.168.1.5") == "192.168.1.5"


@pytest.mark.asyncio
async def test_host_guard_blocks_rebinding_domain():
    from shallots.web.app import _make_host_guard
    guard = _make_host_guard({"shallots.mylan"})

    async def ok_handler(_req):
        return "PASSED"

    def req(host):
        return types.SimpleNamespace(headers={"Host": host})

    # IP-literal Host can't be a rebinding attack → allowed
    assert await guard(req("127.0.0.1:8844"), ok_handler) == "PASSED"
    assert await guard(req("192.168.1.50:8844"), ok_handler) == "PASSED"
    assert await guard(req("localhost"), ok_handler) == "PASSED"
    assert await guard(req("shallots.mylan"), ok_handler) == "PASSED"   # allow-listed
    # An unexpected domain (DNS-rebinding) is rejected 403
    resp = await guard(req("attacker.example.com"), ok_handler)
    assert getattr(resp, "status", None) == 403


# --- Category silence suppresses by verdict, not by corrupting severity -----

def test_category_silence_suppresses_without_corrupting_severity():
    from shallots.pipeline.classifier import Classifier, ClassifierConfig
    cfg = ClassifierConfig()
    cfg.suppress_categories.append("ET DELETED")
    clf = Classifier(cfg)
    out = clf.classify(Alert(source="suricata", severity="high",
                             title="Some alert", category="ET DELETED noise"))
    assert out.verdict == TriageVerdict.SUPPRESS
    assert out.severity == "high"          # severity NOT overwritten to "suppress"


# --- AI silence-rule guard refuses to hide real threats --------------------

@pytest.mark.asyncio
async def test_ai_silence_guard_flags_high_severity_match(tmp_db):
    from shallots.web.api.rules import _rule_hits_high_severity
    await tmp_db.insert_alert(Alert(source="suricata", severity="critical",
                                    title="ET EXPLOIT something", src_ip="203.0.113.9"))
    # A title rule that would bury the critical alert must be flagged
    assert await _rule_hits_high_severity(tmp_db, "title", "ET EXPLOIT", "") is True
    # A rule matching nothing high/critical is fine
    assert await _rule_hits_high_severity(tmp_db, "title", "totally-benign-xyz", "") is False
