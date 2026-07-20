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
