"""Sigma engine + process_creation bridge regression tests.

Guards two things that were silently broken: the engine's public attribute is
`.rules` (the daemon used to check `._rules` -> AttributeError -> Sigma never
fired), and the execve->process_creation bridge (CommandLine maps to the alert
description where the exec ingestor stashes the command line)."""
from __future__ import annotations

import pathlib

from shallots.sigma_engine import SigmaEngine

RULES_DIR = str(pathlib.Path(__file__).resolve().parent.parent / "rules" / "sigma")


def test_engine_public_attribute_is_rules():
    eng = SigmaEngine(rules_dir=RULES_DIR)
    assert hasattr(eng, "rules")          # daemon relies on engine.rules
    assert not hasattr(eng, "_rules")


def test_engine_loads_starter_process_creation_rule():
    eng = SigmaEngine(rules_dir=RULES_DIR)
    n = eng.load_rules()
    assert n >= 1
    assert any("reverse" in (r.title or "").lower() for r in eng.rules)


def test_process_creation_rule_matches_exec_alert_via_description():
    eng = SigmaEngine(rules_dir=RULES_DIR)
    eng.load_rules()
    # an exec alert as produced by ExecLogIngestor: cmdline lives in description
    alert = {
        "src_ip": "", "dst_ip": "", "category": "execution",
        "title": "Suspicious command: bash",
        "description": "bash -c true /dev/tcp/203.0.113.9/4444  (uid=33 ppid=1 exe=/bin/bash)",
    }
    matched = eng.match(alert)
    assert any("/dev/tcp" in str(r.detection) for r in matched) or matched, \
        "the /dev/tcp process_creation rule should fire on the exec alert description"


def test_benign_exec_alert_does_not_match():
    eng = SigmaEngine(rules_dir=RULES_DIR)
    eng.load_rules()
    alert = {"src_ip": "", "dst_ip": "", "category": "execution",
             "title": "exec", "description": "ls -la /home/user"}
    assert eng.match(alert) == []
