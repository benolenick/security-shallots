"""Systemd unit contract tests for operational timers."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_alert_assessment_timer_runs_gate_watch_before_production_gate() -> None:
    unit = (ROOT / "setup" / "systemd" / "shallot-alert-assess.service").read_text()

    gate_watch = unit.index("tools/shallot_gate_watch.py")
    production_gate = unit.index("tools/shallot_production_gate.py")
    self_assess = unit.index("tools/shallot_self_assess.py")
    fleet_top = unit.index("tools/shallot_fleet_top.py")

    assert gate_watch < production_gate
    assert production_gate < self_assess < fleet_top
    assert "tools/shallot_gate_watch.py || true" in unit
    assert "tools/shallot_self_assess.py || true" in unit


def test_alert_assessment_timer_uses_bounded_operator_output() -> None:
    unit = (ROOT / "setup" / "systemd" / "shallot-alert-assess.service").read_text()

    assert "tools/shallot_alert_assess.py --hours 1 --summary-json" in unit
    assert "tools/shallot_syslog_canary.py --timeout 30" in unit
    assert "tools/shallot_self_assess.py" in unit
    assert "tools/shallot_fleet_top.py --compact-json" in unit
    assert "tools/shallot_alert_assess.py --hours 1;" not in unit
    assert "tools/shallot_fleet_top.py; }" not in unit
    assert "tools/shallot_fleet_top.py --summary-json; }" not in unit
