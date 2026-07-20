"""Alert assessment volume guardrail tests."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

from shallots.config import Config
from tools import shallot_alert_assess
from tools.shallot_alert_assess import (
    alert_rate_baseline,
    assess_rows,
    expected_log_source_health,
    network_coverage_summary,
    network_source_health,
    suppression_quality,
    summary_json,
    synthetic_residue_text,
    synthetic_residue_warnings,
    volume_rows_for_text,
)


class Row(dict):
    def __getitem__(self, key):
        return self.get(key)


def _row(host: str, *, verdict: str = "pending", title: str = "Routine", severity: str = "low") -> Row:
    return Row(
        id=f"{host}-{title}-{verdict}",
        timestamp="2026-07-15T00:00:00+00:00",
        source="argus",
        source_ref="session_alert",
        severity=severity,
        title=title,
        description="",
        category="session",
        src_asset=host,
        src_ip="",
        verdict=verdict,
    )


def _timed_row(ts: str, *, host: str = "host02", verdict: str = "pending") -> Row:
    row = _row(host, verdict=verdict)
    row["timestamp"] = ts
    return row


def test_volume_by_host_counts_suppressed_without_making_it_visible() -> None:
    summary = assess_rows(
        [
            _row("host02", verdict="suppress"),
            _row("host02", verdict="suppress"),
            _row("host03", verdict="pending"),
        ],
        hours=24,
    )

    assert summary["raw_alerts"] == 3
    assert summary["visible_non_synthetic"] == 1
    assert summary["volume_by_host"] == [
        {
            "host": "host02",
            "raw": 2,
            "visible": 0,
            "suppressed": 2,
            "suppressed_non_synthetic": 2,
            "synthetic_or_experiment": 0,
            "raw_per_day": 2.0,
            "visible_per_day": 0.0,
            "suppressed_non_synthetic_per_day": 2.0,
        },
        {
            "host": "host03",
            "raw": 1,
            "visible": 1,
            "suppressed": 0,
            "suppressed_non_synthetic": 0,
            "synthetic_or_experiment": 0,
            "raw_per_day": 1.0,
            "visible_per_day": 1.0,
            "suppressed_non_synthetic_per_day": 0.0,
        },
    ]
    assert summary["suppressed_non_synthetic"] == 2
    assert summary["top_suppressed_non_synthetic_titles"] == [
        {
            "source": "argus",
            "severity": "low",
            "title": "Routine",
            "asset": "host02",
            "count": 2,
        }
    ]


def test_alert_rate_baseline_is_clean_for_quiet_current_hour() -> None:
    now = datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc)
    rows = [
        _timed_row("2026-07-15T07:05:00+00:00"),
        _timed_row("2026-07-15T06:05:00+00:00"),
        _timed_row("2026-07-15T05:05:00+00:00"),
    ]

    baseline = alert_rate_baseline(rows, now=now)

    assert baseline["current"] == {"raw": 0, "real_raw": 0, "actionable": 0, "visible": 0}
    assert baseline["quiet_streak_hours"] == {"raw": 1, "real_raw": 1, "actionable": 1, "visible": 1}
    assert baseline["adaptive_thresholds"]["visible"]["exceeded"] is False
    assert baseline["warnings"] == []


def test_alert_rate_baseline_reports_full_quiet_streak_without_rows() -> None:
    now = datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc)

    baseline = alert_rate_baseline([], now=now)

    assert baseline["quiet_streak_hours"] == {"raw": 25, "real_raw": 25, "actionable": 25, "visible": 25}
    assert {item["host"] for item in baseline["per_host"]} == {"host01", "host03", "host04", "host02"}
    assert all(item["current"]["raw"] == 0 for item in baseline["per_host"])


def test_alert_rate_baseline_quiet_streak_ignores_synthetic_for_real_counts() -> None:
    now = datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc)
    synthetic = _timed_row("2026-07-15T07:05:00+00:00", host="shallot-load-webhook")
    synthetic["description"] = "synthetic"
    real = _timed_row("2026-07-15T06:05:00+00:00", host="host02")

    baseline = alert_rate_baseline([synthetic, real], now=now)

    assert baseline["quiet_streak_hours"] == {"raw": 1, "real_raw": 2, "actionable": 2, "visible": 2}


def test_alert_rate_baseline_actionable_ignores_trusted_false_positive_suppression() -> None:
    now = datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc)
    trusted = _timed_row("2026-07-15T08:05:00+00:00", host="host04", verdict="suppress")
    trusted["title"] = "Suspicious outbound connection"
    trusted["source_ref"] = "network_egress_suspicious"
    trusted["category"] = "c2"
    trusted["severity"] = "high"
    trusted["ai_reasoning"] = "operator classification: false positive from processless terminal TCP LAST-ACK state"

    baseline = alert_rate_baseline([trusted], now=now)

    assert baseline["current"] == {"raw": 1, "real_raw": 1, "actionable": 0, "visible": 0}
    assert baseline["quiet_streak_hours"]["raw"] == 0
    assert baseline["quiet_streak_hours"]["real_raw"] == 0
    assert baseline["quiet_streak_hours"]["actionable"] == 25
    assert baseline["quiet_streak_hours"]["visible"] == 25


def test_alert_rate_baseline_reports_per_host_spikes() -> None:
    now = datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc)
    rows = [
        *[_timed_row("2026-07-15T08:05:00+00:00", host="host02") for _ in range(3)],
        _timed_row("2026-07-15T07:05:00+00:00", host="host03"),
        _timed_row("2026-07-15T06:05:00+00:00", host="host03"),
    ]

    baseline = alert_rate_baseline(rows, now=now)

    host02 = next(item for item in baseline["per_host"] if item["host"] == "host02")
    assert host02["current"] == {"raw": 3, "real_raw": 3, "actionable": 3, "visible": 3}
    assert host02["quiet_streak_hours"]["actionable"] == 0
    assert "host02:actionable_spike>=3x" in baseline["warnings"]
    assert "host02:visible_spike>=3x" in baseline["warnings"]
    assert baseline["per_host"][0]["host"] == "host02"


def test_alert_rate_baseline_per_host_separates_synthetic_noise() -> None:
    now = datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc)
    rows = [
        _timed_row("2026-07-15T08:05:00+00:00", host="shallot-load-webhook"),
        _timed_row("2026-07-15T08:06:00+00:00", host="shallot-load-webhook"),
    ]
    for row in rows:
        row["description"] = "synthetic load test"
        row["verdict"] = "suppress"

    baseline = alert_rate_baseline(rows, now=now)

    assert {item["host"] for item in baseline["per_host"]} == {"host01", "host03", "host04", "host02"}
    assert "shallot-load-webhook" not in {item["host"] for item in baseline["per_host"]}
    assert all(item["current"]["raw"] == 0 for item in baseline["per_host"])
    assert baseline["current"]["raw"] == 2
    assert baseline["current"]["real_raw"] == 0
    assert baseline["warnings"] == []


def test_alert_rate_baseline_per_host_keeps_real_hosts_when_synthetic_dominates() -> None:
    now = datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc)
    synthetic_rows = [
        _timed_row("2026-07-15T07:05:00+00:00", host=f"shallot-load-{idx}")
        for idx in range(20)
    ]
    for row in synthetic_rows:
        row["description"] = "synthetic load test"
        row["verdict"] = "suppress"
    rows = [
        *synthetic_rows,
        _timed_row("2026-07-15T07:10:00+00:00", host="host02"),
        _timed_row("2026-07-15T06:10:00+00:00", host="host01"),
    ]

    baseline = alert_rate_baseline(rows, now=now)

    hosts = [item["host"] for item in baseline["per_host"]]
    assert hosts == ["host01", "host02", "host03", "host04"]


def test_synthetic_residue_summarizes_test_noise_separately() -> None:
    rows = [
        _row("shallot-load-webhook-8855", verdict="suppress", title="synthetic load"),
        _row("shallot-load-webhook-8855", verdict="suppress", title="synthetic load 2"),
        _row("host02", title="Routine"),
    ]

    summary = assess_rows(rows, hours=24)

    assert summary["synthetic_or_experiment"] == 2
    assert summary["visible_non_synthetic"] == 1
    residue = summary["synthetic_residue"]
    assert residue["count"] == 2
    assert residue["percent_raw"] == 66.67
    assert residue["per_day"] == 2.0
    assert isinstance(residue["prune_eligible_24h"], int)
    assert "oldest_age_hours" in residue
    assert "newest_age_hours" in residue
    assert "next_eligible_in_hours" in residue
    assert residue["top_hosts"] == [{"host": "shallot-load-webhook-8855", "count": 2, "per_day": 2.0}]
    assert synthetic_residue_warnings(summary["synthetic_residue"]) == []


def test_synthetic_residue_guardrail_warns_when_test_noise_dominates() -> None:
    rows = []
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for i in range(9):
        row = _row(f"shallot-load-webhook-{i}", verdict="suppress", title="synthetic load")
        row["timestamp"] = now
        row["description"] = "synthetic"
        rows.append(row)
    rows.append(_row("host02", title="Routine"))

    summary = assess_rows(rows, hours=0.2)

    assert "synthetic_residue>=80pct_raw" in summary["volume_guardrails"]["warnings"]
    assert "synthetic_residue>=1000/day" in summary["volume_guardrails"]["warnings"]
    assert "volume:synthetic_residue>=80pct_raw" in summary["readiness"]["warnings"]
    assert any("not yet 24h prune-eligible" in action for action in summary["readiness"]["next_actions"])
    assert any("next eligible in ~" in action for action in summary["readiness"]["next_actions"])


def test_volume_guardrails_report_real_and_synthetic_rates_separately() -> None:
    rows = []
    for i in range(4):
        row = _row(f"shallot-load-webhook-{i}", verdict="suppress", title="synthetic load")
        row["description"] = "synthetic"
        rows.append(row)
    rows.append(_row("host02", title="Routine"))

    summary = assess_rows(rows, hours=0.5)

    guardrails = summary["volume_guardrails"]
    assert guardrails["raw_per_hour"] == 10.0
    assert guardrails["real_raw_per_hour"] == 2.0
    assert guardrails["synthetic_per_hour"] == 8.0
    assert guardrails["visible_per_hour"] == 2.0


def test_synthetic_residue_next_action_reports_prune_eligible_rows() -> None:
    old = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(timespec="seconds")
    rows = []
    for i in range(9):
        row = _row(f"shallot-load-webhook-{i}", verdict="suppress", title="synthetic load")
        row["timestamp"] = old
        row["description"] = "synthetic"
        rows.append(row)
    rows.append(_row("host02", title="Routine"))

    summary = assess_rows(rows, hours=0.2)

    assert summary["synthetic_residue"]["prune_eligible_24h"] == 9
    assert any("9 rows are older than 24h" in action for action in summary["readiness"]["next_actions"])


def test_synthetic_residue_text_includes_prune_age_context() -> None:
    text = synthetic_residue_text(
        {
            "count": 9,
            "percent_raw": 90.0,
            "per_day": 1080.0,
            "prune_eligible_24h": 4,
            "oldest_age_hours": 25.5,
            "newest_age_hours": 1.25,
            "top_hosts": [{"host": "shallot-load-webhook", "count": 9}],
        }
    )

    assert "prune_eligible_24h=4" in text
    assert "oldest_age_hours=25.5" in text
    assert "newest_age_hours=1.25" in text
    assert "top_hosts=shallot-load-webhook=9" in text


def test_syslog_canary_rows_are_synthetic_even_before_cleanup() -> None:
    row = _row("127.0.0.1", verdict="pending", title="Router auth failure", severity="high")
    row["source"] = "syslog"
    row["src_ip"] = "127.0.0.1"
    row["description"] = "auth failure"
    row["raw"] = "shallot-syslog-canary-test token=shallot-syslog-canary-test-1234"

    summary = assess_rows([row], hours=1)

    assert summary["raw_alerts"] == 1
    assert summary["synthetic_or_experiment"] == 1
    assert summary["visible_non_synthetic"] == 0
    assert summary["alert_rate_baseline"]["current"]["actionable"] == 0


def test_volume_rows_for_text_caps_and_prioritizes_operator_signal() -> None:
    rows = [
        {"host": "synthetic-heavy", "raw": 500, "visible": 0, "suppressed_non_synthetic": 0},
        {"host": "suppressed-real", "raw": 5, "visible": 0, "suppressed_non_synthetic": 3},
        {"host": "visible-host", "raw": 1, "visible": 1, "suppressed_non_synthetic": 0},
        {"host": "quiet", "raw": 2, "visible": 0, "suppressed_non_synthetic": 0},
    ]

    shown, omitted = volume_rows_for_text(rows, limit=3)

    assert [row["host"] for row in shown] == ["visible-host", "suppressed-real", "synthetic-heavy"]
    assert omitted == 1


def test_summary_json_bounds_volume_rows_without_changing_full_summary() -> None:
    rows = []
    for idx in range(5):
        row = _row(f"shallot-load-{idx}", verdict="suppress", title="synthetic load")
        row["description"] = "synthetic"
        rows.append(row)
    rows.append(_row("visible-host", title="Visible alert"))
    rows.append(_row("suppressed-real", verdict="suppress", title="Suppressed real"))

    summary = assess_rows(rows, hours=24)
    bounded = summary_json(summary, max_host_rows=3)

    assert len(summary["volume_by_host"]) == 7
    assert [row["host"] for row in bounded["volume_by_host_top"]] == [
        "visible-host",
        "suppressed-real",
        "shallot-load-0",
    ]
    assert bounded["volume_by_host_total"] == 7
    assert bounded["volume_by_host_omitted"] == 4
    assert "volume_by_host" not in bounded


def test_alert_rate_baseline_warns_on_real_raw_spike() -> None:
    now = datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc)
    rows = [_timed_row(f"2026-07-15T08:{i:02d}:00+00:00") for i in range(5)]

    baseline = alert_rate_baseline(rows, now=now)

    assert "real_raw_spike>=5x" in baseline["warnings"]


def test_alert_rate_baseline_warns_on_visible_spike() -> None:
    now = datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc)
    rows = [_timed_row(f"2026-07-15T08:{i:02d}:00+00:00") for i in range(3)]

    baseline = alert_rate_baseline(rows, now=now)

    assert "visible_spike>=3x" in baseline["warnings"]


def test_alert_rate_baseline_reports_adaptive_thresholds() -> None:
    now = datetime(2026, 7, 15, 8, 30, tzinfo=timezone.utc)
    rows = []
    for hour in range(1, 25):
        for idx in range(2):
            ts = (now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=hour)).replace(minute=idx)
            rows.append(_timed_row(ts.isoformat()))
    for idx in range(8):
        rows.append(_timed_row(f"2026-07-15T08:{idx:02d}:00+00:00"))

    baseline = alert_rate_baseline(rows, now=now)

    visible = baseline["adaptive_thresholds"]["visible"]
    assert visible["median"] == 2.0
    assert visible["current"] == 8
    assert visible["threshold"] == 5.0
    assert visible["exceeded"] is True
    assert "adaptive_visible_spike" in baseline["warnings"]


def test_suppression_quality_warns_on_suppressed_critical_real_alert() -> None:
    row = _row("host02", verdict="suppress", title="Credential theft attempt", severity="critical")

    quality = suppression_quality([row], hours=24)

    assert quality["status"] == "review"
    assert "suppressed_critical_present" in quality["warnings"]
    assert quality["examples"][0]["asset"] == "host02"


def test_suppression_quality_ignores_synthetic_suppression() -> None:
    row = _row("shallot-load-1", verdict="suppress", title="synthetic load", severity="critical")
    row["description"] = "synthetic"

    quality = suppression_quality([row], hours=1)

    assert quality["status"] == "ok"
    assert quality["warnings"] == []
    assert quality["suppressed_non_synthetic"] == 0


def test_suppression_quality_ignores_trusted_resolved_agent_offline() -> None:
    row = _row("host01", verdict="suppress", title="Agent offline: host01", severity="critical")
    row["category"] = "agent_health"
    row["source_ref"] = "watchdog:host01"

    quality = suppression_quality([row], hours=24)

    assert quality["status"] == "ok"
    assert quality["warnings"] == []
    assert quality["suppressed_non_synthetic"] == 0


def test_suppression_quality_ignores_operator_classified_false_positive() -> None:
    row = _row("host04", verdict="suppress", title="Suspicious outbound connection", severity="high")
    row["source_ref"] = "network_egress_suspicious"
    row["category"] = "c2"
    row["dst_ip"] = "93.158.213.92"
    row["dst_port"] = 1337
    row["ai_reasoning"] = "operator classification: false positive from processless terminal TCP LAST-ACK state"

    quality = suppression_quality([row], hours=1)

    assert quality["status"] == "ok"
    assert quality["warnings"] == []
    assert quality["suppressed_non_synthetic"] == 0


def test_suppression_quality_ignores_operator_calibrated_false_positive() -> None:
    row = _row("host01", verdict="suppress", title="Suspicious Cron Job Persistence", severity="high")
    row["source"] = "argus"
    row["source_ref"] = "persistence_scan"
    row["category"] = "persistence"
    row["ai_reasoning"] = "operator calibration: known false positive; quiet-mode classifier now suppresses this pattern"

    quality = suppression_quality([row], hours=1)
    summary = assess_rows([row], hours=1)

    assert quality["status"] == "ok"
    assert quality["warnings"] == []
    assert quality["suppressed_non_synthetic"] == 0
    assert summary["suppressed_non_synthetic"] == 0


def test_suppression_quality_ignores_broad_enable_calibration_replay() -> None:
    row = _row("37.140.223.65", verdict="suppress", title="CrowdSec BAN: 37.140.223.65", severity="high")
    row["source"] = "crowdsec"
    row["source_ref"] = "464"
    row["category"] = "crowdsec/ban"
    row["ai_reasoning"] = (
        "operator broad-enable calibration: suppress CrowdSec active-decision startup replay; "
        "patched ingestor baselines existing decisions before polling"
    )

    quality = suppression_quality([row], hours=1)
    summary = assess_rows([row], hours=1)

    assert quality["status"] == "ok"
    assert quality["warnings"] == []
    assert quality["suppressed_non_synthetic"] == 0
    assert summary["suppressed_non_synthetic"] == 0


def test_suppression_quality_ignores_documented_operator_maintenance() -> None:
    row = _row("host01", verdict="suppress", title="Protected file changed", severity="high")
    row["source"] = "argus"
    row["source_ref"] = "file_sentinel"
    row["category"] = "collection"
    row["description"] = "Protected file changed: /etc/passwd"
    row["ai_reasoning"] = (
        "operator maintenance 2026-07-18: package installs created grafana/victorialogs users "
        "and updated protected account database files"
    )

    quality = suppression_quality([row], hours=1)
    summary = assess_rows([row], hours=1)

    assert quality["status"] == "ok"
    assert quality["warnings"] == []
    assert quality["suppressed_non_synthetic"] == 0
    assert summary["suppressed_non_synthetic"] == 0


def test_suppression_quality_ignores_native_title_suppression() -> None:
    row = _row("192.168.0.172", verdict="suppress", title="ET SCAN Potential SSH Scan OUTBOUND", severity="high")
    row["source"] = "suricata"
    row["source_ref"] = "2003068"
    row["category"] = "Attempted Information Leak"
    row["ai_reasoning"] = "native suppression: title matched 'ET SCAN Potential SSH Scan'"

    quality = suppression_quality([row], hours=1)
    summary = assess_rows([row], hours=1)

    assert quality["status"] == "ok"
    assert quality["warnings"] == []
    assert quality["suppressed_non_synthetic"] == 0
    assert summary["suppressed_non_synthetic"] == 0


def test_suppression_quality_ignores_router_syslog_user_noise() -> None:
    row = _row("192.168.0.1", verdict="suppress", title="Syslog [user]", severity="low")
    row["source"] = "syslog"
    row["source_ref"] = ""
    row["category"] = "syslog/user"
    row["src_ip"] = "192.168.0.1"
    row["description"] = "routine router user facility message"

    quality = suppression_quality([row], hours=1)
    summary = assess_rows([row], hours=1)

    assert quality["status"] == "ok"
    assert quality["warnings"] == []
    assert quality["suppressed_non_synthetic"] == 0
    assert summary["suppressed_non_synthetic"] == 0


def test_suppression_quality_ignores_loopback_self_test() -> None:
    row = _row("host01", verdict="suppress", title="Watched egress: python3 - -> 127.0.0.1:9001", severity="critical")
    row["source_ref"] = "network_egress_suspicious"
    row["category"] = "c2"
    row["ai_reasoning"] = "operator calibration [egress_watcher loopback self-test - resolved by operator]"

    quality = suppression_quality([row], hours=1)
    summary = assess_rows([row], hours=1)

    assert quality["status"] == "ok"
    assert quality["warnings"] == []
    assert quality["suppressed_non_synthetic"] == 0
    assert summary["suppressed_non_synthetic"] == 0


def test_suppression_quality_ignores_native_housekeeping_state_change() -> None:
    row = _row("host04", verdict="suppress", title="State changed: DISARMED -> ARMED_HOME", severity="low")
    row["source"] = "argus"
    row["source_ref"] = "state_change"
    row["category"] = "state_management"
    row["description"] = "Argus transitioned from DISARMED to ARMED_HOME (daemon_start)"
    row["ai_reasoning"] = "native housekeeping: routine Argus startup/shutdown lifecycle"

    quality = suppression_quality([row], hours=1)
    summary = assess_rows([row], hours=1)

    assert quality["status"] == "ok"
    assert quality["suppressed_non_synthetic"] == 0
    assert summary["suppressed_non_synthetic"] == 0
    assert summary["top_suppressed_non_synthetic_titles"] == []


def test_suppression_quality_ignores_codex_syslog_receiver_test() -> None:
    row = _row("127.0.0.1", verdict="suppress", title="Syslog [local0] dlink", severity="low")
    row["source"] = "syslog"
    row["source_ref"] = ""
    row["category"] = "syslog/local0"
    row["description"] = "syslog forwarder 514 test codex 1784080084"
    row["raw"] = "<134>Jul 15 01:49:00 dlink-m32 dlink: syslog forwarder 514 test codex 1784080084"

    quality = suppression_quality([row], hours=1)
    summary = assess_rows([row], hours=1)

    assert quality["status"] == "ok"
    assert quality["suppressed_non_synthetic"] == 0
    assert summary["suppressed_non_synthetic"] == 0
    assert summary["top_suppressed_non_synthetic_titles"] == []


def test_suppression_quality_keeps_suppressed_high_remote_session_reviewable() -> None:
    row = _row("host03", verdict="suppress", title="Session activity detected", severity="high")
    row["source"] = "argus"
    row["source_ref"] = "session_alert"
    row["category"] = "lateral_movement"
    row["description"] = "SSH/remote session detected for user om on pts/0 from 192.168.0.212"

    quality = suppression_quality([row], hours=24)

    assert quality["status"] == "ok"
    assert quality["suppressed_non_synthetic"] == 1
    assert quality["suppressed_high_or_critical"] == 1
    assert quality["examples"][0]["title"] == "Session activity detected"
    assert quality["examples"][0]["source_ref"] == "session_alert"
    assert quality["examples"][0]["category"] == "lateral_movement"
    assert quality["examples"][0]["count"] == 1
    assert quality["examples"][0]["latest_seen"] == row["timestamp"]
    assert quality["examples"][0]["latest_age_hours"] is not None


def test_suppression_quality_groups_repeated_review_examples() -> None:
    rows = []
    for minute in ("00", "30"):
        row = _row("host03", verdict="suppress", title="Session activity detected", severity="high")
        row["id"] = f"host03-session-{minute}"
        row["timestamp"] = f"2026-07-15T01:{minute}:00+00:00"
        row["source"] = "argus"
        row["source_ref"] = "session_alert"
        row["category"] = "lateral_movement"
        rows.append(row)

    quality = suppression_quality(rows, hours=24)

    assert len(quality["examples"]) == 1
    assert quality["examples"][0]["count"] == 2
    assert quality["examples"][0]["first_seen"] == "2026-07-15T01:00:00+00:00"
    assert quality["examples"][0]["latest_seen"] == "2026-07-15T01:30:00+00:00"


def test_suppression_quality_does_not_double_count_priority_overlap() -> None:
    row = _row("host03", verdict="suppress", title="C2 callback", severity="critical")
    row["source"] = "argus"
    row["source_ref"] = "network_egress_suspicious"
    row["category"] = "c2"
    row["dst_ip"] = "203.0.113.10"
    row["dst_port"] = 4444

    quality = suppression_quality([row], hours=24)

    assert quality["warnings"] == [
        "suppressed_critical_present",
        "suppressed_network_rule_hits_present",
    ]
    assert len(quality["examples"]) == 1
    assert quality["examples"][0]["count"] == 1


def test_network_rule_hit_becomes_incident_candidate_with_rule_metadata() -> None:
    row = _row("host01", title="ET MALWARE Possible C2 Beacon", severity="high")
    row["source"] = "suricata"
    row["source_ref"] = "suricata:1:2030000"
    row["category"] = "ET MALWARE"

    summary = assess_rows([row], hours=1)

    assert summary["incident_candidates"] == [
        {
            "timestamp": row["timestamp"],
            "asset": "host01",
            "source": "suricata",
            "severity": "high",
            "title": "ET MALWARE Possible C2 Beacon",
            "verdict": "pending",
            "rule_hits": [
                {
                    "rule_id": "suricata.threat_signature",
                    "severity": "critical",
                    "reason": "Suricata threat signature keyword",
                }
            ],
        }
    ]
    assert "incident_candidates_present" in summary["readiness"]["blockers"]
    assert "incident_candidates_present" in summary["volume_guardrails"]["warnings"]


def test_router_exposure_change_becomes_incident_candidate() -> None:
    row = _row("dlink", title="UPnP port mapping added", severity="low")
    row["source"] = "syslog"
    row["src_ip"] = "192.168.0.1"
    row["description"] = "UPnP port mapping added TCP 51413 to client 192.168.0.42"
    row["category"] = "router"

    summary = assess_rows([row], hours=1)

    assert summary["incident_candidates"][0]["rule_hits"] == [
        {
            "rule_id": "syslog.exposure_change",
            "severity": "high",
            "reason": "Router/firewall exposure or remote-management setting changed",
        }
    ]
    assert "incident_candidates_present" in summary["readiness"]["blockers"]


def test_argus_anti_tamper_becomes_incident_candidate() -> None:
    row = _row("host02", title="Protected config changed", severity="high")
    row["source"] = "argus"
    row["source_ref"] = "anti_tamper"
    row["description"] = "Tamper signal: watched file changed: /etc/argus/config.toml"
    row["category"] = "defense_evasion"

    summary = assess_rows([row], hours=1)

    assert summary["incident_candidates"][0]["rule_hits"] == [
        {
            "rule_id": "argus.anti_tamper",
            "severity": "critical",
            "reason": "Argus anti-tamper signal",
        }
    ]
    assert "incident_candidates_present" in summary["readiness"]["blockers"]


def test_qbittorrent_egress_noise_does_not_become_incident_candidate() -> None:
    row = _row("host04", title="Suspicious outbound connection: qbittorrent -> 91.145.49.80:51413", severity="high")
    row["source"] = "argus"
    row["source_ref"] = "network_egress_suspicious"
    row["description"] = "Process qbittorrent opened an outbound connection to 91.145.49.80:51413 (suspicious_port)."
    row["category"] = "c2"
    row["dst_ip"] = "91.145.49.80"
    row["dst_port"] = 51413
    row["raw"] = json.dumps(
        {
            "event_type": "network_egress_suspicious",
            "details": {
                "process": "qbittorrent",
                "reason": "suspicious_port",
                "remote_ip": "91.145.49.80",
                "remote_port": 51413,
            },
        }
    )

    summary = assess_rows([row], hours=1)

    assert summary["incident_candidates"] == []
    assert "incident_candidates_present" not in summary["readiness"]["blockers"]


def test_assessment_volume_ignores_operator_classified_false_positive_suppression() -> None:
    row = _row("host04", verdict="suppress", title="Suspicious outbound connection", severity="high")
    row["source_ref"] = "network_egress_suspicious"
    row["category"] = "c2"
    row["ai_reasoning"] = "operator classification: false positive from processless terminal TCP LAST-ACK state"

    summary = assess_rows([row], hours=1)

    assert summary["suppressed"] == 1
    assert summary["suppressed_non_synthetic"] == 0
    assert summary["volume_by_host"][0]["suppressed"] == 1
    assert summary["volume_by_host"][0]["suppressed_non_synthetic"] == 0
    assert summary["top_suppressed_non_synthetic_titles"] == []
    assert "host04:suppressed_non_synthetic>=20/day" not in summary["volume_guardrails"]["warnings"]


def test_assessment_treats_edge_canary_as_synthetic() -> None:
    row = _row("host01", verdict="suppress", title="Argus canary internal session argus-scout-canary-1")
    row["source"] = "argus"
    row["category"] = "edge_canary/session"
    row["source_ref"] = "session_alert"

    summary = assess_rows([row], hours=1)

    assert summary["synthetic_or_experiment"] == 1
    assert summary["suppressed_non_synthetic"] == 0


def test_suppression_quality_ignores_operator_approved_rollout_repair() -> None:
    row = _row("host02", verdict="suppress", title="Protected file changed", severity="high")
    row["source"] = "argus"
    row["source_ref"] = "file_sentinel"
    row["category"] = "collection"
    row["ai_reasoning"] = "operator-approved rollout repair: added Host01 controller public key"

    quality = suppression_quality([row], hours=1)
    summary = assess_rows([row], hours=1)

    assert quality["warnings"] == []
    assert summary["suppressed_non_synthetic"] == 0


def test_volume_guardrail_warns_on_visible_rate() -> None:
    rows = [_row("host02", title=f"Routine {i}") for i in range(11)]

    summary = assess_rows(
        rows,
        hours=1,
        network_sources=[
            {
                "source": "syslog",
                "enabled": True,
                "count_window": 1,
                "udp_listening": True,
                "tcp_listening": True,
            },
            {"source": "suricata", "enabled": False},
            {"source": "pfsense", "enabled": False},
        ],
    )

    assert "visible_rate>=10/h" in summary["volume_guardrails"]["warnings"]
    assert "host02:visible>=20/day" in summary["volume_guardrails"]["warnings"]
    assert summary["readiness"]["status"] == "watch"
    assert any(item.startswith("volume:") for item in summary["readiness"]["warnings"])


def test_volume_guardrail_warns_on_suppressed_real_rate() -> None:
    rows = [_row("host02", verdict="suppress", title=f"Startup noise {i}") for i in range(21)]

    summary = assess_rows(rows, hours=24)

    assert "host02:suppressed_non_synthetic>=20/day" in summary["volume_guardrails"]["warnings"]
    assert "volume:host02:suppressed_non_synthetic>=20/day" in summary["readiness"]["warnings"]


def test_volume_guardrail_reports_db_freelist_pressure(tmp_path, monkeypatch) -> None:
    db = tmp_path / "shallots.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE bulky (payload BLOB)")
    con.executemany("INSERT INTO bulky VALUES (zeroblob(4096))", [() for _ in range(32)])
    con.execute("DELETE FROM bulky")
    con.commit()
    con.close()
    monkeypatch.setattr(shallot_alert_assess, "DB_FREELIST_WARN_BYTES", 1)
    monkeypatch.setattr(shallot_alert_assess, "DB_FREELIST_WARN_PCT", 1.0)

    summary = assess_rows([], hours=1, db_path=str(db))

    guardrails = summary["volume_guardrails"]
    assert guardrails["db_page_count"] > 0
    assert guardrails["db_page_size"] > 0
    assert guardrails["db_freelist_count"] > 0
    assert guardrails["db_freelist_bytes"] > 0
    assert guardrails["db_freelist_pct"] > 0
    assert "db_freelist>=50MiB_and>=20pct" in guardrails["warnings"]


def test_readiness_includes_suppression_quality_warning() -> None:
    row = _row("host02", verdict="suppress", title="Credential theft attempt", severity="critical")

    summary = assess_rows([row], hours=24)

    assert "suppression:suppressed_critical_present" in summary["readiness"]["warnings"]
    assert "suppression_quality_clean" not in summary["readiness"]["strengths"]


def test_assessment_infers_agent_asset_from_watchdog_source_ref() -> None:
    row = _row("", verdict="suppress", title="Agent offline: host01", severity="high")
    row["source_ref"] = "watchdog:host01"
    row["category"] = "agent_health"

    summary = assess_rows([row], hours=24)

    assert summary["volume_by_host"][0]["host"] == "host01"
    assert summary["volume_by_host"][0]["suppressed"] == 1
    assert summary["volume_by_host"][0]["suppressed_non_synthetic"] == 0
    assert summary["top_suppressed_non_synthetic_titles"] == []


def test_assessment_infers_argus_asset_from_raw_host_before_remote_src_ip() -> None:
    row = _row("", verdict="suppress", title="Session activity detected", severity="high")
    row["source"] = "argus"
    row["source_ref"] = "session_alert"
    row["category"] = "lateral_movement"
    row["src_ip"] = "192.168.0.212"
    row["raw"] = '{"host": "host03", "event_type": "session_alert"}'

    summary = assess_rows([row], hours=24)

    assert summary["volume_by_host"][0]["host"] == "host03"
    assert summary["suppression_quality"]["examples"][0]["asset"] == "host03"
    assert summary["top_suppressed_non_synthetic_titles"][0]["asset"] == "host03"


def test_assessment_infers_agent_asset_from_offline_title_without_source_ref() -> None:
    row = _row("", verdict="suppress", title="Agent offline: host04", severity="critical")
    row["source_ref"] = "agent_offline"
    row["category"] = "agent_health"

    summary = assess_rows([row], hours=24)

    assert summary["volume_by_host"][0]["host"] == "host04"


def test_network_source_health_reports_disabled_sources(tmp_path) -> None:
    db = tmp_path / "shallots.db"
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    con.execute(
        """
        CREATE TABLE alerts (
            source TEXT, src_asset TEXT, src_ip TEXT, timestamp TEXT
        )
        """
    )

    sources = network_source_health(con, Config(), cutoff="2026-07-15T00:00:00+00:00")

    assert {"source": "syslog", "enabled": False, "status": "disabled", "warnings": []} in sources
    assert {"source": "pfsense", "enabled": False, "status": "disabled", "warnings": []} in sources


def test_network_source_health_marks_enabled_idle_syslog_without_warning(monkeypatch, tmp_path) -> None:
    db = tmp_path / "shallots.db"
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    con.execute(
        """
        CREATE TABLE alerts (
            source TEXT, src_asset TEXT, src_ip TEXT, timestamp TEXT
        )
        """
    )
    cfg = Config()
    cfg.components.syslog_receiver = True
    cfg.syslog.enabled = True
    monkeypatch.setattr(shallot_alert_assess, "_port_listening", lambda port, proto: True)

    sources = network_source_health(con, cfg, cutoff="2026-07-15T00:00:00+00:00")
    syslog = next(src for src in sources if src["source"] == "syslog")

    assert syslog["status"] == "idle"
    assert syslog["warnings"] == []
    assert syslog["count_window"] == 0


def test_network_coverage_marks_listening_idle_as_watch_not_gap() -> None:
    coverage = network_coverage_summary(
        [
            {
                "source": "syslog",
                "enabled": True,
                "count_window": 0,
                "udp_listening": True,
                "tcp_listening": True,
            },
            {"source": "suricata", "enabled": False},
            {"source": "pfsense", "enabled": False},
        ]
    )

    assert coverage["status"] == "watch"
    assert "syslog" in coverage["listening_sources"]
    assert "no_network_source_events_in_window" in coverage["gaps"]
    assert coverage["blocking_gaps"] == []
    assert set(coverage["advisory_gaps"]) == {
        "packet_ids_disabled",
        "syslog_idle_in_window",
        "no_network_source_events_in_window",
    }
    assert any(action["gap"] == "syslog_idle_in_window" for action in coverage["actions"])
    assert any(action["gap"] == "no_network_source_events_in_window" for action in coverage["actions"])


def test_network_coverage_only_warns_on_pfsense_when_expected() -> None:
    coverage = network_coverage_summary(
        [
            {
                "source": "syslog",
                "enabled": True,
                "count_window": 1,
                "udp_listening": True,
                "tcp_listening": True,
            },
            {"source": "suricata", "enabled": True, "count_window": 1},
            {"source": "pfsense", "enabled": False},
        ]
    )

    assert "pfsense_disabled" not in coverage["gaps"]
    assert coverage["status"] == "ok"

    expected = [{"name": "pfsense_firewall", "type": "pfsense", "status": "missing"}]
    coverage = network_coverage_summary(
        [
            {
                "source": "syslog",
                "enabled": True,
                "count_window": 1,
                "udp_listening": True,
                "tcp_listening": True,
            },
            {"source": "suricata", "enabled": True, "count_window": 1},
            {"source": "pfsense", "enabled": False},
        ],
        expected,
    )

    assert "pfsense_disabled" in coverage["advisory_gaps"]


def test_assess_rows_readiness_marks_network_gap_not_ready() -> None:
    summary = assess_rows(
        [],
        hours=1,
        network_sources=[
            {
                "source": "syslog",
                "enabled": True,
                "count_window": 0,
                "udp_listening": True,
                "tcp_listening": True,
            },
            {"source": "suricata", "enabled": False},
            {"source": "pfsense", "enabled": False},
        ],
        expected_log_sources=[
            {
                "name": "dlink_main",
                "type": "syslog",
                "status": "missing",
                "src_ips": ["192.168.0.1"],
                "warnings": ["expected_source_missing"],
            }
        ],
    )

    assert summary["readiness"]["status"] == "not_ready"
    assert "network_coverage_gap" in summary["readiness"]["blockers"]
    assert any("dlink_main" in action for action in summary["readiness"]["next_actions"])


def test_assess_rows_readiness_marks_quiet_syslog_watch() -> None:
    summary = assess_rows(
        [],
        hours=1,
        network_sources=[
            {
                "source": "syslog",
                "enabled": True,
                "count_window": 0,
                "udp_listening": True,
                "tcp_listening": True,
            },
            {"source": "suricata", "enabled": False},
            {"source": "pfsense", "enabled": False},
        ],
    )

    assert summary["readiness"]["status"] == "watch"
    assert "network_coverage_watch" in summary["readiness"]["warnings"]
    assert "alert_volume_within_guardrails" in summary["readiness"]["strengths"]


def test_network_coverage_marks_missing_enabled_syslog_listener_as_gap() -> None:
    coverage = network_coverage_summary(
        [
            {
                "source": "syslog",
                "enabled": True,
                "count_window": 0,
                "udp_listening": False,
                "tcp_listening": False,
            },
            {"source": "suricata", "enabled": False},
            {"source": "pfsense", "enabled": False},
        ]
    )

    assert coverage["status"] == "gap"
    assert "syslog_not_listening" in coverage["gaps"]
    assert "syslog_not_listening" in coverage["blocking_gaps"]
    assert "packet_ids_disabled" in coverage["advisory_gaps"]
    assert any(action["priority"] == "high" and action["gap"] == "syslog_not_listening" for action in coverage["actions"])


def test_expected_log_source_reports_missing_and_adds_coverage_gap(tmp_path) -> None:
    db = tmp_path / "shallots.db"
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    con.execute(
        """
        CREATE TABLE alerts (
            source TEXT, src_asset TEXT, src_ip TEXT, timestamp TEXT
        )
        """
    )
    manifest = tmp_path / "sources.yaml"
    manifest.write_text(
        """
sources:
  - name: dlink_main
    type: syslog
    expected: true
    src_ips: [192.168.0.1]
"""
    )

    expected = expected_log_source_health(con, path=str(manifest), cutoff="2026-07-15T00:00:00+00:00")
    coverage = network_coverage_summary([], expected)

    assert expected[0]["status"] == "missing"
    assert coverage["status"] == "gap"
    assert "expected_syslog_missing:dlink_main" in coverage["gaps"]
    assert coverage["blocking_gaps"] == ["expected_syslog_missing:dlink_main"]
    assert any("dlink_main" in action["action"] for action in coverage["actions"])
    assert coverage["actions"][0]["priority"] == "high"


def test_expected_log_source_reports_ok_when_seen_in_window(tmp_path) -> None:
    db = tmp_path / "shallots.db"
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    con.execute(
        """
        CREATE TABLE alerts (
            source TEXT, src_asset TEXT, src_ip TEXT, timestamp TEXT
        )
        """
    )
    con.execute(
        "INSERT INTO alerts VALUES (?, ?, ?, ?)",
        ("syslog", "dlink", "192.168.0.1", "2026-07-15T00:30:00+00:00"),
    )
    manifest = tmp_path / "sources.yaml"
    manifest.write_text(
        """
sources:
  - name: dlink_main
    type: syslog
    expected: true
    src_ips: [192.168.0.1]
    hostnames: [dlink]
"""
    )

    expected = expected_log_source_health(con, path=str(manifest), cutoff="2026-07-15T00:00:00+00:00")

    assert expected[0]["status"] == "ok"
    assert expected[0]["count_window"] == 1


def test_livecollator_rows_are_synthetic() -> None:
    row = Row(
        title="Syslog [authpriv] dlink-livecollator-1784416796-cc6fe1c8",
        description="Syslog [user] routine gateway status token=livecollator-1784416796-cc6fe1c8",
        category="syslog/authpriv",
        src_asset="",
        source_ref="",
        raw="",
    )

    assert shallot_alert_assess._is_synthetic(row)


def test_operator_live_test_suppression_is_trusted() -> None:
    row = Row(
        title="sshd: brute force trying to get access to the system",
        description="controlled failed SSH live test",
        category="syslog, sshd, authentication_failures",
        source="wazuh",
        source_ref="",
        severity="high",
        raw="",
        ai_reasoning="operator live test: controlled failed SSH trigger",
    )

    assert shallot_alert_assess._trusted_suppression(row)
