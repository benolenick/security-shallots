"""Production gate drift watch tests."""

from tools.shallot_gate_watch import build_gate_watch


def test_gate_watch_initializes_without_prior_state() -> None:
    report = build_gate_watch(
        {"status": "blocked", "blockers": ["b"], "warnings": ["w"]},
        {},
        now="2026-07-15T00:00:00+00:00",
    )

    assert report["status"] == "initialized"
    assert report["new_blockers"] == ["b"]
    assert report["new_warnings"] == ["w"]
    assert report["blocker_first_seen_at"] == {"b": "2026-07-15T00:00:00+00:00"}
    assert report["warning_first_seen_at"] == {"w": "2026-07-15T00:00:00+00:00"}
    assert report["blocker_age_sec"] == {"b": 0}
    assert report["warning_age_sec"] == {"w": 0}


def test_gate_watch_reports_stable_blockers_and_warnings() -> None:
    previous = {
        "checked_at": "2026-07-15T00:00:00+00:00",
        "blockers": ["b"],
        "warnings": ["w"],
        "blocker_first_seen_at": {"b": "2026-07-14T23:30:00+00:00"},
        "warning_first_seen_at": {"w": "2026-07-14T23:45:00+00:00"},
    }

    report = build_gate_watch(
        {"status": "blocked", "blockers": ["b"], "warnings": ["w"]},
        previous,
        now="2026-07-15T01:00:00+00:00",
    )

    assert report["status"] == "stable"
    assert report["stable_blockers"] == ["b"]
    assert report["stable_warnings"] == ["w"]
    assert report["new_blockers"] == []
    assert report["cleared_blockers"] == []
    assert report["previous_checked_at"] == "2026-07-15T00:00:00+00:00"
    assert report["blocker_first_seen_at"] == {"b": "2026-07-14T23:30:00+00:00"}
    assert report["warning_first_seen_at"] == {"w": "2026-07-14T23:45:00+00:00"}
    assert report["blocker_age_sec"] == {"b": 5400}
    assert report["warning_age_sec"] == {"w": 4500}


def test_gate_watch_prioritizes_new_blocker_status() -> None:
    previous = {"blockers": ["old"], "warnings": ["old_warning"]}

    report = build_gate_watch(
        {"status": "blocked", "blockers": ["new", "old"], "warnings": []},
        previous,
    )

    assert report["status"] == "new_blockers"
    assert report["new_blockers"] == ["new"]
    assert report["cleared_warnings"] == ["old_warning"]
    assert "old_warning" not in report["warning_first_seen_at"]


def test_gate_watch_reports_cleared_blocker_as_changed() -> None:
    previous = {"blockers": ["fixed"], "warnings": []}

    report = build_gate_watch({"status": "ready", "blockers": [], "warnings": []}, previous)

    assert report["status"] == "changed"
    assert report["cleared_blockers"] == ["fixed"]
    assert report["blocker_first_seen_at"] == {}
    assert report["blocker_age_sec"] == {}


def test_gate_watch_upgrades_legacy_state_without_first_seen_maps() -> None:
    previous = {
        "checked_at": "2026-07-15T00:00:00+00:00",
        "blockers": ["b"],
        "warnings": ["w"],
    }

    report = build_gate_watch(
        {"status": "blocked", "blockers": ["b"], "warnings": ["w"]},
        previous,
        now="2026-07-15T00:30:00+00:00",
    )

    assert report["blocker_first_seen_at"] == {"b": "2026-07-15T00:00:00+00:00"}
    assert report["warning_first_seen_at"] == {"w": "2026-07-15T00:00:00+00:00"}
    assert report["blocker_age_sec"] == {"b": 1800}
    assert report["warning_age_sec"] == {"w": 1800}
