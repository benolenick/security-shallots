from pathlib import Path

from argus.monitors.anti_tamper import AntiTamperConfig, AntiTamperMonitor


def test_anti_tamper_file_change(tmp_path: Path) -> None:
    f = tmp_path / "cfg.txt"
    f.write_text("v1", encoding="utf-8")

    mon = AntiTamperMonitor(
        AntiTamperConfig(enabled=True, poll_seconds=15, watch_files=[str(f)], required_tasks=[])
    )
    assert mon._poll_once() == []  # baseline

    f.write_text("v2", encoding="utf-8")
    out = mon._poll_once()
    assert len(out) == 1
    assert out[0].event_type == "anti_tamper"


def test_anti_tamper_missing_task_only_alerts_if_previously_present(monkeypatch) -> None:
    mon = AntiTamperMonitor(
        AntiTamperConfig(enabled=True, poll_seconds=15, watch_files=[], required_tasks=["Argus-OnLock"])
    )
    monkeypatch.setattr("os.name", "nt")

    vals = [False, False, True, False]
    monkeypatch.setattr(mon, "_task_exists", lambda _task: vals.pop(0))

    assert mon._poll_once() == []  # baseline missing
    assert mon._poll_once() == []  # still missing, no alert
    assert mon._poll_once() == []  # appears, no alert
    out = mon._poll_once()         # disappears, alert
    assert len(out) == 1
    assert out[0].event_type == "anti_tamper"


def test_anti_tamper_expands_env_vars(monkeypatch, tmp_path: Path) -> None:
    f = tmp_path / "cfg.txt"
    f.write_text("v1", encoding="utf-8")
    monkeypatch.setenv("ARGUS_WATCH_DIR", str(tmp_path))

    mon = AntiTamperMonitor(
        AntiTamperConfig(
            enabled=True,
            poll_seconds=15,
            watch_files=["%ARGUS_WATCH_DIR%\\cfg.txt"],
            required_tasks=[],
        )
    )
    assert mon._poll_once() == []
    f.write_text("v2", encoding="utf-8")
    out = mon._poll_once()
    assert len(out) == 1
