from argus.monitors.persistence import PersistenceMonitor, PersistenceMonitorConfig


def test_persistence_monitor_emits_on_digest_change(monkeypatch) -> None:
    mon = PersistenceMonitor(PersistenceMonitorConfig(enabled=True, poll_seconds=30, watch_paths=[]))

    vals = ["A", "B"]
    monkeypatch.setattr(mon, "_collect_payload", lambda: vals.pop(0))

    assert mon._poll_once() is None
    sig = mon._poll_once()
    assert sig is not None
    assert sig.event_type == "persistence_detected"


def test_persistence_monitor_windows_schtasks_not_verbose(monkeypatch) -> None:
    mon = PersistenceMonitor(PersistenceMonitorConfig(enabled=True, poll_seconds=30, watch_paths=[]))
    monkeypatch.setattr("os.name", "nt")

    calls: list[list[str]] = []

    class R:
        def __init__(self) -> None:
            self.stdout = ""

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    mon._collect_payload()

    task_cmd = next(c for c in calls if c and c[0] == "schtasks")
    assert "/V" not in task_cmd


def test_persistence_watch_paths_expand_env_vars(monkeypatch, tmp_path) -> None:
    target = tmp_path / "startup.txt"
    target.write_text("x", encoding="utf-8")
    monkeypatch.setenv("ARGUS_PERSIST_DIR", str(tmp_path))
    mon = PersistenceMonitor(
        PersistenceMonitorConfig(
            enabled=True,
            poll_seconds=30,
            watch_paths=["%ARGUS_PERSIST_DIR%\\startup.txt"],
        )
    )

    payload = mon._collect_payload()
    assert str(target) in payload
