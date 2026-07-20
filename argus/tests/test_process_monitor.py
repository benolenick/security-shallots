from argus.monitors.process import ProcessMonitor, ProcessMonitorConfig


def test_process_monitor_detects_denylist(monkeypatch) -> None:
    cfg = ProcessMonitorConfig(
        enabled=True,
        poll_seconds=10,
        allowlist=["*"],
        denylist=["*badtool*"],
        alert_on_unknown=False,
    )
    mon = ProcessMonitor(cfg)

    seq = [
        [{"pid": 1, "name": "safe.exe", "exe": "C:/safe.exe", "cmd": "safe.exe"}],
        [
            {"pid": 1, "name": "safe.exe", "exe": "C:/safe.exe", "cmd": "safe.exe"},
            {"pid": 2, "name": "badtool.exe", "exe": "C:/badtool.exe", "cmd": "badtool.exe"},
        ],
    ]

    monkeypatch.setattr(mon, "_list_processes", lambda: seq.pop(0))
    assert mon._poll_once() == []
    out = mon._poll_once()
    assert len(out) == 1
    assert out[0].event_type == "process_tripwire"
