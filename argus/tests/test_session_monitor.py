from argus.monitors.session import SessionMonitor


def test_session_monitor_emits_for_rdp_user(monkeypatch) -> None:
    mon = SessionMonitor(poll_seconds=10, logon_types=[10])
    monkeypatch.setattr(
        mon,
        "_query_4624_events",
        lambda _start: [
            {
                "LogonType": "10",
                "TargetUserName": "om",
                "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
                "IpAddress": "192.168.0.55",
                "TimeCreated": "2026-03-02T18:00:00.000Z",
            }
        ],
    )

    out = mon._poll_once()
    assert len(out) == 1
    assert out[0].event_type == "session_alert"
    assert out[0].details["target_user"] == "om"


def test_session_monitor_ignores_service_account(monkeypatch) -> None:
    mon = SessionMonitor(poll_seconds=10, logon_types=[3, 10])
    monkeypatch.setattr(
        mon,
        "_query_4624_events",
        lambda _start: [
            {
                "LogonType": "3",
                "TargetUserName": "SYSTEM",
                "ProcessName": "C:\\Windows\\System32\\svchost.exe",
                "IpAddress": "-",
                "TimeCreated": "2026-03-02T18:01:00.000Z",
            }
        ],
    )

    assert mon._poll_once() == []
