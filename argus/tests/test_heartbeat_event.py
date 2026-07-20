from argus.core.events import make_heartbeat_event


def test_heartbeat_includes_host_metadata() -> None:
    event = make_heartbeat_event("host1", "ARMED_HOME", ["session"])

    assert event.details["os"]
    assert "ip_address" in event.details
    assert event.details["active_monitors"] == ["session"]
