from argus.core.state import ArgusMode, ArgusStateMachine


def test_state_machine_basic_flow() -> None:
    sm = ArgusStateMachine(host="host1", initial=ArgusMode.DISARMED)

    t1 = sm.transition("arm", "manual")
    assert t1 is not None
    assert sm.state == ArgusMode.ARMED_HOME

    t2 = sm.transition("away_timeout", "idle")
    assert t2 is not None
    assert sm.state == ArgusMode.ARMED_AWAY

    t3 = sm.transition("threat_detected", "failed_logon")
    assert t3 is not None
    assert sm.state == ArgusMode.LOCKDOWN
    assert "workstation_locked" in t3.actions

    t4 = sm.transition("disarm", "owner_code")
    assert t4 is not None
    assert sm.state == ArgusMode.DISARMED
