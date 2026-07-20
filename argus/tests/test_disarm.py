from argus.core.disarm import clear_disarm_state, issue_disarm_code, verify_disarm_code


def test_disarm_issue_and_verify_ok() -> None:
    st = {
        "disarm_code": None,
        "disarm_expires_utc": None,
        "disarm_attempts": 0,
    }
    code = issue_disarm_code(st, ttl_seconds=60)
    assert len(code) == 4
    result = verify_disarm_code(st, code)
    assert result.ok
    clear_disarm_state(st)
    assert st["disarm_code"] is None
