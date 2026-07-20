from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import secrets


DISARM_CODE_TTL_SECONDS = 60
DISARM_MAX_ATTEMPTS = 5


@dataclass(slots=True)
class DisarmStatus:
    ok: bool
    reason: str


def generate_code(length: int = 4) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def issue_disarm_code(state: dict, ttl_seconds: int = DISARM_CODE_TTL_SECONDS) -> str:
    code = generate_code()
    expires = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    state["disarm_code"] = code
    state["disarm_expires_utc"] = expires.isoformat()
    state["disarm_attempts"] = 0
    return code


def verify_disarm_code(state: dict, code: str, max_attempts: int = DISARM_MAX_ATTEMPTS) -> DisarmStatus:
    expected = str(state.get("disarm_code") or "")
    if not expected:
        return DisarmStatus(False, "no_code_issued")

    exp_raw = state.get("disarm_expires_utc")
    if not exp_raw:
        return DisarmStatus(False, "missing_expiry")

    try:
        exp = datetime.fromisoformat(str(exp_raw))
    except Exception:
        return DisarmStatus(False, "bad_expiry")

    if datetime.now(timezone.utc) > exp:
        return DisarmStatus(False, "expired")

    attempts = int(state.get("disarm_attempts", 0))
    if attempts >= max_attempts:
        return DisarmStatus(False, "max_attempts")

    if str(code).strip() != expected:
        state["disarm_attempts"] = attempts + 1
        return DisarmStatus(False, "invalid_code")

    return DisarmStatus(True, "ok")


def clear_disarm_state(state: dict) -> None:
    state["disarm_code"] = None
    state["disarm_expires_utc"] = None
    state["disarm_attempts"] = 0
