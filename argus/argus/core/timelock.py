"""Argus TimeLock - total system isolation for a configurable duration.

When a threat triggers LOCKDOWN, TimeLock:
1. Disables all network adapters (no reverse shells, no C2, no exfil).
2. Adds firewall block-all rules as a backup layer.
3. Locks the workstation.
4. Starts a countdown timer.  System cannot be disarmed until the timer expires.
5. Failed disarm attempts extend the timer.

State is persisted in state.json so it survives reboots - the machine
stays bricked for the full duration even if the attacker restarts it.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

log = logging.getLogger("argus.core.timelock")

# State dict keys
_KEY_ACTIVE = "timelock_active"
_KEY_EXPIRES = "timelock_expires_utc"
_KEY_ENGAGED = "timelock_engaged_utc"
_KEY_REASON = "timelock_reason"
_KEY_EXTENSIONS = "timelock_extensions"


def engage_timelock(
    state: dict,
    duration_minutes: int,
    reason: str = "lockdown",
    *,
    isolate: bool = True,
) -> datetime:
    """Engage the timelock.  Returns the expiry datetime (UTC).

    If timelock is already active, this extends it (doesn't reset it shorter).
    """
    from ..actions.network_isolation import isolate_network
    from ..actions.lock import lock_workstation

    now = datetime.now(timezone.utc)
    new_expiry = now + timedelta(minutes=duration_minutes)

    # Don't let a new engagement shorten an existing timelock
    existing_expiry = _get_expiry(state)
    if existing_expiry and existing_expiry > new_expiry:
        new_expiry = existing_expiry

    state[_KEY_ACTIVE] = True
    state[_KEY_EXPIRES] = new_expiry.isoformat()
    state[_KEY_ENGAGED] = now.isoformat()
    state[_KEY_REASON] = reason
    state.setdefault(_KEY_EXTENSIONS, 0)

    # Kill the network
    if isolate:
        ok = isolate_network()
        log.info("network isolation %s", "engaged" if ok else "FAILED (check admin privileges)")

    # Lock the workstation
    lock_workstation()
    log.info("timelock engaged: %d min, expires %s, reason=%s", duration_minutes, new_expiry, reason)

    return new_expiry


def extend_timelock(state: dict, additional_minutes: int, reason: str = "failed_disarm") -> datetime | None:
    """Extend an active timelock.  Returns the new expiry or None if not active."""
    if not is_timelocked(state):
        return None

    from ..actions.network_isolation import isolate_network
    from ..actions.lock import lock_workstation

    current_expiry = _get_expiry(state)
    if not current_expiry:
        return None

    new_expiry = current_expiry + timedelta(minutes=additional_minutes)
    state[_KEY_EXPIRES] = new_expiry.isoformat()
    state[_KEY_EXTENSIONS] = int(state.get(_KEY_EXTENSIONS, 0)) + 1

    # Re-enforce isolation (in case someone tried to re-enable adapters)
    isolate_network()
    lock_workstation()

    log.warning(
        "timelock EXTENDED by %d min (reason=%s, total extensions=%d, new expiry=%s)",
        additional_minutes, reason, state[_KEY_EXTENSIONS], new_expiry,
    )
    return new_expiry


def check_timelock(state: dict) -> tuple[bool, int]:
    """Check timelock status.

    Returns (is_locked, remaining_seconds).
    remaining_seconds is 0 if not locked.
    """
    if not state.get(_KEY_ACTIVE, False):
        return False, 0

    expiry = _get_expiry(state)
    if not expiry:
        return False, 0

    now = datetime.now(timezone.utc)
    if now >= expiry:
        # Timer expired - auto-release
        return False, 0

    remaining = int((expiry - now).total_seconds())
    return True, max(0, remaining)


def is_timelocked(state: dict) -> bool:
    """Quick check: is the system currently timelocked?"""
    locked, _ = check_timelock(state)
    return locked


def release_timelock(state: dict, *, restore_net: bool = True) -> bool:
    """Release the timelock and restore network.

    Only call this when the timer has expired or an authorized override occurs.
    Returns True if network was restored.
    """
    from ..actions.network_isolation import restore_network

    state[_KEY_ACTIVE] = False
    state[_KEY_EXPIRES] = None
    state[_KEY_ENGAGED] = None
    state[_KEY_REASON] = None
    state[_KEY_EXTENSIONS] = 0

    if restore_net:
        ok = restore_network()
        log.info("timelock released, network %s", "restored" if ok else "RESTORE FAILED")
        return ok

    log.info("timelock released (network restore skipped)")
    return True


def enforce_timelock(state: dict) -> None:
    """Re-enforce timelock isolation.

    Called on daemon startup to re-apply isolation if the system was
    rebooted while timelocked (attacker tried restarting to escape).
    """
    if not is_timelocked(state):
        return

    from ..actions.network_isolation import isolate_network
    from ..actions.lock import lock_workstation

    _, remaining = check_timelock(state)
    log.warning(
        "timelock still active on startup! Re-engaging isolation (%d seconds remaining)", remaining
    )
    isolate_network()
    lock_workstation()


def get_timelock_info(state: dict) -> dict:
    """Return timelock state info for status display."""
    locked, remaining = check_timelock(state)
    return {
        "active": locked,
        "remaining_seconds": remaining,
        "expires_utc": state.get(_KEY_EXPIRES),
        "engaged_utc": state.get(_KEY_ENGAGED),
        "reason": state.get(_KEY_REASON),
        "extensions": int(state.get(_KEY_EXTENSIONS, 0)),
    }


def _get_expiry(state: dict) -> datetime | None:
    raw = state.get(_KEY_EXPIRES)
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw))
    except Exception:
        return None
