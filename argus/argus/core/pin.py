"""Persistent PIN management for Argus disarm.

PIN is stored as a PBKDF2-HMAC-SHA256 hash — never in plaintext.
Supports set, verify, and change operations.
"""
from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass

log = logging.getLogger("argus.core.pin")

_ITERATIONS = 260_000  # OWASP 2023 recommendation for PBKDF2-SHA256
_HASH_LEN = 32
_SALT_LEN = 16


@dataclass(slots=True)
class PinStatus:
    ok: bool
    reason: str


def hash_pin(pin: str) -> str:
    """Hash a PIN with a random salt.  Returns 'salt_hex:hash_hex'."""
    salt = os.urandom(_SALT_LEN)
    dk = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, _ITERATIONS, dklen=_HASH_LEN)
    return f"{salt.hex()}:{dk.hex()}"


def verify_pin(pin: str, stored_hash: str) -> bool:
    """Verify a PIN against a stored 'salt_hex:hash_hex' string."""
    if not stored_hash or ":" not in stored_hash:
        return False
    try:
        salt_hex, hash_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, _ITERATIONS, dklen=_HASH_LEN)
    return dk == expected


def validate_pin_format(pin: str) -> PinStatus:
    """Check that a PIN meets requirements (4-8 digits)."""
    pin = pin.strip()
    if not pin:
        return PinStatus(False, "empty")
    if not pin.isdigit():
        return PinStatus(False, "must_be_digits")
    if len(pin) < 4:
        return PinStatus(False, "too_short")
    if len(pin) > 8:
        return PinStatus(False, "too_long")
    # Reject trivial PINs
    if len(set(pin)) == 1:  # e.g. 1111, 0000
        return PinStatus(False, "too_simple")
    if pin in ("1234", "12345", "123456", "1234567", "12345678",
               "4321", "54321", "654321", "7654321", "87654321"):
        return PinStatus(False, "too_simple")
    return PinStatus(True, "ok")


def set_pin(state: dict, pin: str) -> PinStatus:
    """Set a new PIN.  Validates format, hashes, and stores in state."""
    status = validate_pin_format(pin)
    if not status.ok:
        return status
    state["pin_hash"] = hash_pin(pin)
    log.info("PIN set successfully")
    return PinStatus(True, "ok")


def check_pin(state: dict, pin: str) -> PinStatus:
    """Verify a PIN against the stored hash."""
    stored = state.get("pin_hash", "")
    if not stored:
        return PinStatus(False, "no_pin_set")
    if verify_pin(pin.strip(), stored):
        return PinStatus(True, "ok")
    return PinStatus(False, "wrong_pin")


def has_pin(state: dict) -> bool:
    """Check if a PIN has been configured."""
    return bool(state.get("pin_hash", ""))


def clear_pin(state: dict) -> None:
    """Remove the stored PIN."""
    state["pin_hash"] = ""
