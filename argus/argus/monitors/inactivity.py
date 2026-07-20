from __future__ import annotations

import os
import subprocess


def get_idle_seconds() -> int:
    if os.name != "nt":
        return _get_idle_seconds_linux()

    import ctypes

    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

    lii = LASTINPUTINFO()
    lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
    if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
        return 0
    now = ctypes.windll.kernel32.GetTickCount()
    elapsed_ms = int(now - lii.dwTime)
    return max(0, elapsed_ms // 1000)


def _get_idle_seconds_linux() -> int:
    """Detect user idle time on Linux.

    Tries xprintidle first (X11, returns ms), then loginctl IdleSinceHint,
    then falls back to 0.
    """
    # Try xprintidle (returns idle time in milliseconds)
    try:
        proc = subprocess.run(
            ["xprintidle"],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            raw = (proc.stdout or "").strip()
            if raw.isdigit():
                return int(raw) // 1000
    except FileNotFoundError:
        pass

    # Try loginctl show-session for IdleSinceHint (microseconds epoch timestamp)
    try:
        proc = subprocess.run(
            ["loginctl", "show-session", "--property=IdleSinceHint", "--value"],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            raw = (proc.stdout or "").strip()
            if raw.isdigit() and raw != "0":
                import time
                idle_since_us = int(raw)
                now_us = int(time.time() * 1_000_000)
                elapsed = (now_us - idle_since_us) // 1_000_000
                return max(0, elapsed)
    except FileNotFoundError:
        pass

    return 0
