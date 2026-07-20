from __future__ import annotations

import logging
import os
import subprocess

log = logging.getLogger("argus.actions.lock")


def lock_workstation() -> None:
    if os.name == "nt":
        subprocess.run(
            ["rundll32.exe", "user32.dll,LockWorkStation"],
            capture_output=True,
            text=True,
        )
        return

    # Linux: try loginctl lock-sessions (systemd)
    try:
        result = subprocess.run(
            ["loginctl", "lock-sessions"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            log.info("workstation locked via loginctl")
            return
        log.warning("loginctl lock-sessions failed (rc=%d): %s", result.returncode, result.stderr.strip())
    except FileNotFoundError:
        log.warning("loginctl not found")

    # Fallback: headless servers typically cannot lock a screen
    log.info("workstation lock not available on this Linux system (headless server?)")
