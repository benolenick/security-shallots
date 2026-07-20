"""HTTP liveness watchdog for the shallots daemon.

Runs as a oneshot from a systemd timer. Hits the local /api/health endpoint;
if it fails three consecutive times (state persisted in /tmp), restarts the
service via `systemctl --user restart` (or system unit if running as root).

Designed for the home install at /home/user/security-shallots. Exits 0 on
success or restart-issued; exits 1 only if it cannot determine state.
"""
from __future__ import annotations

import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

STATE_FILE = Path("/tmp/shallot_watchdog.state.json")
HEALTH_URL = os.environ.get("SHALLOT_HEALTH_URL", "https://127.0.0.1:8844/api/health")
SERVICE = os.environ.get("SHALLOT_SERVICE", "shallotd-home.service")
MAX_FAILURES = int(os.environ.get("SHALLOT_WATCHDOG_MAX_FAILURES", "3"))
TIMEOUT_S = float(os.environ.get("SHALLOT_WATCHDOG_TIMEOUT_S", "5"))


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state))


def _probe() -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=TIMEOUT_S, context=ctx) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def _restart() -> bool:
    cmd = ["systemctl", "restart", SERVICE]
    try:
        subprocess.run(cmd, check=True, timeout=30)
        return True
    except Exception as e:
        print(f"watchdog: restart failed: {e}", file=sys.stderr)
        return False


def main() -> int:
    state = _load_state()
    fails = int(state.get("consecutive_failures", 0))
    now = int(time.time())

    if _probe():
        if fails:
            print(f"watchdog: recovered after {fails} failures")
        _save_state({"consecutive_failures": 0, "last_ok": now})
        return 0

    fails += 1
    state["consecutive_failures"] = fails
    state["last_failure"] = now
    _save_state(state)
    print(f"watchdog: probe failed ({fails}/{MAX_FAILURES})", file=sys.stderr)

    if fails >= MAX_FAILURES:
        print(f"watchdog: restarting {SERVICE}", file=sys.stderr)
        if _restart():
            _save_state({"consecutive_failures": 0, "last_restart": now})
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
