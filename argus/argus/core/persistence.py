from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import os

from .state import ArgusMode


DEFAULT_STATE = {
    "enabled": False,
    "monitor_pid": None,
    "last_poll_utc": None,
    "current_state": ArgusMode.DISARMED.value,
    "disarm_code": None,
    "disarm_expires_utc": None,
    "disarm_attempts": 0,
}


class StateStore:
    def __init__(self, state_path: str) -> None:
        self.path = Path(state_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict:
        if not self.path.exists():
            return dict(DEFAULT_STATE)
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                out = dict(DEFAULT_STATE)
                out.update(data)
                return out
        except Exception:
            pass
        return dict(DEFAULT_STATE)

    def save(self, state: dict) -> None:
        self.path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    def mark_poll(self, state: dict) -> None:
        state["last_poll_utc"] = datetime.now(timezone.utc).isoformat()


def pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    if os.name == "nt":
        import subprocess

        p = subprocess.run(
            ["tasklist", "/FI", f"PID eq {int(pid)}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
        )
        out = (p.stdout or "").strip()
        if not out or "No tasks are running" in out:
            return False
        return str(int(pid)) in out
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def stop_pid(pid: int | None) -> None:
    if not pid:
        return
    if os.name == "nt":
        import subprocess

        subprocess.run(["taskkill", "/PID", str(int(pid)), "/T", "/F"], capture_output=True, text=True)
    else:
        os.kill(int(pid), 15)
