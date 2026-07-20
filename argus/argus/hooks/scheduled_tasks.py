from __future__ import annotations

import subprocess
import sys
from pathlib import Path

LOCK_TASK_NAME = "Argus-OnLock"
UNLOCK_TASK_NAME = "Argus-OnUnlock"


def _create_task(name: str, schedule: str, command: str) -> None:
    base = [
        "schtasks",
        "/Create",
        "/TN",
        name,
        "/TR",
        f'cmd /c "{command}"',
        "/F",
    ]
    if schedule == "ONLOCK":
        args = base + ["/SC", "ONEVENT", "/EC", "Security", "/MO", "*[System[(EventID=4800)]]"]
    elif schedule == "ONUNLOCK":
        args = base + ["/SC", "ONEVENT", "/EC", "Security", "/MO", "*[System[(EventID=4801)]]"]
    else:
        raise ValueError(f"unsupported schedule: {schedule}")

    p = subprocess.run(args, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout).strip())


def install_lock_hooks(require_code: bool = True, config_path: str = "config.toml") -> None:
    py = Path(sys.executable).resolve()
    cfg = str(Path(config_path).resolve())
    on_cmd = f'"{py}" -m argus --config "{cfg}" on'
    disarm_cmd = f'"{py}" -m argus --config "{cfg}" disarm'

    _create_task(LOCK_TASK_NAME, "ONLOCK", on_cmd)
    if require_code:
        _create_task(UNLOCK_TASK_NAME, "ONUNLOCK", disarm_cmd)


def remove_lock_hooks() -> None:
    for task in (LOCK_TASK_NAME, UNLOCK_TASK_NAME):
        subprocess.run(["schtasks", "/Delete", "/TN", task, "/F"], capture_output=True, text=True)
