"""Argus self-update — git pull + restart when instructed by manager."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("argus.updater")


def get_repo_dir() -> Path | None:
    """Find the git repo root for the argus package."""
    # Walk up from the argus package directory to find .git
    pkg_dir = Path(__file__).resolve().parent.parent  # argus/argus/core -> argus/
    for parent in [pkg_dir, pkg_dir.parent]:  # argus/, security-shallots/
        if (parent / ".git").exists():
            return parent
    return None


def get_current_version() -> str:
    """Return current git commit hash, or 'unknown'."""
    repo = get_repo_dir()
    if not repo:
        return "unknown"
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10,
            cwd=str(repo),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.stdout.strip() or "unknown"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return "unknown"


def check_for_updates() -> bool:
    """Check if remote has new commits. Returns True if updates available."""
    repo = get_repo_dir()
    if not repo:
        return False
    try:
        # Fetch without merging
        subprocess.run(
            ["git", "fetch", "--quiet"],
            capture_output=True, timeout=30,
            cwd=str(repo),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        # Compare local HEAD to remote
        result = subprocess.run(
            ["git", "rev-list", "HEAD..@{u}", "--count"],
            capture_output=True, text=True, timeout=10,
            cwd=str(repo),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        count = int(result.stdout.strip() or "0")
        return count > 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
        return False


def perform_update() -> bool:
    """Pull latest code. Returns True on success."""
    repo = get_repo_dir()
    if not repo:
        log.error("Cannot find git repo for update")
        return False
    try:
        result = subprocess.run(
            ["git", "pull", "--ff-only"],
            capture_output=True, text=True, timeout=60,
            cwd=str(repo),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            log.error("git pull failed: %s", result.stderr)
            return False
        log.info("Update pulled: %s", result.stdout.strip())

        # Reinstall package if pyproject.toml exists
        argus_dir = repo if (repo / "pyproject.toml").exists() else repo / "argus"
        if (argus_dir / "pyproject.toml").exists():
            subprocess.run(
                [sys.executable, "-m", "pip", "install", str(argus_dir), "--quiet"],
                capture_output=True, timeout=120,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        log.error("Update failed: %s", e)
        return False


def restart_daemon(config_path: str) -> None:
    """Restart the Argus daemon process."""
    cmd = [sys.executable, "-m", "argus", "--config", config_path, "on"]
    creationflags = 0
    if os.name == "nt":
        creationflags = 0x00000008 | 0x00000200
    try:
        subprocess.Popen(cmd, close_fds=True, creationflags=creationflags)
        log.info("Restart process launched, exiting current daemon")
    except OSError as e:
        log.error("Failed to restart: %s", e)
