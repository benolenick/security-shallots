"""Health checks for all Security Shallots components."""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import shutil
import subprocess
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shallots.config import Config

log = logging.getLogger(__name__)

# Minimum EVE/Wazuh file growth: if the file hasn't grown in this many
# seconds we consider the source stalled (but not necessarily down).
_FILE_STALENESS_SEC = 300  # 5 minutes


def _is_linux() -> bool:
    return platform.system() == "Linux"


def _process_running(name: str) -> bool:
    """Return True if a process with the given name is running (Linux only).

    Matches against the full command line (-f), not just the kernel `comm`
    name (-x): comm is truncated to 15 chars and some daemons rename their
    main thread (Suricata's is literally "Suricata-Main"), so an exact
    `-x suricata` match never fires even while Suricata is healthy and
    actively processing traffic - caught live on 2026-07-21 (eve.json was
    streaming real events the whole time this check said "not running").
    """
    if not _is_linux():
        return True  # On non-Linux (dev machine) we skip process checks
    try:
        result = subprocess.run(
            ["pgrep", "-f", name],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _file_exists_and_growing(path: str, staleness_sec: int = _FILE_STALENESS_SEC) -> tuple[bool, str]:
    """Check that a file exists and was modified recently.

    Returns (ok, detail_message).
    """
    if not os.path.exists(path):
        return False, f"file not found: {path}"
    try:
        stat = os.stat(path)
        age = time.time() - stat.st_mtime
        if stat.st_size == 0:
            return False, f"file is empty: {path}"
        if age > staleness_sec:
            mins = int(age // 60)
            return False, f"file not updated in {mins}m: {path}"
        return True, f"ok (size={stat.st_size}, age={int(age)}s)"
    except OSError as e:
        return False, str(e)


def _sqlite_db_growing(path: str, staleness_sec: int = _FILE_STALENESS_SEC) -> tuple[bool, str]:
    """Like _file_exists_and_growing, but WAL-aware.

    A SQLite DB in WAL mode (Pi-hole's pihole-FTL.db, notably) writes go to
    the -wal sidecar file; the base file's mtime only advances on a periodic
    checkpoint, which can be many minutes stale even while the DB is being
    written to constantly. Use the newest mtime among the base file, -wal,
    and -journal (older rollback-journal mode).
    """
    if not os.path.exists(path):
        return False, f"file not found: {path}"
    try:
        newest_mtime = os.stat(path).st_mtime
        size = os.stat(path).st_size
        for suffix in ("-wal", "-journal"):
            sidecar = path + suffix
            if os.path.exists(sidecar):
                newest_mtime = max(newest_mtime, os.stat(sidecar).st_mtime)
        age = time.time() - newest_mtime
        if size == 0:
            return False, f"file is empty: {path}"
        if age > staleness_sec:
            mins = int(age // 60)
            return False, f"db not updated in {mins}m (incl. -wal): {path}"
        return True, f"ok (size={size}, age={int(age)}s)"
    except OSError as e:
        return False, str(e)


def _disk_space(path: str = "/") -> tuple[bool, str]:
    """Check that disk usage is below 90%.

    Returns (ok, detail_message).
    """
    try:
        usage = shutil.disk_usage(path)
        pct = usage.used / usage.total * 100
        free_gb = usage.free / (1024 ** 3)
        detail = f"{pct:.1f}% used, {free_gb:.1f} GB free"
        return pct < 90, detail
    except Exception as e:
        return False, str(e)


def _ram_usage() -> tuple[bool, str]:
    """Check that RAM usage is below 90% (Linux only).

    Returns (ok, detail_message).
    """
    if not _is_linux():
        return True, "n/a (non-Linux)"
    try:
        with open("/proc/meminfo") as f:
            data = {}
            for line in f:
                key, _, val = line.partition(":")
                data[key.strip()] = val.strip().split()[0]  # value in kB
        total = int(data["MemTotal"])
        available = int(data["MemAvailable"])
        used = total - available
        pct = used / total * 100
        avail_mb = available // 1024
        detail = f"{pct:.1f}% used, {avail_mb} MB available"
        return pct < 90, detail
    except Exception as e:
        return False, str(e)


async def _reachable_http(url: str, timeout: float = 5.0) -> tuple[bool, str]:
    """Check that an HTTP endpoint responds with a non-5xx status.

    Returns (ok, detail_message).
    """
    try:
        import aiohttp
    except ImportError:
        return False, "aiohttp not installed"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status < 500:
                    return True, f"HTTP {resp.status}"
                return False, f"HTTP {resp.status}"
    except aiohttp.ClientConnectorError:
        return False, f"connection refused: {url}"
    except asyncio.TimeoutError:
        return False, f"timeout after {timeout}s"
    except Exception as e:
        return False, str(e)


async def _crowdsec_reachable(api_url: str, api_key: str) -> tuple[bool, str]:
    """Check CrowdSec LAPI by hitting GET /v1/decisions (expects 200 or 204).

    Returns (ok, detail_message).
    """
    try:
        import aiohttp
    except ImportError:
        return False, "aiohttp not installed"

    url = f"{api_url.rstrip('/')}/v1/decisions"
    headers = {"X-Api-Key": api_key}
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status in (200, 204):
                    return True, f"HTTP {resp.status}"
                if resp.status == 403:
                    return False, "auth failed (check api_key)"
                return False, f"HTTP {resp.status}"
    except aiohttp.ClientConnectorError:
        return False, f"connection refused: {api_url}"
    except asyncio.TimeoutError:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


async def _db_accessible(db_path: str) -> tuple[bool, str]:
    """Check that the SQLite DB file is accessible and responds to a query.

    Returns (ok, detail_message).
    """
    if not os.path.exists(db_path):
        return False, f"db file not found: {db_path}"
    try:
        import aiosqlite
        async with aiosqlite.connect(db_path) as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM alerts")
            row = await cursor.fetchone()
            count = row[0] if row else 0
        return True, f"ok ({count} alerts)"
    except ImportError:
        # Fall back to synchronous sqlite3
        try:
            import sqlite3
            loop = asyncio.get_running_loop()

            def _check() -> tuple[bool, str]:
                try:
                    con = sqlite3.connect(db_path, timeout=5)
                    cur = con.execute("SELECT COUNT(*) FROM alerts")
                    count = cur.fetchone()[0]
                    con.close()
                    return True, f"ok ({count} alerts)"
                except sqlite3.OperationalError as e:
                    return False, str(e)

            return await loop.run_in_executor(None, _check)
        except Exception as e:
            return False, str(e)
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def check_all(cfg: Config) -> list[tuple[str, bool, str]]:
    """Run all health checks and return results.

    Returns a list of (name, ok, detail) tuples. All checks run
    concurrently where possible.
    """
    results: list[tuple[str, bool, str]] = []

    # --- Suricata --------------------------------------------------------
    if cfg.components.suricata:
        suricata_running = _process_running("suricata")
        results.append(("suricata_process", suricata_running,
                        "running" if suricata_running else "not running"))

        eve_ok, eve_detail = _file_exists_and_growing(cfg.suricata.eve_path)
        results.append(("suricata_eve_file", eve_ok, eve_detail))

    # --- Wazuh -----------------------------------------------------------
    if cfg.components.wazuh:
        wazuh_running = _process_running("wazuh-analysisd")
        results.append(("wazuh_manager", wazuh_running,
                        "running" if wazuh_running else "not running"))

        wazuh_ok, wazuh_detail = _file_exists_and_growing(cfg.wazuh.alerts_path)
        results.append(("wazuh_alerts_file", wazuh_ok, wazuh_detail))

    # --- CrowdSec --------------------------------------------------------
    if cfg.components.crowdsec:
        cs_ok, cs_detail = await _crowdsec_reachable(
            cfg.crowdsec.api_url, cfg.crowdsec.api_key
        )
        results.append(("crowdsec_lapi", cs_ok, cs_detail))

    # --- Database --------------------------------------------------------
    db_ok, db_detail = await _db_accessible(cfg.storage.db_path)
    results.append(("database", db_ok, db_detail))

    # --- Pi-hole DNS detector ---------------------------------------------
    if cfg.pihole.dns_enabled:
        ph_ok, ph_detail = _sqlite_db_growing(cfg.pihole.db_path)
        results.append(("pihole_dns_source", ph_ok, ph_detail))

    # --- Command-execution monitor (auditd execve log) --------------------
    if cfg.execmon.enabled:
        # Longer staleness window than the default: a quiet host can
        # legitimately go a while without a new process exec, unlike DNS
        # queries or Suricata/Wazuh event streams.
        exec_ok, exec_detail = _file_exists_and_growing(
            cfg.execmon.audit_log_path, staleness_sec=1800,
        )
        results.append(("execmon_audit_log", exec_ok, exec_detail))

    # --- Ollama (if configured) ------------------------------------------
    if cfg.ai.tier == "local" and cfg.ai.ollama_url:
        ollama_ok, ollama_detail = await _reachable_http(
            f"{cfg.ai.ollama_url.rstrip('/')}/api/tags"
        )
        results.append(("ollama", ollama_ok, ollama_detail))

    # --- System resources ------------------------------------------------
    disk_ok, disk_detail = _disk_space("/")
    results.append(("disk_space", disk_ok, disk_detail))

    ram_ok, ram_detail = _ram_usage()
    results.append(("ram_usage", ram_ok, ram_detail))

    return results


def format_health_report(checks: list[tuple[str, bool, str]]) -> str:
    """Format health check results as a human-readable string."""
    lines = ["Health Check Report", "-" * 40]
    for name, ok, detail in checks:
        status = "OK  " if ok else "FAIL"
        lines.append(f"  [{status}] {name:<30} {detail}")
    lines.append("-" * 40)
    total = len(checks)
    passed = sum(1 for _, ok, _ in checks if ok)
    lines.append(f"  {passed}/{total} checks passed")
    return "\n".join(lines)
