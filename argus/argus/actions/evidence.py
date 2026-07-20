from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def capture_evidence(output_dir: str, recent_file_window_minutes: int = 5) -> str:
    out_root = Path(output_dir).expanduser()
    if not out_root.is_absolute():
        out_root = (Path.home() / out_root).resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = out_root / f"evidence_{ts}.json"

    payload: dict[str, Any] = {
        "captured_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hostname": os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "unknown",
        "processes": _capture_processes(),
        "net_connections": _capture_net_connections(),
        "recent_files": _capture_recent_files(minutes=recent_file_window_minutes),
    }

    # Best-effort screenshot capture
    _capture_screenshot(out_root, ts)

    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    return str(out_path)


def _capture_screenshot(output_dir: Path, timestamp: str) -> None:
    """Capture a screenshot if Pillow is available. Silently skipped otherwise."""
    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        screenshot_path = output_dir / f"screenshot_{timestamp}.png"
        img.save(str(screenshot_path), "PNG")
    except Exception:
        pass  # No Pillow, no display, or other issue - skip silently


def _capture_processes() -> list[dict[str, Any]]:
    if os.name == "nt":
        ps = (
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | "
            "ConvertTo-Json -Compress"
        )
        p = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return _json_or_empty(p.stdout)

    p = subprocess.run(["ps", "-eo", "pid,ppid,comm,args"], capture_output=True, text=True)
    rows = []
    for line in (p.stdout or "").splitlines()[1:]:
        parts = line.strip().split(None, 3)
        if len(parts) < 3:
            continue
        rows.append({
            "ProcessId": int(parts[0]),
            "ParentProcessId": int(parts[1]),
            "Name": parts[2],
            "CommandLine": parts[3] if len(parts) > 3 else parts[2],
        })
    return rows


def _capture_net_connections() -> list[dict[str, Any]]:
    if os.name == "nt":
        ps = (
            "Get-NetTCPConnection -State Established | "
            "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | "
            "ConvertTo-Json -Compress"
        )
        p = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return _json_or_empty(p.stdout)

    p = subprocess.run(["netstat", "-tn"], capture_output=True, text=True)
    rows = []
    for line in (p.stdout or "").splitlines():
        if not line.startswith("tcp"):
            continue
        parts = line.split()
        if len(parts) >= 6 and parts[5] == "ESTABLISHED":
            rows.append({"raw": line})
    return rows


def _capture_recent_files(minutes: int = 5) -> list[dict[str, Any]]:
    window = datetime.now(timezone.utc) - timedelta(minutes=max(1, int(minutes)))
    roots = [Path.home() / "Documents", Path.home() / ".ssh"]
    out: list[dict[str, Any]] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
            if mtime >= window:
                out.append({"path": str(path), "mtime_utc": mtime.isoformat(), "size": int(st.st_size)})
            if len(out) >= 500:
                return out
    return out


def _json_or_empty(raw: str | None) -> list[dict[str, Any]]:
    txt = (raw or "").strip()
    if not txt:
        return []
    try:
        parsed = json.loads(txt)
    except json.JSONDecodeError:
        return []
    if isinstance(parsed, list):
        return [x for x in parsed if isinstance(x, dict)]
    if isinstance(parsed, dict):
        return [parsed]
    return []
