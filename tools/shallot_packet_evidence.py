#!/usr/bin/env python3
"""Manage bounded packet evidence for Security Shallots.

This intentionally implements a tiny evidence ring, not long-term full packet
capture. The ring is designed to give an analyst or upstream agent a short
packet window around a Scout card without turning Shallots into a storage sink.
"""

from __future__ import annotations

import argparse
import json
import os
import grp
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_RING_DIR = Path("/var/lib/shallots/pcap-ring")
DEFAULT_EVIDENCE_DIR = Path("/var/lib/shallots/evidence")
DEFAULT_UNIT = Path("/etc/systemd/system/shallot-pcap-ring.service")
DEFAULT_INTERFACE = "enp0s31f6"
DEFAULT_SIZE_MB = 16
DEFAULT_FILES = 64
DEFAULT_SNAP_FILES = 6


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def now_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def service_text(
    *,
    interface: str,
    ring_dir: Path,
    size_mb: int,
    files: int,
    packet_filter: str,
) -> str:
    capture = (
        f"/usr/bin/tcpdump -i {interface} -n -s 0 -U "
        f"-Z root -C {size_mb} -W {files} -w {ring_dir}/shallot-ring.pcap "
        f"{packet_filter}"
    ).strip()
    return f"""[Unit]
Description=Security Shallots bounded packet evidence ring
After=network-online.target
Wants=network-online.target
ConditionPathExists=/usr/bin/tcpdump

[Service]
Type=simple
User=root
Group=om
UMask=0027
ExecStartPre=/usr/bin/install -d -m 0750 -o root -g om {ring_dir}
ExecStart=/bin/sh -lc 'exec {capture}'
Restart=always
RestartSec=5
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""


def install(args: argparse.Namespace) -> dict[str, Any]:
    if not shutil.which("tcpdump"):
        raise SystemExit("tcpdump is required but was not found")
    evidence_dir = Path(args.evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chown(evidence_dir, 0, grp.getgrnam("om").gr_gid)
        evidence_dir.chmod(0o770)
    except PermissionError:
        pass
    text = service_text(
        interface=args.interface,
        ring_dir=Path(args.ring_dir),
        size_mb=args.size_mb,
        files=args.files,
        packet_filter=args.packet_filter,
    )
    unit = Path(args.unit)
    unit.write_text(text, encoding="utf-8")
    run(["systemctl", "daemon-reload"])
    if args.enable:
        run(["systemctl", "enable", "--now", unit.name])
    return {
        "installed": True,
        "unit": str(unit),
        "enabled": bool(args.enable),
        "ring_dir": str(args.ring_dir),
        "evidence_dir": str(args.evidence_dir),
        "size_mb": args.size_mb,
        "files": args.files,
        "max_ring_mb": args.size_mb * args.files,
        "interface": args.interface,
        "packet_filter": args.packet_filter,
    }


def status(args: argparse.Namespace) -> dict[str, Any]:
    ring_dir = Path(args.ring_dir)
    files = sorted(ring_dir.glob("shallot-ring.pcap*"))
    total_bytes = sum(p.stat().st_size for p in files if p.exists())
    active = run(["systemctl", "is-active", Path(args.unit).name], check=False)
    enabled = run(["systemctl", "is-enabled", Path(args.unit).name], check=False)
    newest = max(files, key=lambda p: p.stat().st_mtime, default=None)
    return {
        "unit": str(args.unit),
        "active": active.stdout.strip(),
        "enabled": enabled.stdout.strip(),
        "ring_dir": str(ring_dir),
        "file_count": len(files),
        "total_mb": round(total_bytes / (1024 * 1024), 2),
        "newest_file": str(newest) if newest else "",
        "newest_mtime": (
            datetime.fromtimestamp(newest.stat().st_mtime, timezone.utc).isoformat()
            if newest else ""
        ),
    }


def snapshot(args: argparse.Namespace) -> dict[str, Any]:
    ring_dir = Path(args.ring_dir)
    evidence_dir = Path(args.evidence_dir)
    target = evidence_dir / f"{args.case_id or 'manual'}-{now_id()}"
    target.mkdir(parents=True, exist_ok=True)
    files = sorted(
        ring_dir.glob("shallot-ring.pcap*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[: args.files]
    copied: list[str] = []
    for src in files:
        dst = target / src.name
        shutil.copy2(src, dst)
        copied.append(str(dst))
    manifest = {
        "case_id": args.case_id or "manual",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_ring": str(ring_dir),
        "files": copied,
    }
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--ring-dir", default=str(DEFAULT_RING_DIR))
    common.add_argument("--unit", default=str(DEFAULT_UNIT))

    p_install = sub.add_parser("install", parents=[common])
    p_install.add_argument("--interface", default=DEFAULT_INTERFACE)
    p_install.add_argument("--evidence-dir", default=str(DEFAULT_EVIDENCE_DIR))
    p_install.add_argument("--size-mb", type=int, default=DEFAULT_SIZE_MB)
    p_install.add_argument("--files", type=int, default=DEFAULT_FILES)
    p_install.add_argument(
        "--packet-filter",
        default="not port 11434 and not port 8844",
        help="tcpdump capture filter; default avoids local LLM and dashboard chatter",
    )
    p_install.add_argument("--enable", action="store_true")

    sub.add_parser("status", parents=[common])

    p_snap = sub.add_parser("snapshot", parents=[common])
    p_snap.add_argument("--evidence-dir", default=str(DEFAULT_EVIDENCE_DIR))
    p_snap.add_argument("--case-id", default="")
    p_snap.add_argument("--files", type=int, default=DEFAULT_SNAP_FILES)

    args = parser.parse_args()
    if args.cmd == "install":
        result = install(args)
    elif args.cmd == "status":
        result = status(args)
    elif args.cmd == "snapshot":
        result = snapshot(args)
    else:
        raise AssertionError(args.cmd)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for key, value in result.items():
            print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
