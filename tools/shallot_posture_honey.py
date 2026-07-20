#!/usr/bin/env python3
"""Tiny LAN honey listener for Shallots posture tripwires."""

from __future__ import annotations

import argparse
import json
import socket
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "posture.db"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_hit(addr: str, port: int, banner: str) -> None:
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, timeout=10)
    try:
        con.execute(
            """CREATE TABLE IF NOT EXISTS honey_hits(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               ts TEXT NOT NULL,
               src_ip TEXT NOT NULL,
               src_port INTEGER NOT NULL,
               banner TEXT NOT NULL
            )"""
        )
        con.execute("INSERT INTO honey_hits(ts,src_ip,src_port,banner) VALUES(?,?,?,?)", (now_iso(), addr, port, banner))
        con.execute(
            """CREATE TABLE IF NOT EXISTS posture_findings(
               id TEXT PRIMARY KEY, ts TEXT, category TEXT, severity TEXT, title TEXT,
               detail TEXT, entity TEXT DEFAULT '', status TEXT DEFAULT 'open', evidence TEXT DEFAULT '{}'
            )"""
        )
        fid = f"honey-{addr}-{port}-{now_iso()}"
        con.execute(
            "INSERT OR REPLACE INTO posture_findings VALUES(?,?,?,?,?,?,?,'open',?)",
            (fid, now_iso(), "honey", "high", "Honey listener touched", f"{addr}:{port}", addr, json.dumps({"banner": banner})),
        )
        con.commit()
    finally:
        con.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9922)
    parser.add_argument("--banner", default="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.listen(16)
    while True:
        conn, addr = sock.accept()
        with conn:
            log_hit(addr[0], addr[1], args.banner.strip())
            conn.sendall(args.banner.encode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

