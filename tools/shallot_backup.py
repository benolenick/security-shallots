"""Online SQLite backup for shallots.db with retention.

Uses sqlite3.backup() (online, doesn't lock writers) to copy the live DB to a
timestamped file, compresses with zstd if available (else gzip), snapshots
config.yaml alongside, and prunes per the retention policy.

Designed to run from a systemd timer once an hour. Safe to run while shallots
is processing alerts.

Retention (configurable via env):
  SHALLOT_BACKUP_HOURLY = 24   keep most recent 24 hourly snapshots
  SHALLOT_BACKUP_DAILY  = 14   keep most recent 14 daily snapshots
  SHALLOT_BACKUP_WEEKLY = 8    keep most recent 8 weekly snapshots

Layout:
  {dest}/hourly/shallots-YYYY-MM-DDTHH.tar.{zst|gz}
  {dest}/daily/shallots-YYYY-MM-DD.tar.{zst|gz}
  {dest}/weekly/shallots-YYYY-Wxx.tar.{zst|gz}

The hourly run also promotes a daily/weekly copy when the corresponding tier
is missing for that period. Promotion is a hard link so it costs no disk.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
from pathlib import Path

DEFAULT_DB = Path("/home/user/security-shallots/shallots.db")
DEFAULT_CONFIG = Path("/home/user/security-shallots/config.yaml")
DEFAULT_DEST = Path(os.environ.get("SHALLOT_BACKUP_DEST", "/var/lib/shallots/backups"))


def _online_backup(src: Path, dst_db: Path) -> None:
    src_conn = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    dst_conn = sqlite3.connect(dst_db)
    try:
        with dst_conn:
            src_conn.backup(dst_conn)
    finally:
        src_conn.close()
        dst_conn.close()


def _compress(tar_path: Path) -> Path:
    """Compress with zstd if `zstd` is available, else gzip in-process."""
    if shutil.which("zstd"):
        import subprocess

        out = tar_path.with_suffix(tar_path.suffix + ".zst")
        subprocess.run(
            ["zstd", "-q", "-19", "-f", "--rm", str(tar_path), "-o", str(out)],
            check=True,
        )
        return out
    import gzip

    out = tar_path.with_suffix(tar_path.suffix + ".gz")
    with open(tar_path, "rb") as fin, gzip.open(out, "wb", compresslevel=9) as fout:
        shutil.copyfileobj(fin, fout)
    tar_path.unlink()
    return out


def _make_snapshot(db: Path, config: Path, label: str, tier_dir: Path) -> Path:
    tier_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        snap_db = td_path / "shallots.db"
        _online_backup(db, snap_db)
        if config.exists():
            shutil.copy2(config, td_path / "config.yaml")

        tar_path = tier_dir / f"shallots-{label}.tar"
        with tarfile.open(tar_path, "w") as tar:
            for f in td_path.iterdir():
                tar.add(f, arcname=f.name)
        return _compress(tar_path)


def _prune(tier_dir: Path, keep: int) -> int:
    if not tier_dir.exists():
        return 0
    files = sorted(tier_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    pruned = 0
    for old in files[keep:]:
        try:
            old.unlink()
            pruned += 1
        except OSError:
            pass
    return pruned


def _promote(src: Path, tier_dir: Path, label: str) -> Path | None:
    """Hard-link the latest hourly snapshot into a higher tier if not already there."""
    tier_dir.mkdir(parents=True, exist_ok=True)
    suffix = "".join(src.suffixes)  # preserve .tar.zst / .tar.gz, not just last
    target = tier_dir / f"shallots-{label}{suffix}"
    if target.exists():
        return None
    try:
        os.link(src, target)
    except OSError:
        shutil.copy2(src, target)
    return target


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--db", type=Path, default=DEFAULT_DB)
    p.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    p.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    args = p.parse_args()

    if not args.db.exists():
        print(f"backup: db not found: {args.db}", file=sys.stderr)
        return 2

    args.dest.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now()
    hourly_label = now.strftime("%Y-%m-%dT%H")
    daily_label = now.strftime("%Y-%m-%d")
    weekly_label = now.strftime("%Y-W%V")

    keep_hourly = int(os.environ.get("SHALLOT_BACKUP_HOURLY", "24"))
    keep_daily = int(os.environ.get("SHALLOT_BACKUP_DAILY", "14"))
    keep_weekly = int(os.environ.get("SHALLOT_BACKUP_WEEKLY", "8"))

    hourly_dir = args.dest / "hourly"
    daily_dir = args.dest / "daily"
    weekly_dir = args.dest / "weekly"

    hourly = _make_snapshot(args.db, args.config, hourly_label, hourly_dir)
    print(f"backup: created {hourly}")

    promoted_d = _promote(hourly, daily_dir, daily_label)
    if promoted_d:
        print(f"backup: promoted to daily {promoted_d}")
    promoted_w = _promote(hourly, weekly_dir, weekly_label)
    if promoted_w:
        print(f"backup: promoted to weekly {promoted_w}")

    pruned = _prune(hourly_dir, keep_hourly)
    pruned += _prune(daily_dir, keep_daily)
    pruned += _prune(weekly_dir, keep_weekly)
    if pruned:
        print(f"backup: pruned {pruned} old snapshots")

    return 0


if __name__ == "__main__":
    sys.exit(main())
