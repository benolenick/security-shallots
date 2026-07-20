"""Tests for tools/shallot_backup.py - online backup + retention + idempotency."""
from __future__ import annotations

import importlib.util
import sqlite3
import sys
import tarfile
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "shallot_backup.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("shallot_backup", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["shallot_backup"] = mod
    spec.loader.exec_module(mod)
    return mod


def _make_db(path: Path, rows: int = 5) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE alerts(id INTEGER PRIMARY KEY, msg TEXT);"
    )
    conn.executemany(
        "INSERT INTO alerts(msg) VALUES (?)", [(f"alert-{i}",) for i in range(rows)]
    )
    conn.commit()
    conn.close()


def _run(monkeypatch, db: Path, config: Path, dest: Path) -> int:
    mod = _load_module()
    monkeypatch.setattr(sys, "argv", [
        "shallot_backup",
        "--db", str(db), "--config", str(config), "--dest", str(dest),
    ])
    return mod.main()


def test_creates_full_tier_layout(tmp_path, monkeypatch):
    db = tmp_path / "shallots.db"
    cfg = tmp_path / "config.yaml"
    dest = tmp_path / "backups"
    _make_db(db)
    cfg.write_text("site_id: test\n")

    rc = _run(monkeypatch, db, cfg, dest)
    assert rc == 0

    hourly = list((dest / "hourly").glob("*.tar*"))
    daily = list((dest / "daily").glob("*.tar*"))
    weekly = list((dest / "weekly").glob("*.tar*"))
    assert len(hourly) == 1
    assert len(daily) == 1
    assert len(weekly) == 1
    # All files preserve full .tar.{zst|gz} suffix
    for f in hourly + daily + weekly:
        suf = "".join(f.suffixes)
        assert suf in (".tar.zst", ".tar.gz"), suf


def test_idempotent_in_same_hour(tmp_path, monkeypatch):
    db = tmp_path / "shallots.db"
    cfg = tmp_path / "config.yaml"
    dest = tmp_path / "backups"
    _make_db(db)
    cfg.write_text("site_id: test\n")

    assert _run(monkeypatch, db, cfg, dest) == 0
    assert _run(monkeypatch, db, cfg, dest) == 0

    files = sorted(p for p in dest.rglob("*") if p.is_file())
    # Exactly three files (one per tier), no orphan .tar
    assert len(files) == 3, files
    assert all("".join(p.suffixes) in (".tar.zst", ".tar.gz") for p in files)


def test_snapshot_contains_db_and_config(tmp_path, monkeypatch):
    db = tmp_path / "shallots.db"
    cfg = tmp_path / "config.yaml"
    dest = tmp_path / "backups"
    _make_db(db, rows=3)
    cfg.write_text("site_id: test\nsecret: dont-leak\n")

    assert _run(monkeypatch, db, cfg, dest) == 0

    snap = next((dest / "hourly").iterdir())
    work = tmp_path / "extract"
    work.mkdir()
    # Decompress in-process: zstd or gz
    if snap.suffix == ".zst":
        try:
            import zstandard
        except ImportError:
            pytest.skip("zstandard not installed; skipping content check")
        tar_bytes = zstandard.ZstdDecompressor().decompress(snap.read_bytes())
        tar_path = work / "x.tar"
        tar_path.write_bytes(tar_bytes)
    else:
        import gzip, shutil
        tar_path = work / "x.tar"
        with gzip.open(snap, "rb") as fin, open(tar_path, "wb") as fout:
            shutil.copyfileobj(fin, fout)
    with tarfile.open(tar_path) as tar:
        names = sorted(m.name for m in tar.getmembers())
        assert names == ["config.yaml", "shallots.db"]
        tar.extractall(work, filter="data")
    restored_db = work / "shallots.db"
    rows = sqlite3.connect(restored_db).execute("SELECT count(*) FROM alerts").fetchone()
    assert rows == (3,)


def test_prune_keeps_only_n(tmp_path, monkeypatch):
    db = tmp_path / "shallots.db"
    cfg = tmp_path / "config.yaml"
    dest = tmp_path / "backups"
    _make_db(db)
    cfg.write_text("site_id: test\n")

    monkeypatch.setenv("SHALLOT_BACKUP_HOURLY", "2")
    monkeypatch.setenv("SHALLOT_BACKUP_DAILY", "2")
    monkeypatch.setenv("SHALLOT_BACKUP_WEEKLY", "2")

    hourly_dir = dest / "hourly"
    hourly_dir.mkdir(parents=True)
    # Fake older snapshots - pruning is by mtime, keep newest 2
    for i, label in enumerate(["2026-05-04T10", "2026-05-04T11", "2026-05-04T12"]):
        f = hourly_dir / f"shallots-{label}.tar.zst"
        f.write_bytes(b"old")
        # Stagger mtime so order is deterministic
        ts = time.time() - (10 - i) * 3600
        import os
        os.utime(f, (ts, ts))

    assert _run(monkeypatch, db, cfg, dest) == 0
    remaining = sorted(hourly_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    assert len(remaining) == 2
    # The newest is the freshly-created one
    assert remaining[0].stat().st_mtime > remaining[1].stat().st_mtime
