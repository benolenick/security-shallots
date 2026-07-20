from pathlib import Path

from argus.monitors.file_sentinel import FileSentinelConfig, FileSentinelMonitor


def test_file_sentinel_emits_on_change(tmp_path: Path) -> None:
    target = tmp_path / "x.txt"
    target.write_text("a", encoding="utf-8")

    mon = FileSentinelMonitor(FileSentinelConfig(enabled=True, poll_seconds=5, paths=[str(target)]))
    assert mon._poll_once() == []  # baseline

    target.write_text("bb", encoding="utf-8")
    out = mon._poll_once()
    assert len(out) == 1
    assert out[0].event_type == "file_sentinel"


def test_file_sentinel_expands_env_vars(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "secret.txt"
    target.write_text("a", encoding="utf-8")
    monkeypatch.setenv("ARGUS_TEST_PATH", str(tmp_path))

    mon = FileSentinelMonitor(
        FileSentinelConfig(enabled=True, poll_seconds=5, paths=["%ARGUS_TEST_PATH%\\secret.txt"])
    )
    assert mon._poll_once() == []  # baseline

    target.write_text("bb", encoding="utf-8")
    out = mon._poll_once()
    assert len(out) == 1
