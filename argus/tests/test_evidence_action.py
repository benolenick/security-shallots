import json
from pathlib import Path

from argus.actions.evidence import capture_evidence


def test_capture_evidence_writes_json(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    out_path = capture_evidence(".argus/evidence", recent_file_window_minutes=5)
    p = Path(out_path)
    assert p.exists()

    payload = json.loads(p.read_text(encoding="utf-8"))
    assert "captured_utc" in payload
    assert "processes" in payload
    assert "net_connections" in payload
    assert "recent_files" in payload
