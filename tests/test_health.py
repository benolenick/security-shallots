"""Tests for component-aware health checks."""

from __future__ import annotations

import pytest

from shallots.config import Config
from shallots.health import check_all


@pytest.mark.asyncio
async def test_check_all_skips_disabled_suricata(monkeypatch, tmp_db):
    cfg = Config()
    cfg.components.suricata = False
    cfg.components.wazuh = False
    cfg.components.crowdsec = False
    cfg.ai.tier = "none"
    cfg.storage.db_path = tmp_db.db_path

    def fail_process_check(_name: str) -> bool:
        raise AssertionError("disabled Suricata should not be probed")

    def fail_file_check(_path: str, staleness_sec: int = 300) -> tuple[bool, str]:
        raise AssertionError("disabled Suricata EVE file should not be probed")

    monkeypatch.setattr("shallots.health._process_running", fail_process_check)
    monkeypatch.setattr("shallots.health._file_exists_and_growing", fail_file_check)

    checks = await check_all(cfg)
    names = {name for name, _ok, _detail in checks}

    assert "suricata_process" not in names
    assert "suricata_eve_file" not in names
    assert "database" in names
