from pathlib import Path

from argus.config import ArgusConfig
from argus.core import StateStore
from argus.daemon import ArgusDaemon
from argus.monitors import ThreatSignal


def test_lockdown_gate_requires_severity_and_confidence(tmp_path: Path) -> None:
    cfg = ArgusConfig()
    cfg.threat_response.lockdown_min_severity = "high"
    cfg.threat_response.lockdown_min_confidence = 0.9
    daemon = ArgusDaemon(cfg, StateStore(str(tmp_path / "state.json")))

    unknown_proc = ThreatSignal(
        event_type="process_tripwire",
        title="Unknown process outside allowlist",
        description="test",
        severity="high",
        confidence=0.8,
        category="execution",
    )
    assert daemon._should_trigger_lockdown(unknown_proc) is False

    critical = ThreatSignal(
        event_type="anti_tamper",
        title="Protected config changed",
        description="test",
        severity="critical",
        confidence=0.95,
        category="defense_evasion",
    )
    assert daemon._should_trigger_lockdown(critical) is True
