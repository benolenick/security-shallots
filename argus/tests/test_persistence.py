from pathlib import Path

from argus.core.persistence import StateStore


def test_state_store_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "state.json"
    store = StateStore(str(p))
    st = store.load()
    st["enabled"] = True
    st["current_state"] = "ARMED_HOME"
    store.save(st)

    st2 = store.load()
    assert st2["enabled"] is True
    assert st2["current_state"] == "ARMED_HOME"
