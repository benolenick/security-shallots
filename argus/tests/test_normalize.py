from argus.models import ArgusEvent
from argus.normalize import normalize_alert


def test_normalize_alert_shape() -> None:
    event = ArgusEvent(
        timestamp="2026-03-02T00:00:00+00:00",
        severity=11,
        category="auth_failed",
        description="SSH authentication failure",
        src_ip="1.2.3.4",
        detector="journalctl.ssh_failed",
        raw={"message": "Failed password"},
    )

    out = normalize_alert(event)

    assert set(out.keys()) == {
        "timestamp",
        "source",
        "severity",
        "category",
        "src_ip",
        "dst_ip",
        "description",
        "raw",
    }
    assert out["source"] == "argus"
    assert out["severity"] == 11
    assert out["raw"]["detector"] == "journalctl.ssh_failed"
