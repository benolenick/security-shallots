"""Noise-control classifier tests."""

from __future__ import annotations

import ipaddress

from shallots.pipeline.classifier import Classifier, ClassifierConfig
from shallots.store.models import Alert


def test_suppresses_synthetic_experiment_assets() -> None:
    alert = Alert(
        source="argus",
        src_asset="shallot-load-api-8844-abc",
        severity="high",
        title="Something scary from a load agent",
    )

    out = Classifier().classify(alert)

    assert out.verdict == "suppress"
    assert "synthetic" in out.ai_reasoning


def test_suppresses_startup_state_change() -> None:
    alert = Alert(
        source="argus",
        src_asset="host04",
        severity="low",
        title="State changed: DISARMED -> ARMED_HOME",
        category="state_management",
    )

    out = Classifier().classify(alert)

    assert out.verdict == "suppress"


def test_does_not_suppress_real_security_title() -> None:
    alert = Alert(
        source="suricata",
        src_asset="host02",
        severity="critical",
        title="ET MALWARE Possible C2 Beacon",
        category="ET MALWARE",
    )

    out = Classifier().classify(alert)

    assert out.verdict == "pending"
    assert out.severity == "high"


def test_suppresses_argus_persistence_without_diff_details() -> None:
    alert = Alert(
        source="argus",
        source_ref="persistence_detected",
        severity="high",
        title="Persistence surface changed",
        category="persistence",
        raw='{"details": {}}',
    )

    out = Classifier().classify(alert)

    assert out.verdict == "suppress"
    assert "persistence maintenance" in out.ai_reasoning


def test_operator_configured_maintenance_persistence_diff() -> None:
    """An operator's OWN app services are treated as maintenance only after they
    are declared in config.suppression.maintenance_persistence_patterns — no
    fleet-specific paths are baked into the shipped defaults."""
    from shallots.config import Config

    def app_alert() -> Alert:
        return Alert(
            source="argus",
            source_ref="persistence_detected",
            severity="high",
            title="Persistence surface changed",
            category="persistence",
            raw='{"details": {"added_lines": ["*/30 * * * * cd /opt/myapp && .venv/bin/python worker.py", "myapp-runner.service enabled enabled", "402 unit files listed."], "removed_lines": ["401 unit files listed."]}}',
        )

    import shallots.pipeline.classifier as _clf_mod

    saved = list(_clf_mod._KNOWN_MAINTENANCE_PERSISTENCE_PATTERNS)
    try:
        # Out of the box, an unknown app service change stays visible for a human look.
        assert Classifier().classify(app_alert()).verdict == "pending"

        # Once the operator declares their app's paths/units, it becomes maintenance.
        cfg = Config()
        cfg.suppression.maintenance_persistence_patterns = ["/opt/myapp", "myapp-runner.service"]
        clf = Classifier.from_config(cfg)
        assert clf.classify(app_alert()).verdict == "suppress"
    finally:
        _clf_mod._KNOWN_MAINTENANCE_PERSISTENCE_PATTERNS[:] = saved


def test_suppresses_known_observability_service_persistence_diff() -> None:
    alert = Alert(
        source="argus",
        source_ref="persistence_detected",
        severity="high",
        title="Persistence surface changed",
        category="persistence",
        raw='{"details": {"added_lines": ["grafana-server.service enabled enabled", "victorialogs.service enabled enabled", "crowdsec.service enabled enabled"], "removed_lines": ["279 unit files listed."]}}',
    )

    out = Classifier().classify(alert)

    assert out.verdict == "suppress"
    assert "persistence maintenance" in out.ai_reasoning


def test_keeps_unknown_persistence_diff_visible() -> None:
    alert = Alert(
        source="argus",
        source_ref="persistence_detected",
        severity="high",
        title="Persistence surface changed",
        category="persistence",
        raw='{"details": {"added_lines": ["* * * * * /tmp/.x/.payload --beacon"], "removed_lines": []}}',
    )

    out = Classifier().classify(alert)

    assert out.verdict == "pending"


def test_suppresses_suricata_stream_invalid_ack_variants() -> None:
    for title in (
        "SURICATA STREAM ESTABLISHED invalid ack",
        "SURICATA STREAM FIN invalid ack",
        "SURICATA STREAM Packet with invalid ack",
    ):
        alert = Alert(source="suricata", severity="medium", title=title)

        out = Classifier().classify(alert)

        assert out.verdict == "suppress"
        assert "title matched" in out.ai_reasoning


def test_suppresses_known_remote_access_dns_info_noise() -> None:
    for title in (
        "ET INFO GNU/Linux APT User-Agent Outbound likely related to package management",
        "ET INFO Observed Cloudflare DNS over HTTPS Domain (cloudflare-dns .com in TLS SNI)",
        "ET INFO DNS Query to Cloudflare Tunneling Domain (argotunnel .com)",
        "ET INFO Remote Monitoring and Management (RMM) Tool in DNS Lookup (* .remotedesktop .google .com)",
    ):
        alert = Alert(source="suricata", severity="medium", category="Misc activity", title=title)

        out = Classifier().classify(alert)

        assert out.verdict == "suppress"


def test_suppresses_malformed_argus_lateral_session() -> None:
    alert = Alert(
        source="argus",
        severity="high",
        title="Session activity detected",
        category="lateral_movement",
        src_ip="5733).%1",
    )

    out = Classifier().classify(alert)

    assert out.verdict == "suppress"
    assert "malformed Argus session" in out.ai_reasoning


def test_keeps_valid_argus_lateral_session_visible() -> None:
    alert = Alert(
        source="argus",
        severity="high",
        title="Session activity detected",
        category="lateral_movement",
        src_ip="203.0.113.10",
    )

    out = Classifier().classify(alert)

    assert out.verdict == "pending"


def test_suppresses_crowdsec_active_decision_without_local_target() -> None:
    alert = Alert(
        source="crowdsec",
        severity="high",
        title="CrowdSec BAN: 203.0.113.10 (http:bruteforce)",
        category="crowdsec/ban",
        src_ip="203.0.113.10",
    )

    out = Classifier().classify(alert)

    assert out.verdict == "suppress"
    assert "CrowdSec decision already enforced" in out.ai_reasoning


def test_keeps_crowdsec_decision_with_local_target_visible() -> None:
    alert = Alert(
        source="crowdsec",
        severity="high",
        title="CrowdSec BAN: 203.0.113.10 (http:bruteforce)",
        category="crowdsec/ban",
        src_ip="203.0.113.10",
        dst_ip="192.168.0.172",
    )

    out = Classifier().classify(alert)

    assert out.verdict == "pending"


def test_high_signal_wazuh_bypasses_lan_cidr_suppression() -> None:
    cfg = ClassifierConfig(
        suppress_source_cidrs=[ipaddress.ip_network("192.168.0.0/24")],
        suppress_dest_cidrs=[ipaddress.ip_network("192.168.0.0/24")],
    )
    alert = Alert(
        source="wazuh",
        severity="high",
        src_ip="192.168.0.212",
        title="sshd: brute force trying to get access to the system. Non existent user. (host01)",
        category="syslog, sshd, authentication_failures",
    )

    out = Classifier(cfg).classify(alert)

    assert out.verdict == "pending"


def test_medium_wazuh_invalid_login_still_respects_lan_cidr_suppression() -> None:
    cfg = ClassifierConfig(
        suppress_source_cidrs=[ipaddress.ip_network("192.168.0.0/24")],
    )
    alert = Alert(
        source="wazuh",
        severity="medium",
        src_ip="192.168.0.212",
        title="sshd: Attempt to login using a non-existent user (host01)",
        category="syslog, sshd, authentication_failed, invalid_login",
    )

    out = Classifier(cfg).classify(alert)

    assert out.verdict == "suppress"


def test_wazuh_ssh_success_gets_native_suppression_reason() -> None:
    alert = Alert(
        source="wazuh",
        severity="low",
        src_ip="192.168.0.212",
        title="sshd: authentication success. (host01)",
        category="syslog, sshd, authentication_success",
    )

    out = Classifier().classify(alert)

    assert out.verdict == "suppress"
    assert "title matched" in out.ai_reasoning


def test_high_suricata_bypasses_lan_cidr_suppression() -> None:
    cfg = ClassifierConfig(
        suppress_source_cidrs=[ipaddress.ip_network("192.168.0.0/24")],
        suppress_dest_cidrs=[ipaddress.ip_network("192.168.0.0/24")],
    )
    alert = Alert(
        source="suricata",
        severity="high",
        src_ip="192.168.0.224",
        dst_ip="192.168.0.172",
        title="ET DNS Query to a *.top domain - Likely Hostile",
        category="Potentially Bad Traffic",
    )

    out = Classifier(cfg).classify(alert)

    assert out.verdict == "pending"


def test_medium_suricata_still_respects_lan_cidr_suppression() -> None:
    cfg = ClassifierConfig(
        suppress_source_cidrs=[ipaddress.ip_network("192.168.0.0/24")],
    )
    alert = Alert(
        source="suricata",
        severity="medium",
        src_ip="192.168.0.224",
        title="ET INFO Observed DNS Query",
        category="Misc activity",
    )

    out = Classifier(cfg).classify(alert)

    assert out.verdict == "suppress"


def test_critical_suricata_bypasses_exact_source_ip_suppression() -> None:
    # A critical exploit sig from an ALLOWLISTED internal IP (e.g. a compromised
    # host doing lateral movement) must not be hard-dropped by the source_ips
    # allowlist — it should reach AI triage (verdict stays pending).
    cfg = ClassifierConfig(suppress_source_ips={"192.168.0.172"})
    alert = Alert(
        source="suricata",
        severity="critical",
        src_ip="192.168.0.172",
        dst_ip="192.168.0.1",
        title="ET EXPLOIT D-Link HNAP SOAPAction Command Injection",
        category="Attempted Administrator Privilege Gain",
    )
    out = Classifier(cfg).classify(alert)
    assert out.verdict == "pending"


def test_low_alert_still_respects_exact_source_ip_suppression() -> None:
    # Non-high-signal noise from the same allowlisted IP is still suppressed.
    cfg = ClassifierConfig(suppress_source_ips={"192.168.0.172"})
    alert = Alert(
        source="suricata",
        severity="low",
        src_ip="192.168.0.172",
        dst_ip="192.168.0.212",
        title="ET INFO Observed DNS Query",
        category="Misc activity",
    )
    out = Classifier(cfg).classify(alert)
    assert out.verdict == "suppress"


def test_high_signal_bypasses_exact_dest_ip_suppression() -> None:
    cfg = ClassifierConfig(suppress_dest_ips={"192.168.0.172"})
    alert = Alert(
        source="suricata",
        severity="critical",
        src_ip="192.168.0.224",
        dst_ip="192.168.0.172",
        title="ET SCAN Possible Nmap User-Agent Observed",
        category="Attempted Information Leak",
    )
    out = Classifier(cfg).classify(alert)
    assert out.verdict == "pending"


def test_suppresses_fim_event_on_shallot_own_unit() -> None:
    alert = Alert(
        source="wazuh",
        severity="medium",
        title="File added to the system. (host01)",
        description="Rule 554 (level 5): File added to the system. | File: /etc/systemd/system/shallot-inventory-scan.timer",
    )
    out = Classifier().classify(alert)
    assert out.verdict == "suppress"
    assert "self-file" in out.ai_reasoning


def test_keeps_fim_event_on_foreign_unit_visible() -> None:
    alert = Alert(
        source="wazuh",
        severity="medium",
        title="File added to the system. (host01)",
        description="Rule 554 (level 5): File added to the system. | File: /etc/systemd/system/evil-persist.service",
    )
    out = Classifier().classify(alert)
    assert out.verdict != "suppress"
