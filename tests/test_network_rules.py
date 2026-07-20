"""Network incident candidate rule tests."""

from __future__ import annotations

import json

import pytest

from shallots.ingest.syslog_receiver import parse_syslog, syslog_to_alert
from shallots.pipeline.network_rules import network_rule_hits


def test_suricata_malware_signature_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "suricata",
            "severity": "high",
            "title": "ET MALWARE Possible C2 Beacon",
            "category": "ET MALWARE",
        }
    )

    assert [h.rule_id for h in hits] == ["suricata.threat_signature"]


def test_suricata_critical_signature_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "suricata",
            "severity": "critical",
            "title": "ET POLICY Suspicious TLS Certificate Observed",
            "category": "ET POLICY",
        }
    )

    assert [h.rule_id for h in hits] == ["suricata.critical_signature"]


def test_suricata_info_signature_noise_is_not_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "suricata",
            "severity": "low",
            "title": "ET INFO Observed DNS Query to Public Resolver",
            "category": "ET INFO",
        }
    )

    assert hits == []


def test_wazuh_bruteforce_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "wazuh",
            "severity": "high",
            "title": "sshd: brute force trying to get access to the system. Non existent user. (host01)",
            "category": "syslog, sshd, authentication_failures",
        }
    )

    assert [h.rule_id for h in hits] == ["wazuh.auth_bruteforce"]
    assert hits[0].severity == "high"


def test_wazuh_single_auth_failure_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "wazuh",
            "severity": "medium",
            "title": "sshd: Attempt to login using a non-existent user (host01)",
            "category": "syslog, sshd, authentication_failed, invalid_login",
        }
    )

    assert [h.rule_id for h in hits] == ["wazuh.auth_failure"]
    assert hits[0].severity == "medium"


def test_local_syslog_test_is_not_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "high",
            "src_ip": "127.0.0.1",
            "description": "admin login failed",
        }
    )

    assert hits == []


def test_network_device_auth_failure_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "admin login failed from 192.168.0.99",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.auth_failure"]


def test_router_authentication_failed_phrase_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.2.1",
            "description": "web login failed: authentication failed for admin from 192.168.2.44",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.auth_failure"]


def test_router_port_scan_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Firewall detected port scan from 203.0.113.9 on WAN",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.network_attack"]


def test_router_upnp_port_mapping_is_exposure_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "UPnP port mapping added TCP 51413 to client 192.168.0.42",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.exposure_change"]
    assert hits[0].severity == "high"


def test_router_upnp_enabled_is_exposure_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "UPnP enabled by administrator",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.exposure_change"]
    assert hits[0].severity == "high"


def test_router_upnp_disabled_status_is_not_exposure_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "UPnP status: disabled",
        }
    )

    assert hits == []


def test_router_remote_management_enabled_is_exposure_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.2.1",
            "description": "Remote management enabled from WAN",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.exposure_change"]


def test_router_dns_setting_changed_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "WAN DNS servers changed to 203.0.113.53 and 198.51.100.53",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.dns_change"]
    assert hits[0].severity == "high"


def test_dhcp_dns_option_is_not_dns_change_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "DHCP lease renewed with DNS option 192.168.0.1 for known client",
        }
    )

    assert hits == []


def test_router_firmware_update_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Firmware update completed successfully, version 1.04 installed",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.firmware_change"]
    assert hits[0].severity == "high"


def test_router_firmware_version_status_is_not_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Current firmware version is 1.04",
        }
    )

    assert hits == []


def test_router_configuration_export_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Configuration backup downloaded by admin from 192.168.0.22",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.config_export"]
    assert hits[0].severity == "high"


def test_router_automatic_configuration_save_is_generic_device_change() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "configuration changed and saved automatically",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.device_change"]
    assert hits[0].severity == "medium"


def test_router_configuration_restore_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Configuration restored from uploaded backup file by admin",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.config_restore"]
    assert hits[0].severity == "high"


def test_router_scheduled_configuration_backup_is_not_restore_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Scheduled configuration backup completed successfully",
        }
    )

    assert hits == []


def test_router_factory_reset_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Factory defaults restored by administrator",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.factory_reset"]
    assert hits[0].severity == "high"


def test_router_reboot_completed_is_not_factory_reset() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "System reboot completed successfully",
        }
    )

    assert hits == []


def test_router_ntp_server_changed_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "NTP server changed to time.example.net by administrator",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.time_config_change"]
    assert hits[0].severity == "medium"


def test_router_ntp_synchronized_is_not_time_config_change() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "NTP synchronized successfully",
        }
    )

    assert hits == []


def test_router_admin_password_change_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "administrator password changed from LAN address 192.168.0.22",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.credential_change"]
    assert hits[0].severity == "high"


def test_invalid_admin_password_attempt_stays_auth_failure() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "invalid password for admin from 192.168.0.99",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.auth_failure"]


def test_admin_account_created_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Administrator account created for breakglass user",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.admin_account_change"]
    assert hits[0].severity == "high"


def test_admin_user_list_viewed_is_not_account_change() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Administrator user list viewed by admin",
        }
    )

    assert hits == []


def test_router_firewall_disabled_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "SPI firewall disabled by administrator",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.security_disabled"]
    assert hits[0].severity == "high"


def test_router_firewall_enabled_status_is_not_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "SPI firewall enabled",
        }
    )

    assert hits == []


def test_remote_syslog_disabled_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Remote syslog disabled by administrator",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.logging_disabled"]
    assert hits[0].severity == "high"


def test_system_log_viewed_is_not_logging_disabled() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "System log viewed by administrator",
        }
    )

    assert hits == []


def test_dhcp_reservation_added_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "DHCP reservation added for aa:bb:cc:dd:ee:ff at 192.168.0.44",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.dhcp_reservation_change"]
    assert hits[0].severity == "medium"


def test_guest_network_enabled_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Guest WiFi enabled by administrator",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.guest_network_change"]
    assert hits[0].severity == "medium"


def test_guest_client_join_is_not_guest_network_change() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Guest WiFi client aa:bb:cc:dd:ee:ff associated",
        }
    )

    assert hits == []


def test_wps_enabled_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "WPS enabled by administrator",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.wps_change"]
    assert hits[0].severity == "high"


def test_wps_disabled_status_is_not_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "WPS status: disabled",
        }
    )

    assert hits == []


def test_vpn_server_enabled_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "OpenVPN server enabled by administrator",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.vpn_exposure_change"]
    assert hits[0].severity == "high"


def test_vpn_client_connected_is_not_exposure_change() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "OpenVPN client connected from 198.51.100.23",
        }
    )

    assert hits == []


def test_dmz_host_enabled_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "DMZ host enabled for 192.168.0.55 by administrator",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.dmz_exposure_change"]
    assert hits[0].severity == "high"


def test_dmz_host_status_is_not_exposure_change() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "DMZ host status: disabled",
        }
    )

    assert hits == []


def test_wifi_security_disabled_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Wireless security disabled for primary SSID by administrator",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.wifi_security_change"]
    assert hits[0].severity == "high"


def test_wifi_client_status_is_not_wifi_security_change() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "WiFi client connected using WPA2",
        }
    )

    assert hits == []


def test_mac_filter_disabled_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "MAC filtering disabled by administrator",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.access_control_change"]
    assert hits[0].severity == "medium"


def test_allowed_wireless_client_is_not_access_control_change() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Wireless client aa:bb:cc:dd:ee:ff allowed",
        }
    )

    assert hits == []


def test_telnet_management_service_enabled_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Telnet server enabled by administrator",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.management_service_change"]
    assert hits[0].severity == "high"


def test_telnet_management_service_disabled_status_is_not_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Telnet server status: disabled",
        }
    )

    assert hits == []


def test_remote_admin_success_on_wan_is_critical_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "admin login successful from WAN address 203.0.113.44",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.remote_admin_success"]
    assert hits[0].severity == "critical"


def test_routine_dhcp_renewal_is_not_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "DHCP lease renewed for known client",
        }
    )

    assert hits == []


def test_new_dhcp_client_is_device_change_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "new DHCP client connected: unknown device aa:bb:cc:dd:ee:ff",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.device_change"]


def test_router_logged_in_from_wan_is_critical_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.2.1",
            "description": "administrator logged in from WAN address 203.0.113.44",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.remote_admin_success"]
    assert hits[0].severity == "critical"


def test_syslog_threat_keyword_is_critical_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "pfsense",
            "severity": "medium",
            "src_ip": "192.168.0.1",
            "description": "blocked possible malware c2 callback",
        }
    )

    assert [h.rule_id for h in hits] == ["syslog.threat_keyword"]


def test_syslog_alert_preserves_hostname_as_asset() -> None:
    parsed = parse_syslog(b"<134>Jul 15 04:20:00 dlink system: admin login failed")
    assert parsed is not None

    alert = syslog_to_alert(parsed, "192.168.0.1")

    assert alert.src_asset == "dlink"
    assert alert.src_ip == "192.168.0.1"


def test_argus_suspicious_egress_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "argus",
            "source_ref": "network_egress_suspicious",
            "severity": "high",
            "title": "Suspicious outbound connection",
        }
    )

    assert [h.rule_id for h in hits] == ["argus.suspicious_egress"]


@pytest.mark.parametrize(
    ("remote_ip", "remote_port"),
    (
        ("9.142.218.125", 6789),
        ("46.203.86.84", 5584),
        ("209.166.17.251", 6412),
        ("192.46.185.11", 5701),
        ("82.140.180.176", 7136),
        ("104.165.159.106", 5239),
        ("96.62.181.5", 7217),
        ("9.142.40.96", 6766),
        ("72.1.145.45", 5438),
        ("96.62.192.207", 7423),
        ("46.203.30.240", 6241),
        ("9.142.40.159", 6829),
        ("82.22.181.203", 7914),
        ("104.252.75.164", 5534),
        ("193.160.82.139", 6111),
        ("9.142.194.124", 6792),
        ("166.0.40.128", 7136),
        ("82.29.47.50", 7774),
        ("72.1.183.20", 5317),
        ("82.22.181.247", 7958),
        ("46.203.144.33", 7800),
        ("82.21.35.70", 7830),
    ),
)
def test_argus_python_unusual_port_is_candidate(remote_ip: str, remote_port: int) -> None:
    hits = network_rule_hits(
        {
            "source": "argus",
            "source_ref": "network_egress_suspicious",
            "severity": "high",
            "title": f"Suspicious outbound connection: python3 -> {remote_ip}:{remote_port}",
            "description": f"Process python3 opened an outbound connection to {remote_ip}:{remote_port} (suspicious_port).",
            "raw": json.dumps(
                {
                    "event_type": "network_egress_suspicious",
                    "details": {
                        "process": "python3",
                        "reason": "suspicious_port",
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                    },
                }
            ),
        }
    )

    assert [h.rule_id for h in hits] == ["argus.suspicious_egress"]


def test_argus_anti_tamper_is_critical_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "argus",
            "source_ref": "anti_tamper",
            "severity": "high",
            "title": "Protected config changed",
            "category": "defense_evasion",
        }
    )

    assert [h.rule_id for h in hits] == ["argus.anti_tamper"]
    assert hits[0].severity == "critical"


def test_argus_persistence_change_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "argus",
            "source_ref": "persistence_detected",
            "severity": "high",
            "title": "Persistence surface changed",
            "category": "persistence",
        }
    )

    assert [h.rule_id for h in hits] == ["argus.persistence_change"]


def test_argus_service_change_is_persistence_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "argus",
            "source_ref": "service_change",
            "severity": "high",
            "title": "Service changed",
            "category": "persistence",
        }
    )

    assert [h.rule_id for h in hits] == ["argus.persistence_change"]


def test_argus_wmi_persistence_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "argus",
            "source_ref": "wmi_persistence",
            "severity": "high",
            "title": "WMI persistence detected",
            "category": "persistence",
        }
    )

    assert [h.rule_id for h in hits] == ["argus.persistence_change"]


def test_argus_process_tripwire_is_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "argus",
            "source_ref": "process_tripwire",
            "severity": "high",
            "title": "Suspicious process started",
            "category": "process",
        }
    )

    assert [h.rule_id for h in hits] == ["argus.process_tripwire"]


def test_argus_qbittorrent_suspicious_port_is_not_incident_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "argus",
            "source_ref": "network_egress_suspicious",
            "severity": "high",
            "title": "Suspicious outbound connection: qbittorrent -> 91.145.49.80:51413",
            "description": "Process qbittorrent opened an outbound connection to 91.145.49.80:51413 (suspicious_port).",
            "category": "c2",
            "raw": json.dumps(
                {
                    "event_type": "network_egress_suspicious",
                    "details": {
                        "process": "qbittorrent",
                        "reason": "suspicious_port",
                        "remote_ip": "91.145.49.80",
                        "remote_port": 51413,
                    },
                }
            ),
        }
    )

    assert hits == []


def test_argus_allowed_wget_suspicious_port_is_not_incident_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "argus",
            "source_ref": "network_egress_suspicious",
            "severity": "high",
            "title": "Suspicious outbound connection: wget -> 203.0.113.10:7423",
            "description": "Process wget opened an outbound connection to 203.0.113.10:7423 (suspicious_port).",
            "raw": json.dumps(
                {
                    "event_type": "network_egress_suspicious",
                    "details": {
                        "process": "wget",
                        "reason": "suspicious_port",
                        "remote_ip": "203.0.113.10",
                        "remote_port": 7423,
                    },
                }
            ),
        }
    )

    assert hits == []


def test_argus_allowed_curl_suspicious_port_is_not_incident_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "argus",
            "source_ref": "network_egress_suspicious",
            "severity": "high",
            "title": "Suspicious outbound connection: curl -> 198.51.100.20:6666",
            "description": "Process curl opened an outbound connection to 198.51.100.20:6666 (suspicious_port).",
            "raw": json.dumps(
                {
                    "event_type": "network_egress_suspicious",
                    "details": {
                        "process": "curl",
                        "reason": "suspicious_port",
                        "remote_ip": "198.51.100.20",
                        "remote_port": 6666,
                    },
                }
            ),
        }
    )

    assert hits == []


def test_argus_allowed_syncthing_suspicious_port_is_not_incident_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "argus",
            "source_ref": "network_egress_suspicious",
            "severity": "high",
            "title": "Suspicious outbound connection: syncthing -> 198.51.100.31:22000",
            "description": "Process syncthing opened an outbound connection to 198.51.100.31:22000 (suspicious_port).",
            "raw": json.dumps(
                {
                    "event_type": "network_egress_suspicious",
                    "details": {
                        "process": "syncthing",
                        "reason": "suspicious_port",
                        "remote_ip": "198.51.100.31",
                        "remote_port": 22000,
                    },
                }
            ),
        }
    )

    assert hits == []


def test_argus_allowed_process_with_threat_terms_still_incident_candidate() -> None:
    hits = network_rule_hits(
        {
            "source": "argus",
            "source_ref": "network_egress_suspicious",
            "severity": "high",
            "title": "Suspicious outbound connection: qbittorrent possible malware C2",
            "description": "Process qbittorrent opened malware C2 public egress.",
            "category": "c2",
            "raw": json.dumps(
                {
                    "event_type": "network_egress_suspicious",
                    "details": {"process": "qbittorrent", "reason": "suspicious_port"},
                }
            ),
        }
    )

    assert [h.rule_id for h in hits] == ["argus.suspicious_egress"]
