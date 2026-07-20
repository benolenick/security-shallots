#!/usr/bin/env python3
"""Verify high-signal rule examples without ingesting alerts."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shallots.pipeline.network_rules import network_rule_hits


@dataclass(frozen=True)
class CanaryCase:
    name: str
    alert: dict[str, Any]
    expected_rule_ids: tuple[str, ...]


PYTHON_UNUSUAL_EGRESS_ENDPOINTS = (
    ("argus_python_unusual_port", "9.142.218.125", 6789),
    ("argus_python_unusual_port_alt", "46.203.86.84", 5584),
    ("argus_python_unusual_port_burst_209", "209.166.17.251", 6412),
    ("argus_python_unusual_port_burst_192", "192.46.185.11", 5701),
    ("argus_python_unusual_port_burst_82", "82.140.180.176", 7136),
    ("argus_python_unusual_port_burst_104", "104.165.159.106", 5239),
    ("argus_python_unusual_port_burst_96", "96.62.181.5", 7217),
    ("argus_python_unusual_port_burst_9_142_40", "9.142.40.96", 6766),
    ("argus_python_unusual_port_burst_72", "72.1.145.45", 5438),
    ("argus_python_unusual_port_burst_96_62_192", "96.62.192.207", 7423),
    ("argus_python_unusual_port_burst_46_203_30", "46.203.30.240", 6241),
    ("argus_python_unusual_port_burst_9_142_40_159", "9.142.40.159", 6829),
    ("argus_python_unusual_port_burst_82_22", "82.22.181.203", 7914),
    ("argus_python_unusual_port_burst_104_252", "104.252.75.164", 5534),
    ("argus_python_unusual_port_burst_193_160", "193.160.82.139", 6111),
    ("argus_python_unusual_port_burst_9_142_194", "9.142.194.124", 6792),
    ("argus_python_unusual_port_burst_166_0", "166.0.40.128", 7136),
    ("argus_python_unusual_port_burst_82_29", "82.29.47.50", 7774),
    ("argus_python_unusual_port_burst_72_1_183", "72.1.183.20", 5317),
    ("argus_python_unusual_port_burst_82_22_181", "82.22.181.247", 7958),
    ("argus_python_unusual_port_burst_46_203_144", "46.203.144.33", 7800),
    ("argus_python_unusual_port_burst_82_21_35", "82.21.35.70", 7830),
)


def _argus_python_unusual_port_cases() -> tuple[CanaryCase, ...]:
    return tuple(
        CanaryCase(
            name,
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
            },
            ("argus.suspicious_egress",),
        )
        for name, remote_ip, remote_port in PYTHON_UNUSUAL_EGRESS_ENDPOINTS
    )


CASES = (
    CanaryCase(
        "suricata_malware_c2",
        {
            "source": "suricata",
            "severity": "high",
            "title": "ET MALWARE Possible C2 Beacon",
            "category": "ET MALWARE",
        },
        ("suricata.threat_signature",),
    ),
    CanaryCase(
        "suricata_critical_signature",
        {
            "source": "suricata",
            "severity": "critical",
            "title": "ET POLICY Suspicious TLS Certificate Observed",
            "category": "ET POLICY",
        },
        ("suricata.critical_signature",),
    ),
    CanaryCase(
        "suricata_info_signature_noise",
        {
            "source": "suricata",
            "severity": "low",
            "title": "ET INFO Observed DNS Query to Public Resolver",
            "category": "ET INFO",
        },
        (),
    ),
    CanaryCase(
        "argus_suspicious_egress",
        {
            "source": "argus",
            "source_ref": "network_egress_suspicious",
            "severity": "high",
            "title": "Suspicious outbound connection",
        },
        ("argus.suspicious_egress",),
    ),
    *_argus_python_unusual_port_cases(),
    CanaryCase(
        "argus_anti_tamper",
        {
            "source": "argus",
            "source_ref": "anti_tamper",
            "severity": "high",
            "title": "Protected config changed",
            "category": "defense_evasion",
        },
        ("argus.anti_tamper",),
    ),
    CanaryCase(
        "argus_persistence_change",
        {
            "source": "argus",
            "source_ref": "persistence_detected",
            "severity": "high",
            "title": "Persistence surface changed",
            "category": "persistence",
        },
        ("argus.persistence_change",),
    ),
    CanaryCase(
        "argus_service_change",
        {
            "source": "argus",
            "source_ref": "service_change",
            "severity": "high",
            "title": "Service changed",
            "category": "persistence",
        },
        ("argus.persistence_change",),
    ),
    CanaryCase(
        "argus_process_tripwire",
        {
            "source": "argus",
            "source_ref": "process_tripwire",
            "severity": "high",
            "title": "Suspicious process started",
            "category": "process",
        },
        ("argus.process_tripwire",),
    ),
    CanaryCase(
        "router_auth_failure",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "admin login failed from 192.168.0.99",
        },
        ("syslog.auth_failure",),
    ),
    CanaryCase(
        "router_authentication_failed",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.2.1",
            "description": "web login failed: authentication failed for admin from 192.168.2.44",
        },
        ("syslog.auth_failure",),
    ),
    CanaryCase(
        "router_port_scan",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Firewall detected port scan from 203.0.113.9 on WAN",
        },
        ("syslog.network_attack",),
    ),
    CanaryCase(
        "router_upnp_mapping",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "UPnP port mapping added TCP 51413 to client 192.168.0.42",
        },
        ("syslog.exposure_change",),
    ),
    CanaryCase(
        "router_upnp_enabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "UPnP enabled by administrator",
        },
        ("syslog.exposure_change",),
    ),
    CanaryCase(
        "router_remote_management_enabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.2.1",
            "description": "Remote management enabled from WAN",
        },
        ("syslog.exposure_change",),
    ),
    CanaryCase(
        "router_dns_servers_changed",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "WAN DNS servers changed to 203.0.113.53 and 198.51.100.53",
        },
        ("syslog.dns_change",),
    ),
    CanaryCase(
        "router_firmware_update",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Firmware update completed successfully, version 1.04 installed",
        },
        ("syslog.firmware_change",),
    ),
    CanaryCase(
        "router_config_export",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Configuration backup downloaded by admin from 192.168.0.22",
        },
        ("syslog.config_export",),
    ),
    CanaryCase(
        "router_config_restore",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Configuration restored from uploaded backup file by admin",
        },
        ("syslog.config_restore",),
    ),
    CanaryCase(
        "router_factory_defaults_restored",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Factory defaults restored by administrator",
        },
        ("syslog.factory_reset",),
    ),
    CanaryCase(
        "router_ntp_server_changed",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "NTP server changed to time.example.net by administrator",
        },
        ("syslog.time_config_change",),
    ),
    CanaryCase(
        "router_admin_password_changed",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "administrator password changed from LAN address 192.168.0.22",
        },
        ("syslog.credential_change",),
    ),
    CanaryCase(
        "router_admin_account_created",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Administrator account created for breakglass user",
        },
        ("syslog.admin_account_change",),
    ),
    CanaryCase(
        "router_firewall_disabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "SPI firewall disabled by administrator",
        },
        ("syslog.security_disabled",),
    ),
    CanaryCase(
        "router_remote_syslog_disabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Remote syslog disabled by administrator",
        },
        ("syslog.logging_disabled",),
    ),
    CanaryCase(
        "router_dhcp_reservation_added",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "DHCP reservation added for aa:bb:cc:dd:ee:ff at 192.168.0.44",
        },
        ("syslog.dhcp_reservation_change",),
    ),
    CanaryCase(
        "router_guest_wifi_enabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Guest WiFi enabled by administrator",
        },
        ("syslog.guest_network_change",),
    ),
    CanaryCase(
        "router_wps_enabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "WPS enabled by administrator",
        },
        ("syslog.wps_change",),
    ),
    CanaryCase(
        "router_vpn_server_enabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "OpenVPN server enabled by administrator",
        },
        ("syslog.vpn_exposure_change",),
    ),
    CanaryCase(
        "router_dmz_host_enabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "DMZ host enabled for 192.168.0.55 by administrator",
        },
        ("syslog.dmz_exposure_change",),
    ),
    CanaryCase(
        "router_wifi_security_disabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Wireless security disabled for primary SSID by administrator",
        },
        ("syslog.wifi_security_change",),
    ),
    CanaryCase(
        "router_mac_filter_disabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "MAC filtering disabled by administrator",
        },
        ("syslog.access_control_change",),
    ),
    CanaryCase(
        "router_wan_admin_success",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "admin login successful from WAN address 203.0.113.44",
        },
        ("syslog.remote_admin_success",),
    ),
    CanaryCase(
        "router_wan_admin_logged_in",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.2.1",
            "description": "administrator logged in from WAN address 203.0.113.44",
        },
        ("syslog.remote_admin_success",),
    ),
    CanaryCase(
        "router_telnet_server_enabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Telnet server enabled by administrator",
        },
        ("syslog.management_service_change",),
    ),
    CanaryCase(
        "local_syslog_test",
        {
            "source": "syslog",
            "severity": "high",
            "src_ip": "127.0.0.1",
            "description": "admin login failed",
        },
        (),
    ),
    CanaryCase(
        "router_scheduled_config_backup",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Scheduled configuration backup completed successfully",
        },
        (),
    ),
    CanaryCase(
        "router_reboot_completed",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "System reboot completed successfully",
        },
        (),
    ),
    CanaryCase(
        "router_ntp_synchronized",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "NTP synchronized successfully",
        },
        (),
    ),
    CanaryCase(
        "argus_qbittorrent_suspicious_port",
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
        },
        (),
    ),
    CanaryCase(
        "argus_wget_allowed_process_suspicious_port",
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
        },
        (),
    ),
    CanaryCase(
        "argus_curl_allowed_process_suspicious_port",
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
        },
        (),
    ),
    CanaryCase(
        "argus_syncthing_allowed_process_suspicious_port",
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
        },
        (),
    ),
    CanaryCase(
        "router_wps_status_disabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "WPS status: disabled",
        },
        (),
    ),
    CanaryCase(
        "router_upnp_status_disabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "UPnP status: disabled",
        },
        (),
    ),
    CanaryCase(
        "router_telnet_server_status_disabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Telnet server status: disabled",
        },
        (),
    ),
    CanaryCase(
        "router_admin_user_list_viewed",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Administrator user list viewed by admin",
        },
        (),
    ),
    CanaryCase(
        "router_system_log_viewed",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "System log viewed by administrator",
        },
        (),
    ),
    CanaryCase(
        "router_vpn_client_connected",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "OpenVPN client connected from 198.51.100.23",
        },
        (),
    ),
    CanaryCase(
        "router_dmz_status_disabled",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "DMZ host status: disabled",
        },
        (),
    ),
    CanaryCase(
        "router_wifi_client_wpa2",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "WiFi client connected using WPA2",
        },
        (),
    ),
    CanaryCase(
        "router_wireless_client_allowed",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "Wireless client aa:bb:cc:dd:ee:ff allowed",
        },
        (),
    ),
    CanaryCase(
        "routine_dhcp",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "DHCP lease renewed for known client",
        },
        (),
    ),
    CanaryCase(
        "new_dhcp_client",
        {
            "source": "syslog",
            "severity": "low",
            "src_ip": "192.168.0.1",
            "description": "new DHCP client connected: unknown device aa:bb:cc:dd:ee:ff",
        },
        ("syslog.device_change",),
    ),
)


def run_cases(cases: tuple[CanaryCase, ...] = CASES) -> dict[str, Any]:
    results = []
    failures = []
    source_coverage: dict[str, dict[str, int]] = {}
    covered_rule_ids: set[str] = set()
    positive_cases = 0
    quiet_cases = 0
    for case in cases:
        actual = tuple(hit.rule_id for hit in network_rule_hits(case.alert))
        ok = actual == case.expected_rule_ids
        source = str(case.alert.get("source") or "unknown")
        bucket = source_coverage.setdefault(source, {"cases": 0, "passed": 0, "failed": 0})
        bucket["cases"] += 1
        if ok:
            bucket["passed"] += 1
        else:
            bucket["failed"] += 1
        if case.expected_rule_ids:
            positive_cases += 1
            covered_rule_ids.update(case.expected_rule_ids)
        else:
            quiet_cases += 1
        item = {
            "name": case.name,
            "ok": ok,
            "source": source,
            "expected": list(case.expected_rule_ids),
            "actual": list(actual),
        }
        results.append(item)
        if not ok:
            failures.append(item)
    total_cases = len(results)
    quiet_minimum = max(3, (total_cases + 5) // 6)
    source_minimums = {"argus": 3, "suricata": 2, "syslog": 5}
    source_headroom = {
        source: int((source_coverage.get(source) or {}).get("cases", 0)) - minimum
        for source, minimum in source_minimums.items()
    }
    return {
        "status": "ok" if not failures else "fail",
        "passed": len(results) - len(failures),
        "failed": len(failures),
        "coverage": {
            "total_cases": total_cases,
            "positive_cases": positive_cases,
            "quiet_cases": quiet_cases,
            "covered_rule_ids": sorted(covered_rule_ids),
            "sources": dict(sorted(source_coverage.items())),
        },
        "coverage_guardrails": {
            "quiet": {
                "minimum_cases": quiet_minimum,
                "headroom_cases": quiet_cases - quiet_minimum,
            },
            "sources": {
                "minimum_cases": source_minimums,
                "headroom_cases": source_headroom,
            },
        },
        "cases": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_cases()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"rule canary: {result['status']} ({result['passed']}/{len(result['cases'])} passed)")
        for case in result["cases"]:
            print(
                f"{'ok' if case['ok'] else 'fail':4} {case['name']}: "
                f"expected={case['expected']} actual={case['actual']}"
            )
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
