"""Conservative network alert promotion rules."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


THREAT_TERMS = (
    "malware",
    "trojan",
    "c2",
    "command and control",
    "beacon",
    "exploit",
    "credential",
    "lateral",
    "exfil",
    "ransom",
    "backdoor",
)

AUTH_TERMS = (
    "authentication failure",
    "authentication failed",
    "auth failed",
    "login failed",
    "failed login",
    "admin login failed",
    "web login failed",
    "invalid password",
    "bad password",
    "incorrect password",
)

NETWORK_ATTACK_TERMS = (
    "port scan",
    "portscan",
    "nmap",
    "syn flood",
    "udp flood",
    "icmp flood",
    "dos attack",
    "ddos",
    "brute force",
    "password spray",
)

EXPOSURE_CHANGE_TERMS = (
    "upnp enabled",
    "upnp service enabled",
    "upnp mapping",
    "upnp port mapping",
    "upnp add port",
    "port forward",
    "port forwarding",
    "virtual server",
    "nat rule added",
    "nat rule created",
    "wan access enabled",
    "remote management enabled",
    "remote admin enabled",
    "remote administration enabled",
)

DNS_CHANGE_TERMS = (
    "dns server changed",
    "dns servers changed",
    "dns setting changed",
    "dns settings changed",
    "primary dns changed",
    "secondary dns changed",
    "wan dns changed",
    "lan dns changed",
    "dns override enabled",
)

FIRMWARE_CHANGE_TERMS = (
    "firmware updated",
    "firmware update completed",
    "firmware upgraded",
    "firmware upgrade completed",
    "firmware downgraded",
    "firmware downgrade completed",
    "firmware image installed",
)

CONFIG_EXPORT_TERMS = (
    "configuration exported",
    "config exported",
    "configuration backup downloaded",
    "config backup downloaded",
    "configuration file downloaded",
    "config file downloaded",
    "backup configuration downloaded",
)

CONFIG_RESTORE_TERMS = (
    "configuration restored",
    "config restored",
    "configuration uploaded",
    "config uploaded",
    "configuration imported",
    "config imported",
    "configuration restore completed",
    "configuration file restored",
    "configuration file uploaded",
    "backup configuration restored",
)

FACTORY_RESET_TERMS = (
    "factory reset",
    "factory default restored",
    "factory defaults restored",
    "restored factory defaults",
    "restore factory defaults",
    "reset to factory defaults",
    "reset to default configuration",
    "default configuration restored",
)

TIME_CONFIG_CHANGE_TERMS = (
    "system time changed",
    "router time changed",
    "manual time set",
    "time server changed",
    "ntp server changed",
    "ntp setting changed",
    "ntp settings changed",
    "timezone changed",
    "time zone changed",
)

CREDENTIAL_CHANGE_TERMS = (
    "admin password changed",
    "administrator password changed",
    "password changed for admin",
    "password changed for administrator",
    "router password changed",
    "management password changed",
    "web admin password changed",
)

ADMIN_ACCOUNT_CHANGE_TERMS = (
    "admin user added",
    "administrator user added",
    "admin account created",
    "administrator account created",
    "new admin user",
    "new administrator account",
)

SECURITY_DISABLED_TERMS = (
    "firewall disabled",
    "spi firewall disabled",
    "packet filter disabled",
    "packet filtering disabled",
    "intrusion detection disabled",
    "ids disabled",
    "ips disabled",
    "dos protection disabled",
)

LOGGING_DISABLED_TERMS = (
    "system log disabled",
    "remote log disabled",
    "remote logging disabled",
    "syslog disabled",
    "remote syslog disabled",
    "audit log disabled",
    "audit logging disabled",
)

DHCP_RESERVATION_TERMS = (
    "dhcp reservation added",
    "dhcp reservation removed",
    "dhcp reservation changed",
    "static dhcp lease added",
    "static dhcp lease removed",
    "static dhcp lease changed",
    "address reservation added",
    "address reservation removed",
    "address reservation changed",
)

GUEST_NETWORK_CHANGE_TERMS = (
    "guest network enabled",
    "guest network disabled",
    "guest wifi enabled",
    "guest wifi disabled",
    "guest wi-fi enabled",
    "guest wi-fi disabled",
    "guest ssid enabled",
    "guest ssid disabled",
)

WPS_CHANGE_TERMS = (
    "wps enabled",
    "wps disabled",
    "wps pin enabled",
    "wps pin disabled",
    "wps push button enabled",
    "wps push button disabled",
)

VPN_EXPOSURE_CHANGE_TERMS = (
    "vpn server enabled",
    "vpn server disabled",
    "remote access vpn enabled",
    "remote access vpn disabled",
    "openvpn server enabled",
    "openvpn server disabled",
    "l2tp server enabled",
    "l2tp server disabled",
    "pptp server enabled",
    "pptp server disabled",
)

DMZ_EXPOSURE_CHANGE_TERMS = (
    "dmz host enabled",
    "dmz host disabled",
    "dmz enabled",
    "dmz disabled",
    "exposed host enabled",
    "exposed host disabled",
)

WIFI_SECURITY_CHANGE_TERMS = (
    "wireless security disabled",
    "wireless security enabled",
    "wifi security disabled",
    "wifi security enabled",
    "wi-fi security disabled",
    "wi-fi security enabled",
    "wireless encryption disabled",
    "wireless encryption enabled",
    "wifi encryption disabled",
    "wifi encryption enabled",
    "wpa disabled",
    "wpa enabled",
    "wpa2 disabled",
    "wpa2 enabled",
    "wpa3 disabled",
    "wpa3 enabled",
)

ACCESS_CONTROL_CHANGE_TERMS = (
    "mac filter enabled",
    "mac filter disabled",
    "mac filtering enabled",
    "mac filtering disabled",
    "wireless access control enabled",
    "wireless access control disabled",
    "access control enabled",
    "access control disabled",
    "device block list changed",
    "device allow list changed",
    "mac allow list changed",
    "mac block list changed",
)

REMOTE_ADMIN_TERMS = (
    "remote management login",
    "remote admin login",
    "admin login successful",
    "admin login succeeded",
    "administrator logged in",
    "administrator login successful",
    "administrator login succeeded",
    "web login success",
    "web login successful",
    "login success",
)

REMOTE_CONTEXT_TERMS = (
    "wan",
    "internet",
    "external",
    "remote",
    "public",
)

MANAGEMENT_SERVICE_CHANGE_TERMS = (
    "telnet server enabled",
    "telnet management enabled",
    "management telnet enabled",
    "ssh server enabled",
    "ssh management enabled",
    "management ssh enabled",
)

DEVICE_CHANGE_TERMS = (
    "configuration changed",
    "config changed",
    "admin login",
    "new device",
    "new dhcp",
    "dhcp new",
    "unknown client",
    "unknown device",
)

ARGUS_ALLOWED_EGRESS_PROCESSES = {
    "qbittorrent",
    "qbittorrent-nox",
    "firefox",
    "chrome",
    "chromium",
    "brave",
    "curl",
    "wget",
    "syncthing",
    "tailscale",
    "tailscaled",
}

@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    severity: str
    reason: str


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    severity: str
    reason: str


ARGUS_ENDPOINT_RULES = {
    "anti_tamper": RuleSpec("argus.anti_tamper", "critical", "Argus anti-tamper signal"),
    "persistence_detected": RuleSpec("argus.persistence_change", "high", "Argus persistence surface changed"),
    "registry_persistence": RuleSpec("argus.persistence_change", "high", "Argus registry persistence signal"),
    "wmi_persistence": RuleSpec("argus.persistence_change", "high", "Argus WMI persistence signal"),
    "linux_persistence": RuleSpec("argus.persistence_change", "high", "Argus Linux persistence signal"),
    "service_change": RuleSpec("argus.persistence_change", "high", "Argus service persistence surface changed"),
    "process_tripwire": RuleSpec("argus.process_tripwire", "high", "Argus process tripwire matched"),
}


def _field(alert: Any, key: str) -> Any:
    if hasattr(alert, "get"):
        return alert.get(key)
    try:
        return alert[key]
    except (IndexError, KeyError):
        return None


def _text(alert: Any) -> str:
    return " ".join(
        str(_field(alert, k) or "")
        for k in ("title", "description", "category", "source_ref", "raw")
    ).lower()


def _narrative_text(alert: Any) -> str:
    return " ".join(
        str(_field(alert, k) or "")
        for k in ("title", "description", "raw")
    ).lower()


def _raw_json(alert: Any) -> dict[str, Any]:
    raw = _field(alert, "raw")
    if not isinstance(raw, str) or not raw.strip().startswith("{"):
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _argus_detail(alert: Any, key: str) -> str:
    data = _raw_json(alert)
    details = data.get("details") if isinstance(data, dict) else {}
    if isinstance(details, dict) and details.get(key) is not None:
        return str(details.get(key) or "").strip().lower()
    text = _text(alert)
    if key == "process":
        match = re.search(r"\bprocess\s+([a-z0-9_.+-]+)\b", text)
        if match:
            return match.group(1).strip().lower()
    if key == "reason":
        match = re.search(r"\(([^)]+)\)", text)
        if match:
            return match.group(1).strip().lower()
    return ""


def network_rule_hits(alert: Any) -> list[RuleHit]:
    """Return named network-rule hits for a normalized alert mapping.

    These rules intentionally favor precision over volume. They identify
    candidate incidents for review; they do not mutate alert verdicts.
    """
    source = str(_field(alert, "source") or "").lower()
    severity = str(_field(alert, "severity") or "").lower()
    src_ip = str(_field(alert, "src_ip") or "")
    text = _text(alert)
    hits: list[RuleHit] = []

    if source == "suricata":
        if any(term in text for term in THREAT_TERMS):
            sev = "critical" if severity in {"critical", "high"} else "high"
            hits.append(RuleHit("suricata.threat_signature", sev, "Suricata threat signature keyword"))
        elif severity == "critical":
            hits.append(RuleHit("suricata.critical_signature", "critical", "Critical Suricata signature"))

    if source == "argus":
        source_ref = str(_field(alert, "source_ref") or "").lower()
        spec = ARGUS_ENDPOINT_RULES.get(source_ref)
        if spec:
            hits.append(RuleHit(spec.rule_id, spec.severity, spec.reason))
        if source_ref == "network_egress_suspicious":
            process = _argus_detail(alert, "process")
            threat_narrative = _narrative_text(alert)
            if process in ARGUS_ALLOWED_EGRESS_PROCESSES and not any(term in threat_narrative for term in THREAT_TERMS):
                return hits
            hits.append(RuleHit("argus.suspicious_egress", "high", "Argus detected suspicious public egress"))

    if source == "wazuh":
        if "brute force" in text or "authentication_failures" in text:
            hits.append(RuleHit("wazuh.auth_bruteforce", "high", "Wazuh reported SSH/authentication brute-force aggregation"))
        elif "authentication_failed" in text or "invalid_login" in text:
            hits.append(RuleHit("wazuh.auth_failure", "medium", "Wazuh reported endpoint authentication failure"))
        if "syscheck" in text or "fim event" in text:
            hits.append(RuleHit("wazuh.file_integrity", "high", "Wazuh reported file-integrity change"))
        if severity in {"critical", "high"} and not hits:
            hits.append(RuleHit("wazuh.high_severity", severity, "High severity Wazuh endpoint alert"))

    if source in {"syslog", "pfsense"}:
        if src_ip.startswith("127."):
            return hits
        if any(term in text for term in THREAT_TERMS):
            hits.append(RuleHit("syslog.threat_keyword", "critical", "Network device threat keyword"))
        if any(term in text for term in NETWORK_ATTACK_TERMS):
            hits.append(RuleHit("syslog.network_attack", "high", "Network device reported scan/flood/brute-force activity"))
        if any(term in text for term in EXPOSURE_CHANGE_TERMS):
            hits.append(RuleHit("syslog.exposure_change", "high", "Router/firewall exposure or remote-management setting changed"))
        if any(term in text for term in DNS_CHANGE_TERMS):
            hits.append(RuleHit("syslog.dns_change", "high", "Router/firewall DNS resolver setting changed"))
        if any(term in text for term in FIRMWARE_CHANGE_TERMS):
            hits.append(RuleHit("syslog.firmware_change", "high", "Router/firewall firmware changed"))
        if any(term in text for term in CONFIG_EXPORT_TERMS):
            hits.append(RuleHit("syslog.config_export", "high", "Router/firewall configuration exported"))
        if any(term in text for term in CONFIG_RESTORE_TERMS):
            hits.append(RuleHit("syslog.config_restore", "high", "Router/firewall configuration restored"))
        if any(term in text for term in FACTORY_RESET_TERMS):
            hits.append(RuleHit("syslog.factory_reset", "high", "Router/firewall factory reset or default config restored"))
        if any(term in text for term in TIME_CONFIG_CHANGE_TERMS):
            hits.append(RuleHit("syslog.time_config_change", "medium", "Router/firewall time or NTP setting changed"))
        if any(term in text for term in CREDENTIAL_CHANGE_TERMS):
            hits.append(RuleHit("syslog.credential_change", "high", "Router/firewall administrator credential changed"))
        if any(term in text for term in ADMIN_ACCOUNT_CHANGE_TERMS):
            hits.append(RuleHit("syslog.admin_account_change", "high", "Router/firewall administrator account changed"))
        if any(term in text for term in SECURITY_DISABLED_TERMS):
            hits.append(RuleHit("syslog.security_disabled", "high", "Router/firewall security control disabled"))
        if any(term in text for term in LOGGING_DISABLED_TERMS):
            hits.append(RuleHit("syslog.logging_disabled", "high", "Router/firewall logging disabled"))
        if any(term in text for term in DHCP_RESERVATION_TERMS):
            hits.append(RuleHit("syslog.dhcp_reservation_change", "medium", "Router/firewall DHCP reservation changed"))
        if any(term in text for term in GUEST_NETWORK_CHANGE_TERMS):
            hits.append(RuleHit("syslog.guest_network_change", "medium", "Router/firewall guest network setting changed"))
        if any(term in text for term in WPS_CHANGE_TERMS):
            hits.append(RuleHit("syslog.wps_change", "high", "Router/firewall WPS setting changed"))
        if any(term in text for term in VPN_EXPOSURE_CHANGE_TERMS):
            hits.append(RuleHit("syslog.vpn_exposure_change", "high", "Router/firewall VPN exposure setting changed"))
        if any(term in text for term in DMZ_EXPOSURE_CHANGE_TERMS):
            hits.append(RuleHit("syslog.dmz_exposure_change", "high", "Router/firewall DMZ exposure setting changed"))
        if any(term in text for term in WIFI_SECURITY_CHANGE_TERMS):
            hits.append(RuleHit("syslog.wifi_security_change", "high", "Router/firewall WiFi security setting changed"))
        if any(term in text for term in ACCESS_CONTROL_CHANGE_TERMS):
            hits.append(RuleHit("syslog.access_control_change", "medium", "Router/firewall access-control setting changed"))
        if any(term in text for term in MANAGEMENT_SERVICE_CHANGE_TERMS):
            hits.append(RuleHit("syslog.management_service_change", "high", "Router/firewall management service enabled"))
        if any(term in text for term in REMOTE_ADMIN_TERMS) and any(term in text for term in REMOTE_CONTEXT_TERMS):
            hits.append(RuleHit("syslog.remote_admin_success", "critical", "Remote/WAN administrator login succeeded"))
        if any(term in text for term in AUTH_TERMS):
            hits.append(RuleHit("syslog.auth_failure", "high", "Network device authentication failure"))
        elif not hits and any(term in text for term in DEVICE_CHANGE_TERMS):
            hits.append(RuleHit("syslog.device_change", "medium", "Network device state/configuration change"))
        if severity in {"critical", "high"} and not hits:
            hits.append(RuleHit("syslog.high_severity", severity, "High severity network device log"))

    return hits
