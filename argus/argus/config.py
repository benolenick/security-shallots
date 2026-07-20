from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json
import socket

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


@dataclass(slots=True)
class GuardConfig:
    inactivity_timeout_seconds: int = 600
    heartbeat_seconds: int = 120


@dataclass(slots=True)
class SmsConfig:
    enabled: bool = False
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    from_number: str = ""
    to_number: str = ""


@dataclass(slots=True)
class WindowsEventsConfig:
    enabled: bool = True
    poll_seconds: int = 15
    watch_event_ids: list[int] = field(default_factory=lambda: [
        4625, 4720, 4728, 4732, 4740, 1102,  # original: failed logon, account changes, audit clear
        4648, 4672, 4688, 4698, 4702, 4719,   # cred use, admin logon, process create, schtask, audit change
        4624, 4756, 4757, 4769,               # logon (filtered), universal groups, kerberoasting
    ])


@dataclass(slots=True)
class JsonlConfig:
    enabled: bool = True
    directory: str = ".argus/events"


@dataclass(slots=True)
class ProcessMonitorConfig:
    enabled: bool = False
    poll_seconds: int = 10
    allowlist: list[str] = field(
        default_factory=lambda: [
            r"C:\\Windows\\*",
            r"C:\\Program Files\\*",
            r"C:\\Program Files (x86)\\*",
            r"%USERPROFILE%\\AppData\\Local\\Programs\\*",
        ]
    )
    denylist: list[str] = field(
        default_factory=lambda: [
            "*mimikatz*",
            "*procdump*",
            "*rundll32* comsvcs.dll*",
        ]
    )
    alert_on_unknown: bool = True


@dataclass(slots=True)
class FileSentinelConfig:
    enabled: bool = False
    poll_seconds: int = 5
    paths: list[str] = field(
        default_factory=lambda: [
            r"%USERPROFILE%\\Documents\\credentials.kdbx",
            r"%USERPROFILE%\\.ssh\\id_ed25519",
        ]
    )


@dataclass(slots=True)
class PersistenceMonitorConfig:
    enabled: bool = False
    poll_seconds: int = 30
    watch_paths: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AntiTamperConfig:
    enabled: bool = False
    poll_seconds: int = 15
    watch_files: list[str] = field(default_factory=lambda: [".argus/state.json", "config.toml"])
    required_tasks: list[str] = field(default_factory=lambda: ["Argus-OnLock", "Argus-OnUnlock"])


@dataclass(slots=True)
class SessionMonitorConfig:
    enabled: bool = False
    poll_seconds: int = 10
    logon_types: list[int] = field(default_factory=lambda: [3, 10])


@dataclass(slots=True)
class UsbMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 10


@dataclass(slots=True)
class DnsMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 30
    suspicious_tlds: list[str] = field(
        default_factory=lambda: [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".buzz", ".club"]
    )
    entropy_threshold: float = 3.5


@dataclass(slots=True)
class RegistryMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 30
    watch_keys: list[str] = field(
        default_factory=lambda: [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        ]
    )


@dataclass(slots=True)
class ServiceMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 60
    suspicious_paths: list[str] = field(
        default_factory=lambda: ["%temp%", "\\appdata\\", "\\downloads\\", "\\users\\public\\"]
    )


@dataclass(slots=True)
class AuditPolicyConfig:
    enabled: bool = True
    poll_seconds: int = 300


@dataclass(slots=True)
class FirewallMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 300
    suspicious_ports: list[int] = field(
        default_factory=lambda: [4444, 5555, 8888, 9001, 1234, 6666]
    )


@dataclass(slots=True)
class NetworkEgressConfig:
    enabled: bool = False
    poll_seconds: int = 60
    suspicious_ports: list[int] = field(default_factory=lambda: [4444, 5555, 6666, 9001, 1234, 1337, 31337])
    suspicious_processes: list[str] = field(
        default_factory=lambda: ["nc", "ncat", "netcat", "socat", "plink", "chisel", "ligolo", "ngrok"]
    )
    process_allowlist: list[str] = field(
        default_factory=lambda: [
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
        ]
    )


@dataclass(slots=True)
class PostureMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 3600


@dataclass(slots=True)
class BrowserExtensionConfig:
    enabled: bool = True
    poll_seconds: int = 300


@dataclass(slots=True)
class WmiSubsConfig:
    enabled: bool = True
    poll_seconds: int = 120


@dataclass(slots=True)
class AdsMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 300
    scan_dirs: list[str] = field(
        default_factory=lambda: [
            r"%USERPROFILE%\Desktop",
            r"%USERPROFILE%\Downloads",
            r"%USERPROFILE%\Documents",
            r"%TEMP%",
        ]
    )


@dataclass(slots=True)
class EvidenceConfig:
    enabled: bool = True
    output_dir: str = ".argus/evidence"
    recent_file_window_minutes: int = 5


@dataclass(slots=True)
class TimeLockConfig:
    enabled: bool = True
    lockdown_mode: str = "reactive"  # "reactive" = kill network + lock | "passive" = alert + evidence only
    duration_minutes: int = 15
    network_isolation: bool = True
    extend_on_failed_disarm_minutes: int = 5


@dataclass(slots=True)
class ThreatResponseConfig:
    # Master kill-switch. When False, LOCKDOWN is never auto-triggered no
    # matter what severity/confidence the signal carries. Manual transitions
    # (CLI `argus on/off`, screen-lock hooks) still work.
    # Default True for backwards compat. Set False during soft-launch so a
    # noisy monitor (e.g. firewall_monitor flagging iptables-not-loaded on
    # an ufw box) cannot cause unintended LOCKDOWN.
    lockdown_enabled: bool = True
    lockdown_min_severity: str = "high"
    lockdown_min_confidence: float = 0.9


@dataclass(slots=True)
class MeteringConfig:
    # "standard" keeps current behavior close to historical defaults. "lite"
    # applies conservative fleet-safe defaults unless a field is explicitly set.
    profile: str = "standard"
    queue_max_signals: int = 4096
    max_signal_payload_bytes: int = 262144
    max_signals_per_minute: int = 0
    loop_jitter_percent: float = 0.0
    backoff_seconds: float = 0.0
    cycle_time_budget_seconds: float = 0.0
    cpu_max_load_per_core: float = 0.0
    disk_min_free_mb: int = 50
    disk_min_free_percent: float = 0.0
    reserve_severity: str = "high"


@dataclass(slots=True)
class WebhookSinkConfig:
    enabled: bool = False
    url: str = ""
    secret: str = ""
    timeout_seconds: int = 5
    verify_tls: bool = True   # verify the manager's TLS cert (set false only for self-signed)
    ca_cert: str = ""         # path to a CA/pinned cert for a self-signed manager
    allow_self_update: bool = False  # honor a manager "update" command (git pull + restart)


@dataclass(slots=True)
class SyslogSinkConfig:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 5514
    protocol: str = "udp"


@dataclass(slots=True)
class ListenerConfig:
    """LAN disarm HTTP listener. Accepts HMAC-signed requests from Lumen portal."""
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 8913
    secret: str = ""


@dataclass(slots=True)
class ArgusConfig:
    hostname: str = ""
    guard: GuardConfig = field(default_factory=GuardConfig)
    sms: SmsConfig = field(default_factory=SmsConfig)
    windows_events: WindowsEventsConfig = field(default_factory=WindowsEventsConfig)
    jsonl: JsonlConfig = field(default_factory=JsonlConfig)
    process_monitor: ProcessMonitorConfig = field(default_factory=ProcessMonitorConfig)
    file_sentinel: FileSentinelConfig = field(default_factory=FileSentinelConfig)
    persistence_monitor: PersistenceMonitorConfig = field(default_factory=PersistenceMonitorConfig)
    anti_tamper: AntiTamperConfig = field(default_factory=AntiTamperConfig)
    session_monitor: SessionMonitorConfig = field(default_factory=SessionMonitorConfig)
    usb_monitor: UsbMonitorConfig = field(default_factory=UsbMonitorConfig)
    dns_monitor: DnsMonitorConfig = field(default_factory=DnsMonitorConfig)
    registry_monitor: RegistryMonitorConfig = field(default_factory=RegistryMonitorConfig)
    service_monitor: ServiceMonitorConfig = field(default_factory=ServiceMonitorConfig)
    audit_policy: AuditPolicyConfig = field(default_factory=AuditPolicyConfig)
    firewall_monitor: FirewallMonitorConfig = field(default_factory=FirewallMonitorConfig)
    network_egress: NetworkEgressConfig = field(default_factory=NetworkEgressConfig)
    posture_monitor: PostureMonitorConfig = field(default_factory=PostureMonitorConfig)
    browser_extensions: BrowserExtensionConfig = field(default_factory=BrowserExtensionConfig)
    wmi_subs: WmiSubsConfig = field(default_factory=WmiSubsConfig)
    ads_monitor: AdsMonitorConfig = field(default_factory=AdsMonitorConfig)
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)
    timelock: TimeLockConfig = field(default_factory=TimeLockConfig)
    threat_response: ThreatResponseConfig = field(default_factory=ThreatResponseConfig)
    metering: MeteringConfig = field(default_factory=MeteringConfig)
    webhook: WebhookSinkConfig = field(default_factory=WebhookSinkConfig)
    syslog: SyslogSinkConfig = field(default_factory=SyslogSinkConfig)
    listener: ListenerConfig = field(default_factory=ListenerConfig)

    def resolved_hostname(self) -> str:
        return self.hostname.strip() or socket.gethostname()


def _read_dict(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".toml", ".tml"}:
        if tomllib is None:
            raise RuntimeError("tomllib unavailable; use Python 3.11+ for TOML config")
        parsed = tomllib.loads(raw)
        return parsed if isinstance(parsed, dict) else {}

    if path.suffix.lower() in {".json"}:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}

    try:
        import yaml  # type: ignore

        parsed = yaml.safe_load(raw)
        return parsed if isinstance(parsed, dict) else {}
    except ModuleNotFoundError as exc:
        raise RuntimeError("YAML config requires PyYAML; use TOML or JSON") from exc


def _get(d: dict[str, Any], key: str, default: Any) -> Any:
    value = d.get(key, default)
    return default if value is None else value


def _metering_config(raw: dict[str, Any]) -> MeteringConfig:
    profile = str(_get(raw, "profile", "standard")).strip().lower() or "standard"
    profile_defaults: dict[str, Any]
    if profile == "lite":
        profile_defaults = {
            "queue_max_signals": 256,
            "max_signal_payload_bytes": 32768,
            "max_signals_per_minute": 120,
            "loop_jitter_percent": 0.2,
            "backoff_seconds": 2.0,
            "cycle_time_budget_seconds": 10.0,
            "cpu_max_load_per_core": 2.0,
            "disk_min_free_mb": 512,
            "disk_min_free_percent": 5.0,
            "reserve_severity": "high",
        }
    else:
        profile = "standard"
        profile_defaults = {
            "queue_max_signals": 4096,
            "max_signal_payload_bytes": 262144,
            "max_signals_per_minute": 0,
            "loop_jitter_percent": 0.0,
            "backoff_seconds": 0.0,
            "cycle_time_budget_seconds": 0.0,
            "cpu_max_load_per_core": 0.0,
            "disk_min_free_mb": 50,
            "disk_min_free_percent": 0.0,
            "reserve_severity": "high",
        }

    return MeteringConfig(
        profile=profile,
        queue_max_signals=max(1, int(_get(raw, "queue_max_signals", profile_defaults["queue_max_signals"]))),
        max_signal_payload_bytes=max(
            0, int(_get(raw, "max_signal_payload_bytes", profile_defaults["max_signal_payload_bytes"]))
        ),
        max_signals_per_minute=max(
            0, int(_get(raw, "max_signals_per_minute", profile_defaults["max_signals_per_minute"]))
        ),
        loop_jitter_percent=max(
            0.0, min(1.0, float(_get(raw, "loop_jitter_percent", profile_defaults["loop_jitter_percent"])))
        ),
        backoff_seconds=max(0.0, float(_get(raw, "backoff_seconds", profile_defaults["backoff_seconds"]))),
        cycle_time_budget_seconds=max(
            0.0, float(_get(raw, "cycle_time_budget_seconds", profile_defaults["cycle_time_budget_seconds"]))
        ),
        cpu_max_load_per_core=max(
            0.0, float(_get(raw, "cpu_max_load_per_core", profile_defaults["cpu_max_load_per_core"]))
        ),
        disk_min_free_mb=max(0, int(_get(raw, "disk_min_free_mb", profile_defaults["disk_min_free_mb"]))),
        disk_min_free_percent=max(
            0.0, min(100.0, float(_get(raw, "disk_min_free_percent", profile_defaults["disk_min_free_percent"])))
        ),
        reserve_severity=str(_get(raw, "reserve_severity", profile_defaults["reserve_severity"])).strip().lower(),
    )


def load_config(path: str) -> ArgusConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"config not found: {p}")

    raw = _read_dict(p)
    argus_raw = raw.get("argus", raw if "guard" in raw else {})
    if not isinstance(argus_raw, dict):
        argus_raw = {}

    guard_raw = argus_raw.get("guard", {}) if isinstance(argus_raw.get("guard", {}), dict) else {}
    sms_raw = argus_raw.get("sms", {}) if isinstance(argus_raw.get("sms", {}), dict) else {}
    win_raw = (
        argus_raw.get("windows_events", {}) if isinstance(argus_raw.get("windows_events", {}), dict) else {}
    )
    jsonl_raw = argus_raw.get("jsonl", {}) if isinstance(argus_raw.get("jsonl", {}), dict) else {}
    proc_raw = argus_raw.get("process_monitor", {}) if isinstance(argus_raw.get("process_monitor", {}), dict) else {}
    files_raw = argus_raw.get("file_sentinel", {}) if isinstance(argus_raw.get("file_sentinel", {}), dict) else {}
    persist_raw = (
        argus_raw.get("persistence_monitor", {})
        if isinstance(argus_raw.get("persistence_monitor", {}), dict)
        else {}
    )
    tamper_raw = argus_raw.get("anti_tamper", {}) if isinstance(argus_raw.get("anti_tamper", {}), dict) else {}
    session_raw = (
        argus_raw.get("session_monitor", {}) if isinstance(argus_raw.get("session_monitor", {}), dict) else {}
    )
    usb_raw = argus_raw.get("usb_monitor", {}) if isinstance(argus_raw.get("usb_monitor", {}), dict) else {}
    dns_raw = argus_raw.get("dns_monitor", {}) if isinstance(argus_raw.get("dns_monitor", {}), dict) else {}
    registry_raw = argus_raw.get("registry_monitor", {}) if isinstance(argus_raw.get("registry_monitor", {}), dict) else {}
    service_raw = argus_raw.get("service_monitor", {}) if isinstance(argus_raw.get("service_monitor", {}), dict) else {}
    audit_raw = argus_raw.get("audit_policy", {}) if isinstance(argus_raw.get("audit_policy", {}), dict) else {}
    fw_raw = argus_raw.get("firewall_monitor", {}) if isinstance(argus_raw.get("firewall_monitor", {}), dict) else {}
    egress_raw = argus_raw.get("network_egress", {}) if isinstance(argus_raw.get("network_egress", {}), dict) else {}
    posture_raw = argus_raw.get("posture_monitor", {}) if isinstance(argus_raw.get("posture_monitor", {}), dict) else {}
    browser_raw = argus_raw.get("browser_extensions", {}) if isinstance(argus_raw.get("browser_extensions", {}), dict) else {}
    wmi_raw = argus_raw.get("wmi_subs", {}) if isinstance(argus_raw.get("wmi_subs", {}), dict) else {}
    ads_raw = argus_raw.get("ads_monitor", {}) if isinstance(argus_raw.get("ads_monitor", {}), dict) else {}
    evidence_raw = argus_raw.get("evidence", {}) if isinstance(argus_raw.get("evidence", {}), dict) else {}
    timelock_raw = argus_raw.get("timelock", {}) if isinstance(argus_raw.get("timelock", {}), dict) else {}
    response_raw = (
        argus_raw.get("threat_response", {}) if isinstance(argus_raw.get("threat_response", {}), dict) else {}
    )
    metering_raw = argus_raw.get("metering", {}) if isinstance(argus_raw.get("metering", {}), dict) else {}
    webhook_raw = argus_raw.get("webhook", {}) if isinstance(argus_raw.get("webhook", {}), dict) else {}
    syslog_raw = argus_raw.get("syslog", {}) if isinstance(argus_raw.get("syslog", {}), dict) else {}
    listener_raw = argus_raw.get("listener", {}) if isinstance(argus_raw.get("listener", {}), dict) else {}

    return ArgusConfig(
        hostname=str(_get(argus_raw, "hostname", "")),
        guard=GuardConfig(
            inactivity_timeout_seconds=max(60, int(_get(guard_raw, "inactivity_timeout_seconds", 600))),
            heartbeat_seconds=max(30, int(_get(guard_raw, "heartbeat_seconds", 300))),
        ),
        sms=SmsConfig(
            enabled=bool(_get(sms_raw, "enabled", False)),
            twilio_account_sid=str(_get(sms_raw, "twilio_account_sid", "")),
            twilio_auth_token=str(_get(sms_raw, "twilio_auth_token", "")),
            from_number=str(_get(sms_raw, "from_number", "")),
            to_number=str(_get(sms_raw, "to_number", "")),
        ),
        windows_events=WindowsEventsConfig(
            enabled=bool(_get(win_raw, "enabled", True)),
            poll_seconds=max(5, int(_get(win_raw, "poll_seconds", 15))),
            watch_event_ids=[int(x) for x in _get(win_raw, "watch_event_ids", [4625, 4720, 4728, 4732, 4740, 1102])],
        ),
        jsonl=JsonlConfig(
            enabled=bool(_get(jsonl_raw, "enabled", True)),
            directory=str(_get(jsonl_raw, "directory", ".argus/events")),
        ),
        process_monitor=ProcessMonitorConfig(
            enabled=bool(_get(proc_raw, "enabled", False)),
            poll_seconds=max(3, int(_get(proc_raw, "poll_seconds", 10))),
            allowlist=[str(x) for x in _get(proc_raw, "allowlist", ProcessMonitorConfig().allowlist)],
            denylist=[str(x) for x in _get(proc_raw, "denylist", ProcessMonitorConfig().denylist)],
            alert_on_unknown=bool(_get(proc_raw, "alert_on_unknown", True)),
        ),
        file_sentinel=FileSentinelConfig(
            enabled=bool(_get(files_raw, "enabled", False)),
            poll_seconds=max(3, int(_get(files_raw, "poll_seconds", 5))),
            paths=[str(x) for x in _get(files_raw, "paths", FileSentinelConfig().paths)],
        ),
        persistence_monitor=PersistenceMonitorConfig(
            enabled=bool(_get(persist_raw, "enabled", False)),
            poll_seconds=max(10, int(_get(persist_raw, "poll_seconds", 30))),
            watch_paths=[str(x) for x in _get(persist_raw, "watch_paths", [])],
        ),
        anti_tamper=AntiTamperConfig(
            enabled=bool(_get(tamper_raw, "enabled", False)),
            poll_seconds=max(5, int(_get(tamper_raw, "poll_seconds", 15))),
            watch_files=[str(x) for x in _get(tamper_raw, "watch_files", AntiTamperConfig().watch_files)],
            required_tasks=[str(x) for x in _get(tamper_raw, "required_tasks", AntiTamperConfig().required_tasks)],
        ),
        session_monitor=SessionMonitorConfig(
            enabled=bool(_get(session_raw, "enabled", False)),
            poll_seconds=max(5, int(_get(session_raw, "poll_seconds", 10))),
            logon_types=[int(x) for x in _get(session_raw, "logon_types", [3, 10])],
        ),
        usb_monitor=UsbMonitorConfig(
            enabled=bool(_get(usb_raw, "enabled", True)),
            poll_seconds=max(5, int(_get(usb_raw, "poll_seconds", 10))),
        ),
        dns_monitor=DnsMonitorConfig(
            enabled=bool(_get(dns_raw, "enabled", True)),
            poll_seconds=max(10, int(_get(dns_raw, "poll_seconds", 30))),
            suspicious_tlds=[str(x) for x in _get(dns_raw, "suspicious_tlds", DnsMonitorConfig().suspicious_tlds)],
            entropy_threshold=float(_get(dns_raw, "entropy_threshold", 3.5)),
        ),
        registry_monitor=RegistryMonitorConfig(
            enabled=bool(_get(registry_raw, "enabled", True)),
            poll_seconds=max(10, int(_get(registry_raw, "poll_seconds", 30))),
            watch_keys=[str(x) for x in _get(registry_raw, "watch_keys", RegistryMonitorConfig().watch_keys)],
        ),
        service_monitor=ServiceMonitorConfig(
            enabled=bool(_get(service_raw, "enabled", True)),
            poll_seconds=max(30, int(_get(service_raw, "poll_seconds", 60))),
            suspicious_paths=[str(x) for x in _get(service_raw, "suspicious_paths", ServiceMonitorConfig().suspicious_paths)],
        ),
        audit_policy=AuditPolicyConfig(
            enabled=bool(_get(audit_raw, "enabled", True)),
            poll_seconds=max(60, int(_get(audit_raw, "poll_seconds", 300))),
        ),
        firewall_monitor=FirewallMonitorConfig(
            enabled=bool(_get(fw_raw, "enabled", True)),
            poll_seconds=max(60, int(_get(fw_raw, "poll_seconds", 300))),
            suspicious_ports=[int(x) for x in _get(fw_raw, "suspicious_ports", FirewallMonitorConfig().suspicious_ports)],
        ),
        network_egress=NetworkEgressConfig(
            enabled=bool(_get(egress_raw, "enabled", False)),
            poll_seconds=max(30, int(_get(egress_raw, "poll_seconds", 60))),
            suspicious_ports=[int(x) for x in _get(egress_raw, "suspicious_ports", NetworkEgressConfig().suspicious_ports)],
            suspicious_processes=[
                str(x).lower() for x in _get(egress_raw, "suspicious_processes", NetworkEgressConfig().suspicious_processes)
            ],
            process_allowlist=[
                str(x).lower() for x in _get(egress_raw, "process_allowlist", NetworkEgressConfig().process_allowlist)
            ],
        ),
        posture_monitor=PostureMonitorConfig(
            enabled=bool(_get(posture_raw, "enabled", True)),
            poll_seconds=max(300, int(_get(posture_raw, "poll_seconds", 3600))),
        ),
        browser_extensions=BrowserExtensionConfig(
            enabled=bool(_get(browser_raw, "enabled", True)),
            poll_seconds=max(60, int(_get(browser_raw, "poll_seconds", 300))),
        ),
        wmi_subs=WmiSubsConfig(
            enabled=bool(_get(wmi_raw, "enabled", True)),
            poll_seconds=max(30, int(_get(wmi_raw, "poll_seconds", 120))),
        ),
        ads_monitor=AdsMonitorConfig(
            enabled=bool(_get(ads_raw, "enabled", True)),
            poll_seconds=max(60, int(_get(ads_raw, "poll_seconds", 300))),
            scan_dirs=[str(x) for x in _get(ads_raw, "scan_dirs", AdsMonitorConfig().scan_dirs)],
        ),
        evidence=EvidenceConfig(
            enabled=bool(_get(evidence_raw, "enabled", True)),
            output_dir=str(_get(evidence_raw, "output_dir", ".argus/evidence")),
            recent_file_window_minutes=max(1, int(_get(evidence_raw, "recent_file_window_minutes", 5))),
        ),
        timelock=TimeLockConfig(
            enabled=bool(_get(timelock_raw, "enabled", True)),
            lockdown_mode=str(_get(timelock_raw, "lockdown_mode", "reactive")).strip().lower(),
            duration_minutes=max(1, int(_get(timelock_raw, "duration_minutes", 15))),
            network_isolation=bool(_get(timelock_raw, "network_isolation", True)),
            extend_on_failed_disarm_minutes=max(0, int(_get(timelock_raw, "extend_on_failed_disarm_minutes", 5))),
        ),
        threat_response=ThreatResponseConfig(
            lockdown_enabled=bool(_get(response_raw, "lockdown_enabled", True)),
            lockdown_min_severity=str(_get(response_raw, "lockdown_min_severity", "high")).strip().lower(),
            lockdown_min_confidence=float(_get(response_raw, "lockdown_min_confidence", 0.9)),
        ),
        metering=_metering_config(metering_raw),
        webhook=WebhookSinkConfig(
            enabled=bool(_get(webhook_raw, "enabled", False)),
            url=str(_get(webhook_raw, "url", "")).strip(),
            secret=str(_get(webhook_raw, "secret", "")),
            timeout_seconds=max(1, int(_get(webhook_raw, "timeout_seconds", 5))),
            verify_tls=bool(_get(webhook_raw, "verify_tls", True)),
            ca_cert=str(_get(webhook_raw, "ca_cert", "")).strip(),
            allow_self_update=bool(_get(webhook_raw, "allow_self_update", False)),
        ),
        syslog=SyslogSinkConfig(
            enabled=bool(_get(syslog_raw, "enabled", False)),
            host=str(_get(syslog_raw, "host", "127.0.0.1")).strip() or "127.0.0.1",
            port=max(1, min(65535, int(_get(syslog_raw, "port", 5514)))),
            protocol=str(_get(syslog_raw, "protocol", "udp")).strip().lower(),
        ),
        listener=ListenerConfig(
            enabled=bool(_get(listener_raw, "enabled", False)),
            host=str(_get(listener_raw, "host", "0.0.0.0")).strip(),
            port=max(1024, min(65535, int(_get(listener_raw, "port", 8913)))),
            secret=str(_get(listener_raw, "secret", "")),
        ),
    )
