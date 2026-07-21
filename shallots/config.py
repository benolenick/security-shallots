"""Configuration loading and validation."""

from __future__ import annotations

import os
import platform
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


CONFIG_SEARCH_PATHS = [
    Path("./config.yaml"),
    Path("./config.yml"),
    Path(os.path.expanduser("~/.config/shallots/config.yaml")),
    Path("/etc/shallots/config.yaml"),
]

PROFILES = {
    "lite": {
        "suricata": True,
        "crowdsec": False,
        "wazuh": False,
        "victorialogs": False,
        "grafana": False,
        "syslog_receiver": True,
        "argus": False,
        "webapp": False,
    },
    "micro": {
        "suricata": True,
        "crowdsec": True,
        "wazuh": False,
        "victorialogs": False,
        "grafana": False,
        "syslog_receiver": False,
        "argus": False,
        "webapp": False,
    },
    "standard": {
        "suricata": True,
        "crowdsec": True,
        "wazuh": True,
        "victorialogs": True,
        "grafana": True,
        "syslog_receiver": False,
        "argus": False,
        "webapp": False,
    },
    "full": {
        "suricata": True,
        "crowdsec": True,
        "wazuh": True,
        "victorialogs": True,
        "grafana": True,
        "syslog_receiver": True,
        "argus": True,
        "webapp": True,
    },
}


@dataclass
class NetworkConfig:
    home_cidr: str = "192.168.0.0/16"
    monitor_interface: str = "eth0"


@dataclass
class SuricataConfig:
    eve_path: str = "/var/log/suricata/eve.json"


@dataclass
class WazuhConfig:
    alerts_path: str = "/var/ossec/logs/alerts/alerts.json"
    manager_api_url: str = "https://127.0.0.1:55000"
    manager_api_user: str = ""
    manager_api_password: str = ""


@dataclass
class CrowdSecConfig:
    api_url: str = "http://127.0.0.1:8080"
    api_key: str = ""


@dataclass
class PfSenseConfig:
    enabled: bool = False
    api_url: str = ""
    api_key: str = ""
    api_secret: str = ""
    # Verify the firewall's TLS cert. The API key rides in the Authorization
    # header, so an unverified channel leaks it to a MITM. Set false only for a
    # self-signed pfSense you access over a trusted link.
    verify_ssl: bool = True


@dataclass
class PiHoleConfig:
    enabled: bool = False
    api_url: str = ""
    api_key: str = ""
    # DNS-log detector (PiholeDnsIngestor): reads pihole-FTL.db directly,
    # co-located on the same host as shallotd.
    dns_enabled: bool = False
    db_path: str = "/etc/pihole/pihole-FTL.db"
    poll_interval_sec: int = 15


@dataclass
class SyslogConfig:
    enabled: bool = False
    udp_port: int = 5514
    tcp_port: int = 5514
    low_severity_duplicate_limit: int = 20
    low_severity_duplicate_window_sec: int = 60


@dataclass
class AutopilotConfig:
    mode: str = "off"  # off, copilot, autopilot
    noise_threshold: int = 5  # same src_ip+title N times in window → noise
    noise_window_min: int = 60  # window for noise detection (minutes)
    auto_silence_after: int = 10  # create silence rule after N noise hits
    shift_report_hours: int = 8  # shift report interval
    squawk_sms: bool = True  # send SMS on squawk (if Twilio configured)
    batch_interval_sec: int = 30  # how often autopilot processes


@dataclass
class AIConfig:
    tier: str = "none"  # none, remote_micro, remote_standard, remote_api, local
    ollama_url: str = ""
    ollama_model: str = ""
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    batch_size: int = 5
    batch_interval_sec: int = 30
    # When tier=remote_api, pseudonymize network identifiers (IPs, MACs, hostnames,
    # usernames, emails, home paths) before sending to the cloud model and restore
    # them in the reply. Reduces identifier leakage; behavior/timing still leak.
    # No effect on local/none tiers (nothing leaves the box).
    obfuscate_cloud: bool = False
    autopilot: AutopilotConfig = field(default_factory=AutopilotConfig)


@dataclass
class ScoutConfig:
    """Non-judgmental edge scout for missed-signal candidates."""
    enabled: bool = False
    ollama_url: str = ""
    model: str = "granite3.3:8b"
    batch_size: int = 10
    interval_sec: int = 60
    lookback_hours: int = 24
    min_score: int = 2
    corpus_path: str = "data/fleet_context.db"
    # Optional environment hints for scoring heuristics (all inert if unset):
    router_ip: str = ""            # your gateway/router's LAN IP
    router_syslog_hint: str = ""   # substring identifying router-origin syslog (e.g. vendor name)
    sensor_ips: list[str] = field(default_factory=list)  # IPs of hosts running a local Suricata sensor


@dataclass
class ExecMonConfig:
    """Command-execution monitoring via the Linux audit log (auditd EXECVE).

    Captures every command as it runs, scores it with the lexicon ranker, and
    only alerts on the suspicious tail (score >= emit_min_score) - the benign
    99% is counted and dropped. Needs an auditd execve rule keyed 'shallots_exec'
    (setup/audit/shallots-exec.rules). Off by default."""
    enabled: bool = False
    audit_log_path: str = "/var/log/audit/audit.log"
    lexicon_path: str = ""           # optional JSON override; empty uses built-ins
    escalate_threshold: int = 40
    investigate_threshold: int = 15
    emit_min_score: int = 15         # below this a command is scored and dropped
    poll_seconds: int = 5


@dataclass
class StorageConfig:
    db_path: str = "/var/lib/shallots/shallots.db"
    retention_days: int = 30
    max_backups: int = 3          # rotate backups, keep N most recent
    backup_dir: str = ""          # defaults to ./backups/ relative to db_path
    elasticsearch_url: str = ""
    victorialogs_url: str = ""


@dataclass
class WebConfig:
    # Loopback by default - the dashboard is not exposed to the LAN until the
    # operator sets host to 0.0.0.0 AND configures credentials (see app.py guard).
    host: str = "127.0.0.1"
    port: int = 8844
    username: str = ""
    password: str = ""
    # Hostnames allowed in the Host header (anti-DNS-rebinding). IP access always
    # works; add reverse-proxy / LAN hostnames here if you serve via a name.
    allowed_hosts: list[str] = field(default_factory=list)
    tls_cert: str = ""  # Path to TLS certificate (enables HTTPS)
    tls_key: str = ""   # Path to TLS private key


@dataclass
class EmailAlertConfig:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    from_addr: str = ""
    to_addr: str = ""
    min_severity: str = "high"  # Only alert on this severity and above


@dataclass
class SyslogAlertConfig:
    enabled: bool = False
    host: str = ""
    port: int = 514


@dataclass
class SmsAlertConfig:
    enabled: bool = False
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    from_number: str = ""
    to_number: str = ""
    min_severity: str = "critical"  # Only SMS for critical by default


@dataclass
class NtfyConfig:
    enabled: bool = False
    topic: str = ""  # e.g. "my-shallots-alerts" - published to ntfy.sh/<topic>
    server: str = "https://ntfy.sh"  # override for self-hosted ntfy
    token: str = ""  # optional auth token for private topics


@dataclass
class AlertingConfig:
    webhook_url: str = ""
    ntfy: NtfyConfig = field(default_factory=NtfyConfig)
    email: EmailAlertConfig = field(default_factory=EmailAlertConfig)
    syslog: SyslogAlertConfig = field(default_factory=SyslogAlertConfig)
    sms: SmsAlertConfig = field(default_factory=SmsAlertConfig)


@dataclass
class GeoIPConfig:
    db_path: str = "/var/lib/shallots/GeoLite2-City.mmdb"


@dataclass
class VirusTotalConfig:
    api_key: str = ""
    enabled: bool = False
    ip_lookup_enabled: bool = False


@dataclass
class AbuseIPDBConfig:
    api_key: str = ""
    enabled: bool = False


@dataclass
class ShodanInternetDBConfig:
    enabled: bool = True  # Free, no API key needed


@dataclass
class GreyNoiseConfig:
    api_key: str = ""
    enabled: bool = False


@dataclass
class AgentMonitorConfig:
    enabled: bool = True
    check_interval_sec: int = 60
    degraded_after_sec: int = 300    # 5 min → yellow
    offline_after_sec: int = 480     # 8 min → red + alert
    heartbeat_secret: str = ""       # optional X-Heartbeat-Secret


@dataclass
class TlsMonitorConfig:
    enabled: bool = False
    targets: list[str] = field(default_factory=list)
    check_interval_hours: int = 24
    warn_days: int = 30


@dataclass
class WebAppIngestConfig:
    enabled: bool = False
    log_paths: list[str] = field(default_factory=list)  # e.g. ["/tmp/fv24.log"]
    app_name: str = "webapp"       # human label for alerts
    server_ip: str = ""            # IP of the server hosting the app
    server_port: int = 443         # public-facing port


@dataclass
class ArgusConfig:
    jsonl_dir: str = ""       # path to Argus JSONL events dir (e.g. ~/.argus/events)
    webhook_enabled: bool = False
    webhook_port: int = 8855
    webhook_path: str = "/api/ingest/argus"
    webhook_secret: str = ""  # shared secret for X-Argus-Secret header
    allowed_source_cidrs: list[str] = field(default_factory=list)
    webhook_tls_enabled: bool = False
    webhook_tls_cert: str = ""
    webhook_tls_key: str = ""
    require_per_agent_secret: bool = False
    agent_secrets: dict[str, str] = field(default_factory=dict)


@dataclass
class AssetNetwork:
    cidr: str = ""
    name: str = ""
    role: str = ""


@dataclass
class SigmaConfig:
    enabled: bool = False
    rules_dir: str = "/etc/shallots/sigma-rules"


@dataclass
class IocFeedConfig:
    enabled: bool = False
    feeds: list[dict] = field(default_factory=list)


@dataclass
class SuppressionConfig:
    """IP/CIDR-based alert suppression rules."""
    source_cidrs: list[str] = field(default_factory=list)  # e.g. ["192.168.3.0/24"]
    dest_cidrs: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)    # e.g. ["192.168.0.96"]
    dest_ips: list[str] = field(default_factory=list)
    title_patterns: list[str] = field(default_factory=list)  # extra patterns beyond defaults
    sig_ids: list[int] = field(default_factory=list)         # extra sig IDs beyond defaults
    # Substrings identifying your own services/scripts/paths whose persistence-surface
    # changes are routine maintenance, not an attacker (e.g. "myapp.service").
    maintenance_persistence_patterns: list[str] = field(default_factory=list)


@dataclass
class ThreatEngineConfig:
    """Auto-tuned threat engine settings based on hardware capabilities."""
    tier: str = "auto"  # auto, pi, mid, server - auto-detected from hardware
    baselines: bool = True        # always on (pure Python, minimal resources)
    graph: bool = True            # always on (in-memory, lightweight)
    ml_detector: bool = True      # requires sklearn - auto-disabled if unavailable
    killchain: bool = True        # always on (pure Python, no deps)
    # Tuning knobs (auto-set by tier)
    correlator_interval_sec: int = 300   # pi=600, mid=300, server=120
    baseline_rebuild_sec: int = 21600    # pi=43200, mid=21600, server=3600
    ml_retrain_sec: int = 21600          # pi=43200, mid=21600, server=3600
    ml_training_samples: int = 200       # pi=100, mid=200, server=1000
    graph_max_nodes: int = 300           # pi=100, mid=300, server=1000
    baseline_window_days: int = 7        # pi=3, mid=7, server=14


@dataclass
class ComponentToggles:
    suricata: bool = True
    crowdsec: bool = True
    wazuh: bool = True
    victorialogs: bool = True
    grafana: bool = True
    syslog_receiver: bool = False
    argus: bool = False
    webapp: bool = False


@dataclass
class Config:
    profile: str = "auto"
    network: NetworkConfig = field(default_factory=NetworkConfig)
    components: ComponentToggles = field(default_factory=ComponentToggles)
    suricata: SuricataConfig = field(default_factory=SuricataConfig)
    wazuh: WazuhConfig = field(default_factory=WazuhConfig)
    crowdsec: CrowdSecConfig = field(default_factory=CrowdSecConfig)
    pfsense: PfSenseConfig = field(default_factory=PfSenseConfig)
    pihole: PiHoleConfig = field(default_factory=PiHoleConfig)
    syslog: SyslogConfig = field(default_factory=SyslogConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    scout: ScoutConfig = field(default_factory=ScoutConfig)
    execmon: ExecMonConfig = field(default_factory=ExecMonConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    web: WebConfig = field(default_factory=WebConfig)
    alerting: AlertingConfig = field(default_factory=AlertingConfig)
    geoip: GeoIPConfig = field(default_factory=GeoIPConfig)
    virustotal: VirusTotalConfig = field(default_factory=VirusTotalConfig)
    abuseipdb: AbuseIPDBConfig = field(default_factory=AbuseIPDBConfig)
    shodan: ShodanInternetDBConfig = field(default_factory=ShodanInternetDBConfig)
    greynoise: GreyNoiseConfig = field(default_factory=GreyNoiseConfig)
    argus: ArgusConfig = field(default_factory=ArgusConfig)
    webapp: WebAppIngestConfig = field(default_factory=WebAppIngestConfig)
    agent_monitor: AgentMonitorConfig = field(default_factory=AgentMonitorConfig)
    tls_monitor: TlsMonitorConfig = field(default_factory=TlsMonitorConfig)
    suppression: SuppressionConfig = field(default_factory=SuppressionConfig)
    threat_engine: ThreatEngineConfig = field(default_factory=ThreatEngineConfig)
    sigma: SigmaConfig = field(default_factory=SigmaConfig)
    ioc_feeds: IocFeedConfig = field(default_factory=IocFeedConfig)
    assets: list[AssetNetwork] = field(default_factory=list)


def detect_profile() -> str:
    """Auto-detect deployment profile based on available RAM."""
    try:
        if platform.system() == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(re.search(r"\d+", line).group())
                        gb = kb / (1024 * 1024)
                        if gb < 2:
                            return "lite"
                        elif gb < 4:
                            return "micro"
                        elif gb < 8:
                            return "standard"
                        else:
                            return "full"
    except Exception:
        pass
    return "standard"


def _detect_hardware() -> dict:
    """Detect hardware capabilities for threat engine auto-tuning.

    Returns dict with: ram_gb, cpu_cores, has_gpu, gpu_name, has_sklearn, tier
    """
    import multiprocessing

    hw = {
        "ram_gb": 0.0,
        "cpu_cores": multiprocessing.cpu_count() or 1,
        "has_gpu": False,
        "gpu_name": "",
        "has_sklearn": False,
        "tier": "mid",  # default
    }

    # Detect RAM
    try:
        if platform.system() == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(re.search(r"\d+", line).group())
                        hw["ram_gb"] = round(kb / (1024 * 1024), 1)
                        break
        elif platform.system() == "Windows":
            import ctypes
            kernel32 = ctypes.windll.kernel32
            c_ulonglong = ctypes.c_ulonglong
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", c_ulonglong),
                    ("ullAvailPhys", c_ulonglong),
                    ("ullTotalPageFile", c_ulonglong),
                    ("ullAvailPageFile", c_ulonglong),
                    ("ullTotalVirtual", c_ulonglong),
                    ("ullAvailVirtual", c_ulonglong),
                    ("ullAvailExtendedVirtual", c_ulonglong),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(stat)
            kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            hw["ram_gb"] = round(stat.ullTotalPhys / (1024**3), 1)
        else:
            hw["ram_gb"] = 4.0  # conservative default
    except Exception:
        hw["ram_gb"] = 4.0

    # Detect GPU (NVIDIA)
    try:
        import subprocess
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            hw["has_gpu"] = True
            hw["gpu_name"] = result.stdout.strip().split("\n")[0]
    except Exception:
        pass

    # Detect sklearn
    try:
        import sklearn  # noqa: F401
        hw["has_sklearn"] = True
    except ImportError:
        pass

    # Determine tier
    ram = hw["ram_gb"]
    cores = hw["cpu_cores"]
    if ram < 4 or cores <= 2:
        hw["tier"] = "pi"
    elif ram >= 16 and cores >= 8:
        hw["tier"] = "server"
    else:
        hw["tier"] = "mid"

    return hw


def _apply_threat_engine_tier(te: ThreatEngineConfig, hw: dict) -> None:
    """Apply hardware-detected tier settings to threat engine config."""
    tier = hw["tier"]

    if te.tier != "auto":
        tier = te.tier  # user override

    te.tier = tier

    if tier == "pi":
        # On low-resource systems, disable the entire threat engine.
        # The correlator alone handles port scans, brute force, lateral movement.
        te.baselines = False
        te.graph = False
        te.ml_detector = False
        te.killchain = False
        te.correlator_interval_sec = 600
    elif tier == "server":
        te.correlator_interval_sec = 120
        te.baseline_rebuild_sec = 3600       # 1 hour
        te.ml_retrain_sec = 3600
        te.ml_training_samples = 1000
        te.graph_max_nodes = 1000
        te.baseline_window_days = 14
    else:  # mid
        te.correlator_interval_sec = 300
        te.baseline_rebuild_sec = 21600      # 6 hours
        te.ml_retrain_sec = 21600
        te.ml_training_samples = 200
        te.graph_max_nodes = 300
        te.baseline_window_days = 7
        if not hw["has_sklearn"]:
            te.ml_detector = False


def _merge_dict(target: dict, source: dict) -> dict:
    """Deep merge source into target."""
    for key, value in source.items():
        if key in target and isinstance(target[key], dict) and isinstance(value, dict):
            _merge_dict(target[key], value)
        else:
            target[key] = value
    return target


def _dict_to_dataclass(cls, data: dict[str, Any]):
    """Recursively convert a dict to a dataclass instance."""
    if not isinstance(data, dict):
        return data
    import dataclasses

    field_types = {f.name: f.type for f in dataclasses.fields(cls)}
    kwargs = {}
    for name, ftype in field_types.items():
        if name not in data:
            continue
        val = data[name]
        # Resolve string type annotations
        if isinstance(ftype, str):
            ftype = eval(ftype, {**globals(), "list": list})
        if dataclasses.is_dataclass(ftype) and isinstance(val, dict):
            kwargs[name] = _dict_to_dataclass(ftype, val)
        elif hasattr(ftype, "__origin__") and ftype.__origin__ is list:
            # Handle list[AssetNetwork] etc.
            inner = ftype.__args__[0] if ftype.__args__ else str
            if dataclasses.is_dataclass(inner):
                kwargs[name] = [_dict_to_dataclass(inner, item) for item in val]
            else:
                kwargs[name] = val
        else:
            kwargs[name] = val
    return cls(**kwargs)


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from YAML file.

    Search order: explicit path, ./config.yaml, ~/.config/shallots/config.yaml,
    /etc/shallots/config.yaml. Falls back to defaults if nothing found.
    """
    raw: dict[str, Any] = {}

    if path:
        p = Path(path)
        if p.exists():
            raw = yaml.safe_load(p.read_text()) or {}
        else:
            raise FileNotFoundError(f"Config file not found: {path}")
    else:
        for search_path in CONFIG_SEARCH_PATHS:
            if search_path.exists():
                raw = yaml.safe_load(search_path.read_text()) or {}
                break

    # Resolve profile
    profile = raw.get("profile", "auto")
    if profile == "auto":
        profile = detect_profile()

    # Apply profile defaults for components
    if profile in PROFILES and "components" not in raw:
        raw["components"] = PROFILES[profile]

    raw["profile"] = profile

    # Handle nested AI config
    if "ai" in raw and isinstance(raw["ai"], dict):
        ai_raw = raw["ai"]
        if "autopilot" in ai_raw and isinstance(ai_raw["autopilot"], dict):
            ai_raw["autopilot"] = _dict_to_dataclass(AutopilotConfig, ai_raw["autopilot"])

    # Handle nested alerting config
    if "alerting" in raw:
        alerting = raw["alerting"]
        if "email" in alerting and isinstance(alerting["email"], dict):
            alerting["email"] = _dict_to_dataclass(EmailAlertConfig, alerting["email"])
        if "syslog" in alerting and isinstance(alerting["syslog"], dict):
            alerting["syslog"] = _dict_to_dataclass(SyslogAlertConfig, alerting["syslog"])
        if "sms" in alerting and isinstance(alerting["sms"], dict):
            alerting["sms"] = _dict_to_dataclass(SmsAlertConfig, alerting["sms"])

    # Handle assets list
    if "assets" in raw and isinstance(raw["assets"], dict):
        raw["assets"] = raw["assets"].get("networks", [])

    cfg = _dict_to_dataclass(Config, raw)

    # Auto-detect and tune threat engine based on hardware
    hw = _detect_hardware()
    _apply_threat_engine_tier(cfg.threat_engine, hw)

    # Auto-enable Argus webhook when Argus component is on
    if cfg.components.argus and not cfg.argus.webhook_enabled:
        cfg.argus.webhook_enabled = True
    return cfg
