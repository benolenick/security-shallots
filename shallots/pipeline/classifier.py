"""Rule-based pre-classification of alerts before AI triage."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shallots.config import Config

from shallots.store.models import Alert, Severity, TriageVerdict

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default suppress lists — well-known noisy / low-value signatures
# ---------------------------------------------------------------------------

# Signature titles (substring match, case-insensitive) to auto-suppress
_DEFAULT_SUPPRESS_TITLE_PATTERNS: list[str] = [
    # Security Shallots experiments and lifecycle chatter
    "Synthetic Shallots experiment",
    "State changed: DISARMED -> ARMED_HOME",
    "State changed: ARMED_HOME -> DISARMED",
    "Argus heartbeat",
    # Suricata stream engine noise — TCP reassembly artifacts, not threats
    "SURICATA STREAM Packet with invalid timestamp",
    "SURICATA STREAM ESTABLISHED packet out of window",
    "SURICATA STREAM ESTABLISHED invalid ack",
    "SURICATA STREAM FIN out of window",
    "SURICATA STREAM FIN invalid ack",
    "SURICATA STREAM TIMEWAIT",
    "SURICATA STREAM excessive retransmissions",
    "SURICATA STREAM Packet with broken ack",
    "SURICATA STREAM Packet with invalid ack",
    "SURICATA STREAM SHUTDOWN RST invalid ack",
    "SURICATA Applayer Wrong direction first Data",
    "Protocol anomaly: applayer",
    # ICMP informational
    "ET INFO ICMP Destination Unreachable",
    "GPL ICMP_INFO Echo Reply",
    "GPL ICMP_INFO Echo Request",
    # Common benign traffic
    "GPL MISC UPnP",
    "ET POLICY IP Check Domain",
    "ET INFO TechSmith",
    "ET INFO Observed DNS Query to .onion proxy Domain",
    "ET INFO Windows OS Submitting USB",
    "ET POLICY curl User-Agent",
    "ET POLICY Python-urllib",
    "ET INFO GNU/Linux APT User-Agent",
    "ET INFO Observed Cloudflare DNS over HTTPS Domain",
    "ET INFO DNS Query to Cloudflare Tunneling Domain",
    "Remote Monitoring and Management",
    # LLMNR/mDNS — noisy on Windows networks, benign unless hunting Responder
    "LLMNR query",
    # PAM session noise — just login/logout logging
    "PAM: Login session opened",
    "PAM: Login session closed",
    "sshd: authentication success.",
    # Low-value web enumeration noise. NOTE: we deliberately do NOT title-suppress
    # anything naming an exploit (RCE), brute force, or a named attack tool — those
    # stay visible and get severity/direction-classified, even if they are common
    # internet background. Suppressing "PHP Remote Code Execution" outright would
    # hide a real hit. Volume from these is managed by dedup + direction-aware
    # severity, not by blanket suppression.
    "ET SCAN Wordpress",
    "ET WEB_SERVER robots.txt",
    "ET POLICY HTTP Request to a *.tk domain",
    "ET POLICY HTTP Request to a *.xyz domain",
    # DNS noise
    "ET DNS Query for .bit TLD",
    "ET DNS Standard query response, Name Error",
    # TLS/SSL informational
    "SURICATA TLS invalid record",
    "SURICATA TLS invalid handshake",
    "ET POLICY SSLv3 Outbound Connection",
    # Misc protocol noise
    "ET NETBIOS DCERPC ISystemActivator",
    "ET POLICY SMB2 NT Create",
    "ET POLICY Dropbox",
    "SURICATA HTTP unable to match response to request",
]

_DEFAULT_SUPPRESS_ASSET_PREFIXES: tuple[str, ...] = (
    "shallot-load-",
    "shallot-experiment",
    "shallot-auth-boundary",
)

# Persistence-surface changes that match one of these substrings are treated as
# routine maintenance (a service/unit/script you run on purpose) rather than an
# attacker establishing persistence. Ships with only the sensors Shallots itself
# may install; add your own app services/paths via
# config.yaml -> suppression.maintenance_persistence_patterns.
_KNOWN_MAINTENANCE_PERSISTENCE_PATTERNS: list[str] = [
    "crowdsec.service",
    "grafana-server.service",
    "victorialogs.service",
]


def register_maintenance_persistence_patterns(patterns: list[str]) -> None:
    """Extend the known-maintenance persistence allowlist from operator config.

    Called once at daemon start with config.suppression.maintenance_persistence_patterns
    so operators can mark their own services/scripts as expected without editing code.
    """
    for p in patterns:
        p = str(p).strip()
        if p and p not in _KNOWN_MAINTENANCE_PERSISTENCE_PATTERNS:
            _KNOWN_MAINTENANCE_PERSISTENCE_PATTERNS.append(p)

# Signature IDs to auto-suppress (integers)
_DEFAULT_SUPPRESS_SIG_IDS: set[int] = {
    2200075,  # GPL ICMP PING *NIX
    2200074,  # GPL ICMP PING BSDtype
    2210050,  # SURICATA HTTP unable to match response
    2260000,  # GPL DELETED
}

# Category prefixes that map to severity overrides
_CATEGORY_SEVERITY_MAP: dict[str, str] = {
    "ET SCAN": "low",
    "ET INFO": "low",
    "Not Suspicious": "low",
    "Potential Corporate Privacy Violation": "low",
    "Misc activity": "low",
    "firewall/block": "low",
    "syslog/kern": "low",
    "ET MALWARE": "high",
    "ET TROJAN": "high",
    "ET EXPLOIT": "critical",
    "ET WEB_SERVER": "medium",
    "ET WEB_CLIENT": "medium",
    "Authentication Failure": "medium",
    "crowdsec/ban": "high",
    "crowdsec/captcha": "medium",
}


@dataclass
class ClassifierConfig:
    """Tunable classifier settings (can override defaults from config)."""
    suppress_title_patterns: list[str] = field(
        default_factory=lambda: list(_DEFAULT_SUPPRESS_TITLE_PATTERNS)
    )
    suppress_sig_ids: set[int] = field(
        default_factory=lambda: set(_DEFAULT_SUPPRESS_SIG_IDS)
    )
    # Category → forced severity overrides
    category_severity_map: dict[str, str] = field(
        default_factory=lambda: dict(_CATEGORY_SEVERITY_MAP)
    )
    # Internal→internal traffic severity dampening (one step down)
    dampen_internal_internal: bool = True
    # External→internal traffic severity bump (one step up)
    amplify_external_internal: bool = True
    # IP/CIDR-based suppression (loaded from config.yaml suppression section)
    suppress_source_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list
    )
    suppress_dest_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list
    )
    suppress_source_ips: set[str] = field(default_factory=set)
    suppress_dest_ips: set[str] = field(
        default_factory=lambda: {
            "224.0.0.252",   # LLMNR multicast — normal Windows name resolution
        }
    )
    suppress_asset_prefixes: tuple[str, ...] = _DEFAULT_SUPPRESS_ASSET_PREFIXES
    # Category substrings the operator has explicitly silenced (via a "category"
    # silence rule). Suppresses matching alerts by verdict — NOT by overwriting
    # severity (the old category_severity_map["suppress"] bug).
    suppress_categories: list[str] = field(default_factory=list)


def _severity_up(sev: str) -> str:
    order = ["low", "medium", "high", "critical"]
    try:
        idx = order.index(sev)
        return order[min(idx + 1, len(order) - 1)]
    except ValueError:
        return sev


def _severity_down(sev: str) -> str:
    order = ["low", "medium", "high", "critical"]
    try:
        idx = order.index(sev)
        return order[max(idx - 1, 0)]
    except ValueError:
        return sev


def _is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _matches_home_cidr(ip: str, home_cidr: str) -> bool:
    """Return True if ip is within the configured home network CIDR."""
    if not ip or not home_cidr:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(home_cidr, strict=False)
    except ValueError:
        return False


def _is_quiet_argus_persistence(alert: Alert) -> bool:
    if alert.source != "argus" or alert.category != "persistence":
        return False
    if alert.source_ref and alert.source_ref not in {
        "persistence_detected",
        "service_change",
        "registry_persistence",
    }:
        return False
    if "persistence surface changed" not in (alert.title or "").lower():
        return False

    details = _raw_details(alert.raw)
    added = [str(x) for x in details.get("added_lines", []) if str(x).strip()]
    removed = [str(x) for x in details.get("removed_lines", []) if str(x).strip()]
    changed = added + removed

    if not changed:
        return True

    material = [
        line for line in changed
        if not _is_persistence_bookkeeping_line(line)
    ]
    if not material:
        return True

    return all(
        any(pattern in line for pattern in _KNOWN_MAINTENANCE_PERSISTENCE_PATTERNS)
        for line in material
    )


def _is_malformed_argus_session(alert: Alert) -> bool:
    if alert.source != "argus" or alert.category != "lateral_movement":
        return False
    if "session activity detected" not in (alert.title or "").lower():
        return False
    return bool(alert.src_ip) and not _valid_ip(alert.src_ip)


def _is_quiet_crowdsec_decision(alert: Alert) -> bool:
    if alert.source != "crowdsec":
        return False
    category = (alert.category or "").lower()
    if category not in {"crowdsec/ban", "crowdsec/captcha", "crowdsec/throttle", "crowdsec/challenge"}:
        return False
    # CrowdSec decisions are already-enforced local control-plane outcomes.
    # Keep them searchable as evidence; escalate only if another detector ties
    # the same IP to protected local traffic or host activity.
    return not bool(alert.dst_ip)


def _valid_ip(raw: str) -> bool:
    try:
        ipaddress.ip_address(raw)
        return True
    except ValueError:
        return False


# Shallots' own install artifacts. FIM (Wazuh syscheck) events on these are
# self-inflicted — Shallots writes its own units/config/db — and must not be
# escalated as "suspicious file added" incidents (it flagged its own
# shallot-inventory-scan.timer as an unknown binary on 2026-07-19).
# NB: an attacker with root could name a unit "shallot-evil.service" to ride this
# allowlist; that's an accepted residual (they already own the box, and any
# non-shallot path in /etc/systemd/system is still caught).
_SHALLOT_SELF_FILE_MARKERS = (
    "/home/user/security-shallots/",
    "/etc/systemd/system/shallot",
    "/etc/shallots/",
    "/var/lib/shallots/",
)


def _is_shallot_self_file(alert: Alert) -> bool:
    if alert.source != "wazuh":
        return False
    title = (alert.title or "").lower()
    if not any(
        k in title
        for k in (
            "file added",
            "integrity checksum changed",
            "file deleted",
            "file modified",
            "checksum changed",
        )
    ):
        return False
    blob = f"{alert.description or ''} {alert.raw or ''}"
    return any(marker in blob for marker in _SHALLOT_SELF_FILE_MARKERS)


def _is_high_signal_for_cidr_bypass(alert: Alert) -> bool:
    source = str(alert.source)
    if source == "suricata" and alert.severity in {"high", "critical"}:
        return True
    if source != "wazuh":
        return False
    if alert.severity in {"high", "critical"}:
        return True
    text = f"{alert.title} {alert.description} {alert.category}".lower()
    return any(
        term in text
        for term in (
            "brute force",
            "authentication_failures",
            "multiple authentication failures",
            "privilege escalation",
            "rootcheck",
            "syscheck",
        )
    )


def _raw_details(raw: str) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}
    details = parsed.get("details", {})
    return details if isinstance(details, dict) else {}


def _is_persistence_bookkeeping_line(line: str) -> bool:
    stripped = line.strip()
    return (
        stripped.startswith("# (")
        or bool(re.match(r"^\d+\s+unit files listed\.$", stripped))
    )


# ---------------------------------------------------------------------------
# Main classifier
# ---------------------------------------------------------------------------

class Classifier:
    """Applies rule-based pre-classification to alerts.

    Operates before AI triage to:
    - Suppress known-noisy alerts (sets verdict=suppress)
    - Override severity based on category
    - Adjust severity based on traffic direction (internal vs external)

    The AI triage step can override any verdict set here.
    """

    def __init__(self, cfg: ClassifierConfig | None = None):
        self._cfg = cfg or ClassifierConfig()
        self._suppress_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self._cfg.suppress_title_patterns
        ]
        # Combo silence rules (src_ip+title) — list of (ip, title_pattern) tuples
        self._combo_rules: list[tuple[str, str]] = []

    @classmethod
    def from_config(cls, cfg: Config) -> Classifier:
        """Build a Classifier from the main application Config."""
        ccfg = ClassifierConfig()

        sup = cfg.suppression
        # Parse CIDR strings into network objects
        for cidr_str in sup.source_cidrs:
            try:
                ccfg.suppress_source_cidrs.append(
                    ipaddress.ip_network(cidr_str, strict=False)
                )
            except ValueError:
                log.warning("Invalid suppress source CIDR: %s", cidr_str)
        for cidr_str in sup.dest_cidrs:
            try:
                ccfg.suppress_dest_cidrs.append(
                    ipaddress.ip_network(cidr_str, strict=False)
                )
            except ValueError:
                log.warning("Invalid suppress dest CIDR: %s", cidr_str)

        ccfg.suppress_source_ips = set(sup.source_ips)
        ccfg.suppress_dest_ips = set(sup.dest_ips)

        # Merge extra title patterns and sig IDs from config
        ccfg.suppress_title_patterns.extend(sup.title_patterns)
        ccfg.suppress_sig_ids.update(sup.sig_ids)

        # Operator-defined "this is my own service, not attacker persistence" list
        register_maintenance_persistence_patterns(
            getattr(sup, "maintenance_persistence_patterns", []) or []
        )

        return cls(ccfg)

    def classify(self, alert: Alert, home_cidr: str = "") -> Alert:
        """Apply pre-classification rules to an alert in-place.

        Sets alert.verdict to 'suppress' or leaves it at 'pending'.
        May adjust alert.severity.

        Returns the mutated alert.
        """
        # 0. Flow-fan-out recon (port scan / host sweep) is a deliberate, already
        # noise-filtered, deterministic detection. Escalate it directly and return
        # before the generic internal/self/CIDR suppression rules below (which would
        # otherwise bury LAN-to-LAN recon as noise). Authoritative by construction —
        # the fan-out threshold already did the filtering.
        if str(alert.source_ref) in ("flow-portscan", "flow-sweep"):
            alert.verdict = TriageVerdict.ESCALATE
            alert.confidence = 0.9
            alert.ai_reasoning = "flow fan-out reconnaissance (deterministic high-signal detector)"
            return alert

        # 1. Suppress synthetic/load assets before severity or AI work.
        asset_names = (alert.src_asset or "", alert.dst_asset or "", alert.source_ref or "")
        if any(
            name.startswith(prefix)
            for name in asset_names
            for prefix in self._cfg.suppress_asset_prefixes
        ):
            alert.verdict = TriageVerdict.SUPPRESS
            alert.ai_reasoning = "native suppression: synthetic/load/test agent"
            return alert

        # Argus persistence changes are useful audit records, but generic
        # baseline churn with no concrete diff is not operator-worthy. Known
        # fleet-maintenance diffs stay stored and searchable without climbing
        # the escalation ladder.
        if _is_quiet_argus_persistence(alert):
            alert.verdict = TriageVerdict.SUPPRESS
            alert.ai_reasoning = "native suppression: routine/undetailed persistence maintenance"
            return alert

        if _is_malformed_argus_session(alert):
            alert.verdict = TriageVerdict.SUPPRESS
            alert.ai_reasoning = "native suppression: malformed Argus session fields"
            return alert

        if _is_quiet_crowdsec_decision(alert):
            alert.verdict = TriageVerdict.SUPPRESS
            alert.ai_reasoning = "native suppression: CrowdSec decision already enforced; retained as evidence"
            return alert

        if _is_shallot_self_file(alert):
            alert.verdict = TriageVerdict.SUPPRESS
            alert.ai_reasoning = "native suppression: FIM event on Shallots' own install artifact (self-file)"
            return alert

        # 2. Suppress by signature ID
        if alert.signature_id and alert.signature_id in self._cfg.suppress_sig_ids:
            log.debug(
                "Suppressing alert %s: sig_id %d in suppress list",
                alert.id, alert.signature_id,
            )
            alert.verdict = TriageVerdict.SUPPRESS
            return alert

        # 3. Suppress by title pattern
        for pattern in self._suppress_patterns:
            if pattern.search(alert.title):
                log.debug(
                    "Suppressing alert %s: title matches pattern '%s'",
                    alert.id, pattern.pattern,
                )
                alert.verdict = TriageVerdict.SUPPRESS
                alert.ai_reasoning = f"native suppression: title matched {pattern.pattern!r}"
                return alert

        # 3b. Suppress by operator-silenced category substring
        if self._cfg.suppress_categories and alert.category:
            for cat in self._cfg.suppress_categories:
                if cat and cat in alert.category:
                    alert.verdict = TriageVerdict.SUPPRESS
                    alert.ai_reasoning = f"native suppression: category matched {cat!r}"
                    return alert

        # 4. Suppress by source IP
        # High-signal bypass mirrors steps 6/7 (CIDR): a critical exploit/C2/scan
        # signature from an ALLOWLISTED internal IP is exactly what a compromised
        # internal host doing lateral movement looks like. Do NOT hard-drop it here
        # — let it reach AI triage (verdict stays pending) so a real internal threat
        # can't hide behind a source_ips allowlist entry. Recurring known-benign
        # tooling should be silenced deliberately via combo rules (step 8), not by
        # blanket-muting every high/critical sig from the host.
        if (
            alert.src_ip
            and alert.src_ip in self._cfg.suppress_source_ips
            and not _is_high_signal_for_cidr_bypass(alert)
        ):
            log.debug("Suppressing alert %s: src_ip %s in suppress list", alert.id, alert.src_ip)
            alert.verdict = TriageVerdict.SUPPRESS
            return alert

        # 5. Suppress by dest IP (same high-signal bypass as step 4)
        if (
            alert.dst_ip
            and alert.dst_ip in self._cfg.suppress_dest_ips
            and not _is_high_signal_for_cidr_bypass(alert)
        ):
            log.debug("Suppressing alert %s: dst_ip %s in suppress list", alert.id, alert.dst_ip)
            alert.verdict = TriageVerdict.SUPPRESS
            return alert

        # 6. Suppress by source CIDR
        if alert.src_ip and self._cfg.suppress_source_cidrs and not _is_high_signal_for_cidr_bypass(alert):
            try:
                src_addr = ipaddress.ip_address(alert.src_ip)
                for net in self._cfg.suppress_source_cidrs:
                    if src_addr in net:
                        log.debug("Suppressing alert %s: src_ip %s in CIDR %s", alert.id, alert.src_ip, net)
                        alert.verdict = TriageVerdict.SUPPRESS
                        return alert
            except ValueError:
                pass

        # 7. Suppress by dest CIDR
        if alert.dst_ip and self._cfg.suppress_dest_cidrs and not _is_high_signal_for_cidr_bypass(alert):
            try:
                dst_addr = ipaddress.ip_address(alert.dst_ip)
                for net in self._cfg.suppress_dest_cidrs:
                    if dst_addr in net:
                        log.debug("Suppressing alert %s: dst_ip %s in CIDR %s", alert.id, alert.dst_ip, net)
                        alert.verdict = TriageVerdict.SUPPRESS
                        return alert
            except ValueError:
                pass

        # 8. Combo rules (src_ip+title)
        if alert.src_ip and alert.title and self._combo_rules:
            title_lower = alert.title.lower()
            for combo_ip, combo_title in self._combo_rules:
                if alert.src_ip == combo_ip and combo_title.lower() in title_lower:
                    log.debug(
                        "Suppressing alert %s: combo rule src_ip=%s + title~'%s'",
                        alert.id, combo_ip, combo_title,
                    )
                    alert.verdict = TriageVerdict.SUPPRESS
                    return alert

        # 9. Category-based severity override (most specific prefix wins)
        new_sev = _category_severity(alert.category, self._cfg.category_severity_map)
        if new_sev and new_sev != alert.severity:
            log.debug(
                "Classifier: category '%s' overrides severity %s → %s",
                alert.category, alert.severity, new_sev,
            )
            alert.severity = new_sev

        # 4. Direction-based severity adjustment
        src_internal = _is_private_ip(alert.src_ip) or _matches_home_cidr(alert.src_ip, home_cidr)
        dst_internal = _is_private_ip(alert.dst_ip) or _matches_home_cidr(alert.dst_ip, home_cidr)

        if src_internal and dst_internal and self._cfg.dampen_internal_internal:
            # Internal → internal: reduce noise
            old_sev = alert.severity
            alert.severity = _severity_down(alert.severity)
            if alert.severity != old_sev:
                log.debug(
                    "Classifier: internal→internal traffic dampened severity %s → %s",
                    old_sev, alert.severity,
                )

        elif not src_internal and dst_internal and self._cfg.amplify_external_internal:
            # External → internal: more interesting
            old_sev = alert.severity
            alert.severity = _severity_up(alert.severity)
            if alert.severity != old_sev:
                log.debug(
                    "Classifier: external→internal traffic amplified severity %s → %s",
                    old_sev, alert.severity,
                )

        return alert


def _category_severity(category: str, mapping: dict[str, str]) -> str:
    """Find the most specific matching category prefix and return its severity."""
    if not category:
        return ""

    best_match = ""
    best_len = 0

    for prefix, sev in mapping.items():
        if category.startswith(prefix) and len(prefix) > best_len:
            best_match = sev
            best_len = len(prefix)

    return best_match


def classify(alert: Alert, cfg: Config) -> Alert:
    """Convenience function: classify a single alert using application config."""
    classifier = Classifier.from_config(cfg)
    home_cidr = cfg.network.home_cidr if cfg.network else ""
    return classifier.classify(alert, home_cidr)
