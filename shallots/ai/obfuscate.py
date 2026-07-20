"""Reversible pseudonymization for cloud-LLM triage (ai.tier: remote_api).

Fail-safe by design: masks anything that STRUCTURALLY looks like a network
identifier (IP/MAC/email/home-path), plus known assets (case-insensitively /
by substring), then RE-CHECKS the output and generically redacts anything that
still looks like an identifier. Preserves triage SEMANTICS (INT/EXT direction,
privilege role, universal system paths). Map stays on-box; replies de-tokenized
locally.

HONEST LIMIT: reduces IDENTIFIER leakage, NOT anonymization. Behavior/timing/
preserved-semantics still leak; tier=local is the only no-leak path. Aggressive
masking can also over-mask (e.g. a version string that parses as an IP) - that's
the deliberate fail-safe trade.
"""
from __future__ import annotations
import ipaddress, re
from collections import defaultdict

_PRIV_USERS = {"root", "admin", "administrator", "sudo"}
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}\b")
_RE_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RE_HOMEPATH = re.compile(r"/home/([A-Za-z0-9._-]+)")
_MIN_FUZZY_LEN = 4  # don't fuzzy-match asset names shorter than this (avoid clobbering common words)


class Obfuscator:
    def __init__(self, strict: bool = True) -> None:
        self._fwd: dict[str, str] = {}
        self._rev: dict[str, str] = {}
        self._n: dict[str, int] = defaultdict(int)
        self._assets: list[str] = []   # seeded hostnames (lowercased) for fuzzy match
        self.strict = strict

    def _tok(self, kind: str, real: str, tag: str = "") -> str:
        real = str(real)
        if real in self._fwd:
            return self._fwd[real]
        self._n[kind] += 1
        token = f"{kind}_{self._n[kind]}" + (f"({tag})" if tag else "")
        self._fwd[real] = token
        self._rev[token] = real
        return token

    def ip(self, addr: str, tag: str = "") -> str:
        try:
            obj = ipaddress.ip_address(str(addr).strip())
        except ValueError:
            return addr
        kind = "INT_IP" if (obj.is_private or obj.is_loopback or obj.is_link_local) else "EXT_IP"
        return self._tok(kind, str(addr).strip(), tag)

    def host(self, name: str) -> str:
        return self._tok("HOST", name) if name else name

    def user(self, name: str) -> str:
        if not name:
            return name
        tag = "privileged" if str(name).lower() in _PRIV_USERS else ""
        return self._tok("USER", name, tag)

    def mac(self, m: str) -> str:
        return self._tok("MAC", m) if m else m

    def seed_assets(self, hostnames=(), ips=(), users=()) -> None:
        for h in hostnames:
            if h and str(h).strip():
                self.host(str(h).strip())
                self._assets.append(str(h).strip().lower())
        for ip in ips:
            if ip and str(ip).strip():
                self.ip(ip)
        for u in users:
            if u and str(u).strip():
                self.user(u)

    # ── pattern masking (catches unknowns/prose, no seeding needed) ──
    def mask_patterns(self, text: str) -> str:
        if not text:
            return text
        text = _RE_MAC.sub(lambda m: self.mac(m.group(0)), text)
        text = _RE_EMAIL.sub(lambda m: self._tok("EMAIL", m.group(0)), text)
        text = _RE_IPV6.sub(lambda m: self.ip(m.group(0)), text)
        text = _RE_IPV4.sub(lambda m: self.ip(m.group(0)), text)
        text = _RE_HOMEPATH.sub(lambda m: "/home/" + self.user(m.group(1)), text)
        return text

    def scrub_text(self, text: str) -> str:
        """Mask mapped values + seeded assets, case-insensitively, longest-first."""
        text = self.mask_patterns(text)
        for real in sorted(self._fwd, key=len, reverse=True):
            token = self._fwd[real]
            if len(real) >= 7 or "." in real or ":" in real or re.search(r"[^0-9A-Za-z_]", real):
                text = re.sub(re.escape(real), token, text, flags=re.IGNORECASE)
            elif len(real) >= _MIN_FUZZY_LEN:
                text = re.sub(rf"(?<![0-9A-Za-z_]){re.escape(real)}(?![0-9A-Za-z_])",
                              token, text, flags=re.IGNORECASE)
        return text

    _TEXT_FIELDS = ("title", "description", "raw", "message")
    _IP_FIELDS = ("src_ip", "dst_ip")
    _HOST_FIELDS = ("src_asset", "dst_asset", "hostname", "agent_name")
    _USER_FIELDS = ("username", "src_user", "dst_user")
    _MAC_FIELDS = ("src_mac", "dst_mac", "mac")

    def obfuscate_alert(self, alert: dict) -> dict:
        a = dict(alert)
        for f in self._IP_FIELDS:
            if a.get(f): a[f] = self.ip(a[f])
        for f in self._HOST_FIELDS:
            if a.get(f): a[f] = self.host(a[f])
        for f in self._USER_FIELDS:
            if a.get(f): a[f] = self.user(a[f])
        for f in self._MAC_FIELDS:
            if a.get(f): a[f] = self.mac(a[f])
        for f in self._TEXT_FIELDS:
            if a.get(f): a[f] = self.scrub_text(str(a[f]))
        if self.strict:
            for f in self._TEXT_FIELDS + self._IP_FIELDS + self._HOST_FIELDS:
                if a.get(f):
                    a[f] = self._redact_residue(str(a[f]))
        return a

    def verify(self, obj) -> list[str]:
        """Re-check: return anything identifier-shaped that survived."""
        blob = str(obj)
        hits = []
        for rx in (_RE_IPV4, _RE_IPV6, _RE_MAC, _RE_EMAIL):
            hits += rx.findall(blob)
        low = blob.lower()
        for asset in self._assets:
            if len(asset) >= _MIN_FUZZY_LEN and asset in low:
                hits.append(asset)
        return hits

    def _redact_residue(self, text: str) -> str:
        """Fail-closed: generically redact anything still identifier-shaped."""
        for rx in (_RE_MAC, _RE_EMAIL, _RE_IPV6, _RE_IPV4):
            text = rx.sub("[REDACTED]", text)
        for asset in sorted(self._assets, key=len, reverse=True):
            if len(asset) >= _MIN_FUZZY_LEN:
                text = re.sub(re.escape(asset), "[REDACTED]", text, flags=re.IGNORECASE)
        return text

    def deobfuscate(self, text: str) -> str:
        if not text:
            return text
        for token in sorted(self._rev, key=len, reverse=True):
            text = text.replace(token, self._rev[token])
        return text

    def leak_check(self, obf: dict) -> list[str]:
        blob = str(obf)
        return [r for r in self._fwd if r in blob and len(r) >= 4]
