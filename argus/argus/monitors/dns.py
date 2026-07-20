from __future__ import annotations

import asyncio
import collections
import json
import math
import os
import subprocess
from dataclasses import dataclass, field

from .types import ThreatSignal


@dataclass(slots=True)
class DnsMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 30
    suspicious_tlds: list[str] = field(
        default_factory=lambda: [
            ".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".buzz", ".club"
        ]
    )
    entropy_threshold: float = 3.5


class DnsMonitor:
    def __init__(self, cfg: DnsMonitorConfig) -> None:
        self.cfg = cfg
        self._seen_domains: set[str] = set()
        self._primed = False

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            await asyncio.sleep(max(10, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        entries = self._get_dns_cache()
        out: list[ThreatSignal] = []

        if not self._primed:
            self._seen_domains = {e["domain"] for e in entries}
            self._primed = True
            return out

        for entry in entries:
            domain = entry["domain"]
            if domain in self._seen_domains:
                continue
            self._seen_domains.add(domain)

            # Check suspicious TLD
            domain_lower = domain.lower()
            for tld in self.cfg.suspicious_tlds:
                if domain_lower.endswith(tld):
                    out.append(
                        ThreatSignal(
                            event_type="suspicious_dns",
                            title="Suspicious TLD in DNS cache",
                            description=f"Domain with suspicious TLD resolved: {domain}",
                            severity="high",
                            confidence=0.8,
                            category="c2",
                            details={
                                "domain": domain,
                                "data": entry["data"],
                                "reason": "suspicious_tld",
                                "entropy": round(_shannon_entropy(_main_label(domain)), 4),
                            },
                            raw=entry,
                        )
                    )
                    break
            else:
                # Check Shannon entropy of main label for DGA detection
                label = _main_label(domain)
                entropy = _shannon_entropy(label)
                if entropy > self.cfg.entropy_threshold:
                    out.append(
                        ThreatSignal(
                            event_type="suspicious_dns",
                            title="High-entropy domain — possible DGA",
                            description=(
                                f"Domain '{domain}' has high label entropy "
                                f"({entropy:.2f}), possible DGA activity"
                            ),
                            severity="high",
                            confidence=0.75,
                            category="c2",
                            details={
                                "domain": domain,
                                "data": entry["data"],
                                "reason": "high_entropy",
                                "entropy": round(entropy, 4),
                            },
                            raw=entry,
                        )
                    )

        return out

    @staticmethod
    def _get_dns_cache() -> list[dict]:
        if os.name != "nt":
            return DnsMonitor._get_dns_cache_linux()

        ps = "Get-DnsClientCache | Select-Object Entry,Data | ConvertTo-Json -Compress"
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = (proc.stdout or "").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        items = parsed if isinstance(parsed, list) else [parsed]
        out = []
        for it in items:
            if not isinstance(it, dict):
                continue
            out.append(
                {
                    "domain": str(it.get("Entry", "") or ""),
                    "data": str(it.get("Data", "") or ""),
                }
            )
        return out

    @staticmethod
    def _get_dns_cache_linux() -> list[dict]:
        """Extract recent DNS queries from systemd-resolved journal on Linux."""
        try:
            proc = subprocess.run(
                ["journalctl", "-u", "systemd-resolved", "-n", "500",
                 "--no-pager", "-o", "cat"],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return []

        output = (proc.stdout or "").strip()
        if not output:
            return []

        # Extract lines like: "... ANSWER SECTION: example.com. 300 IN A 1.2.3.4"
        # or "... example.com IN A 1.2.3.4" from resolved log lines
        import re
        seen: dict[str, str] = {}
        # Pattern: domain name followed by record type and data
        pattern = re.compile(
            r"(?:ANSWER|QUERY|->)\s+([a-zA-Z0-9._-]+\.)\s+.*?(?:IN\s+\w+\s+(.+))?",
            re.IGNORECASE,
        )
        # Simpler fallback: grab any FQDN-like tokens from resolved output
        fqdn_pattern = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b")
        for line in output.splitlines():
            for match in fqdn_pattern.finditer(line):
                domain = match.group(1).rstrip(".")
                if domain and "." in domain and domain not in seen:
                    seen[domain] = line.strip()[:120]

        return [{"domain": d, "data": v} for d, v in seen.items()]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = collections.Counter(s)
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


def _main_label(domain: str) -> str:
    """Return the longest label (by character count) from the domain, excluding the TLD."""
    parts = domain.rstrip(".").split(".")
    if len(parts) <= 1:
        return domain
    # Strip the TLD (last part) and return the longest remaining label
    labels = parts[:-1]
    return max(labels, key=len)
