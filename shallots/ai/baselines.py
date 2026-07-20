"""Behavioral baselines for network devices.

Learns what "normal" looks like per IP/device over a rolling window,
then flags deviations in real time during correlation cycles.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.store.db import AlertDB

from shallots.store.models import now_iso

log = logging.getLogger(__name__)

_BASELINE_WINDOW_DAYS = 7
_REBUILD_INTERVAL_SEC = 6 * 3600  # 6 hours
_DEVIATION_SIGMA = 3.0  # flag if > 3 standard deviations


@dataclass
class DeviceProfile:
    """Behavioral profile for a single network entity."""

    ip: str = ""
    asset_name: str | None = None
    first_seen: str = ""
    last_seen: str = ""
    # Rolling stats
    hourly_alert_counts: dict[str, float] = field(default_factory=dict)  # "0"-"23" → avg
    hourly_alert_stddev: dict[str, float] = field(default_factory=dict)
    common_dst_ports: dict[str, int] = field(default_factory=dict)       # port → freq
    common_dst_ips: list[str] = field(default_factory=list)
    common_categories: dict[str, int] = field(default_factory=dict)
    dns_domains: list[str] = field(default_factory=list)
    protocols: dict[str, int] = field(default_factory=dict)
    total_alerts: int = 0
    baseline_updated: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

    @classmethod
    def from_json(cls, data: str) -> DeviceProfile:
        d = json.loads(data)
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class BaselineDeviation:
    """A detected deviation from baseline behavior."""

    ip: str
    deviation_type: str   # new_dst_ip, new_port, volume_spike, new_category, new_domain, protocol_change
    description: str
    severity: str = "medium"
    score: float = 0.0    # 0.0-1.0 confidence
    alert_ids: list[str] = field(default_factory=list)
    baseline_context: str = ""  # what the baseline expected


class BaselineEngine:
    """Builds and maintains behavioral baselines per device."""

    def __init__(self, db: AlertDB, rebuild_interval_sec: int = 0, window_days: int = 0):
        self._db = db
        self._profiles: dict[str, DeviceProfile] = {}
        self._running = False
        self._task: asyncio.Task | None = None
        self._rebuild_interval = rebuild_interval_sec or _REBUILD_INTERVAL_SEC
        self._window_days = window_days or _BASELINE_WINDOW_DAYS

    # ── Lifecycle ─────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        # Load cached profiles from DB
        await self._load_profiles()
        self._task = asyncio.create_task(self._rebuild_loop(), name="baselines")
        log.info("Baseline engine started (%d cached profiles)", len(self._profiles))

    async def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("Baseline engine stopped")

    # ── Rebuild loop ──────────────────────────────────────────

    async def _rebuild_loop(self) -> None:
        # Do an initial build immediately
        try:
            await self.rebuild()
        except Exception:
            log.exception("Baseline: initial rebuild failed")

        while self._running:
            try:
                await asyncio.sleep(self._rebuild_interval)
            except asyncio.CancelledError:
                return
            try:
                await self.rebuild()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("Baseline: rebuild failed")

    async def rebuild(self) -> int:
        """Rebuild all device profiles from alert history. Returns profile count."""
        log.info("Baseline: rebuilding profiles from last %d days", self._window_days)

        rows = await self._db.execute_sql(
            """SELECT src_ip, dst_ip, dst_port, proto, category, title,
                      timestamp, id, src_dns, dst_dns
               FROM alerts
               WHERE datetime(timestamp) >= datetime('now', ?)
               AND src_ip IS NOT NULL AND src_ip != ''
               ORDER BY timestamp ASC""",
            (f"-{self._window_days} days",),
        )

        if not rows:
            log.info("Baseline: no alerts in window, skipping rebuild")
            return 0

        # Aggregate per src_ip
        ip_data: dict[str, dict[str, Any]] = defaultdict(lambda: {
            "alerts": [],
            "dst_ports": defaultdict(int),
            "dst_ips": set(),
            "categories": defaultdict(int),
            "protocols": defaultdict(int),
            "domains": set(),
            "hourly_counts": defaultdict(list),  # hour → [counts per day]
            "first_seen": None,
            "last_seen": None,
        })

        # Group alerts by (src_ip, day, hour) for per-hour-of-day stats
        daily_hourly: dict[str, dict[str, dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(int))
        )

        for row in rows:
            src_ip = row["src_ip"]
            d = ip_data[src_ip]
            d["alerts"].append(row["id"])

            ts = row["timestamp"] or ""
            if not d["first_seen"] or ts < d["first_seen"]:
                d["first_seen"] = ts
            if not d["last_seen"] or ts > d["last_seen"]:
                d["last_seen"] = ts

            if row["dst_port"]:
                d["dst_ports"][str(row["dst_port"])] += 1
            if row["dst_ip"]:
                d["dst_ips"].add(row["dst_ip"])
            if row["category"]:
                d["categories"][row["category"]] += 1
            if row["proto"]:
                d["protocols"][row["proto"]] += 1

            # Extract domains from DNS fields
            for dns_field in ("src_dns", "dst_dns"):
                dns = row.get(dns_field) or ""
                if dns and "." in dns:
                    d["domains"].add(dns)

            # Per-day-hour counting
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    day_key = dt.strftime("%Y-%m-%d")
                    hour_key = str(dt.hour)
                    daily_hourly[src_ip][day_key][hour_key] += 1
                except (ValueError, TypeError):
                    pass

        # Build profiles
        new_profiles: dict[str, DeviceProfile] = {}
        for ip, d in ip_data.items():
            # Compute hourly averages and stddev
            hourly_avg: dict[str, float] = {}
            hourly_std: dict[str, float] = {}
            days = daily_hourly.get(ip, {})
            num_days = max(len(days), 1)

            for hour in range(24):
                h = str(hour)
                counts = [days.get(day, {}).get(h, 0) for day in days]
                if counts:
                    avg = sum(counts) / len(counts)
                    variance = sum((c - avg) ** 2 for c in counts) / len(counts)
                    hourly_avg[h] = round(avg, 2)
                    hourly_std[h] = round(math.sqrt(variance), 2)
                else:
                    hourly_avg[h] = 0.0
                    hourly_std[h] = 0.0

            profile = DeviceProfile(
                ip=ip,
                asset_name=None,  # populated from asset table if available
                first_seen=d["first_seen"] or "",
                last_seen=d["last_seen"] or "",
                hourly_alert_counts=hourly_avg,
                hourly_alert_stddev=hourly_std,
                common_dst_ports=dict(d["dst_ports"]),
                common_dst_ips=sorted(d["dst_ips"])[:200],  # cap list size
                common_categories=dict(d["categories"]),
                dns_domains=sorted(d["domains"])[:200],
                protocols=dict(d["protocols"]),
                total_alerts=len(d["alerts"]),
                baseline_updated=now_iso(),
            )
            new_profiles[ip] = profile

        # Persist to DB
        for ip, profile in new_profiles.items():
            await self._db.execute_sql(
                """INSERT OR REPLACE INTO device_baselines
                   (ip, asset_name, first_seen, last_seen, profile_json,
                    baseline_updated, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, COALESCE(
                       (SELECT created_at FROM device_baselines WHERE ip = ?),
                       ?
                   ), ?)""",
                (ip, profile.asset_name, profile.first_seen, profile.last_seen,
                 profile.to_json(), profile.baseline_updated,
                 ip, now_iso(), now_iso()),
                commit=True,
            )

        self._profiles = new_profiles
        log.info("Baseline: rebuilt %d device profiles", len(new_profiles))
        return len(new_profiles)

    # ── Deviation detection ───────────────────────────────────

    def check_deviations(self, alerts: list[dict[str, Any]]) -> list[BaselineDeviation]:
        """Check a batch of alerts against baselines. Returns detected deviations."""
        if not self._profiles:
            return []

        deviations: list[BaselineDeviation] = []

        # Group current alerts by src_ip
        by_ip: dict[str, list[dict]] = defaultdict(list)
        for a in alerts:
            if a.get("src_ip"):
                by_ip[a["src_ip"]].append(a)

        for ip, ip_alerts in by_ip.items():
            profile = self._profiles.get(ip)
            if not profile or profile.total_alerts < 10:
                # Not enough history to establish baseline
                continue

            alert_ids = [a["id"] for a in ip_alerts if a.get("id")]

            # 1. New destination IP (never seen before)
            for a in ip_alerts:
                dst_ip = a.get("dst_ip") or ""
                if dst_ip and dst_ip not in profile.common_dst_ips and not _is_rfc1918(dst_ip):
                    deviations.append(BaselineDeviation(
                        ip=ip,
                        deviation_type="new_dst_ip",
                        description=(
                            f"{ip} connected to {dst_ip} for the first time. "
                            f"This IP has not been seen in the last {self._window_days} days of history."
                        ),
                        severity="medium",
                        score=0.6,
                        alert_ids=[a["id"]] if a.get("id") else [],
                        baseline_context=f"Known destinations: {len(profile.common_dst_ips)} IPs",
                    ))

            # 2. New destination port
            for a in ip_alerts:
                dst_port = str(a.get("dst_port") or "")
                if dst_port and dst_port != "0" and dst_port not in profile.common_dst_ports:
                    deviations.append(BaselineDeviation(
                        ip=ip,
                        deviation_type="new_port",
                        description=(
                            f"{ip} used destination port {dst_port} for the first time. "
                            f"Known ports: {list(profile.common_dst_ports.keys())[:10]}"
                        ),
                        severity="low",
                        score=0.4,
                        alert_ids=[a["id"]] if a.get("id") else [],
                        baseline_context=f"Known ports: {len(profile.common_dst_ports)}",
                    ))

            # 3. Volume spike (current hour count vs baseline)
            now = datetime.now(timezone.utc)
            hour_key = str(now.hour)
            current_count = len(ip_alerts)
            avg = profile.hourly_alert_counts.get(hour_key, 0)
            std = profile.hourly_alert_stddev.get(hour_key, 0)

            if std > 0 and current_count > avg + (_DEVIATION_SIGMA * std):
                z_score = (current_count - avg) / std if std > 0 else 0
                deviations.append(BaselineDeviation(
                    ip=ip,
                    deviation_type="volume_spike",
                    description=(
                        f"{ip} generated {current_count} alerts this hour, "
                        f"vs baseline avg {avg:.1f} (σ={std:.1f}, z={z_score:.1f})"
                    ),
                    severity="high" if z_score > 5 else "medium",
                    score=min(z_score / 10, 1.0),
                    alert_ids=alert_ids,
                    baseline_context=f"Hourly avg: {avg:.1f}, stddev: {std:.1f}",
                ))

            # 4. New alert category
            for a in ip_alerts:
                cat = a.get("category") or ""
                if cat and cat not in profile.common_categories:
                    deviations.append(BaselineDeviation(
                        ip=ip,
                        deviation_type="new_category",
                        description=(
                            f"{ip} triggered new alert category '{cat}' "
                            f"not seen in {self._window_days}-day baseline."
                        ),
                        severity="medium",
                        score=0.5,
                        alert_ids=[a["id"]] if a.get("id") else [],
                        baseline_context=f"Known categories: {list(profile.common_categories.keys())[:10]}",
                    ))

            # 5. Protocol change
            for a in ip_alerts:
                proto = a.get("proto") or ""
                if proto and proto not in profile.protocols:
                    deviations.append(BaselineDeviation(
                        ip=ip,
                        deviation_type="protocol_change",
                        description=(
                            f"{ip} used protocol {proto} for the first time. "
                            f"Known protocols: {list(profile.protocols.keys())}"
                        ),
                        severity="medium",
                        score=0.5,
                        alert_ids=[a["id"]] if a.get("id") else [],
                        baseline_context=f"Known protocols: {list(profile.protocols.keys())}",
                    ))

        return deviations

    # ── Profile access ────────────────────────────────────────

    def get_profile(self, ip: str) -> DeviceProfile | None:
        return self._profiles.get(ip)

    def get_all_profiles(self) -> dict[str, DeviceProfile]:
        return dict(self._profiles)

    # ── Internal ──────────────────────────────────────────────

    async def _load_profiles(self) -> None:
        """Load cached profiles from database."""
        try:
            rows = await self._db.execute_sql(
                "SELECT ip, profile_json FROM device_baselines"
            )
            for row in rows:
                try:
                    self._profiles[row["ip"]] = DeviceProfile.from_json(row["profile_json"])
                except Exception:
                    pass
            log.info("Baseline: loaded %d cached profiles", len(self._profiles))
        except Exception:
            log.debug("Baseline: no cached profiles found (table may not exist yet)")


def _is_rfc1918(ip: str) -> bool:
    if not ip:
        return False
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return (a == 10) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
    except (ValueError, IndexError):
        return False
