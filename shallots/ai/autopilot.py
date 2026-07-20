"""AI Autopilot Worker for Security Shallots.

Operates in two modes:
  - copilot:   Suggests actions (noise suppression, threat escalation) as pending
               decisions that a human reviews and approves.
  - autopilot: Acts autonomously - auto-suppresses noise, creates silence rules,
               raises squawks for threats, generates shift reports.

The worker runs as an asyncio background task alongside TriageWorker. It processes
alerts that have already been through triage (verdict != 'pending') and applies
higher-level pattern recognition: volume-based noise detection and AI threat
assessment for actionable alerts.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from typing import TYPE_CHECKING, Any, Callable, Coroutine

if TYPE_CHECKING:
    from shallots.config import AIConfig
    from shallots.store.db import AlertDB

from shallots.ai.ollama_client import OllamaClient
from shallots.ai.prompts import (
    AUTOPILOT_NOISE_SYSTEM,
    AUTOPILOT_NOISE_TEMPLATE,
    AUTOPILOT_SHIFT_SYSTEM,
    AUTOPILOT_SHIFT_TEMPLATE,
    AUTOPILOT_THREAT_SYSTEM,
    AUTOPILOT_THREAT_TEMPLATE,
)
from shallots.store.models import now_iso

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

WsBroadcastFn = Callable[[dict], Coroutine[Any, Any, None]]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ACTIONABLE_VERDICTS = frozenset(["investigate", "escalate"])
_ACTIONABLE_SEVERITIES = frozenset(["high", "critical"])
_SQUAWK_BLOCK_TITLE_FRAGMENTS = (
    "et info observed dns query to .",
    "et info observed ip lookup domain",
    "et info abused hosting domain",
    "ended abnormally",
)
_SQUAWK_ALLOW_TITLE_FRAGMENTS = (
    "exploit",
    "malware",
    "trojan",
    "c2",
    "command and control",
    "ransomware",
    "credential",
    "persistence",
    "protected file changed",
    "ssh scan",
)
_SQUAWK_ALLOW_CATEGORIES = ("malware", "exploit", "c2", "credential", "persistence")


def _slim_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Return a trimmed alert dict suitable for sending to the AI."""
    return {
        "id": alert.get("id", ""),
        "timestamp": alert.get("timestamp", ""),
        "source": alert.get("source", ""),
        "severity": alert.get("severity", "medium"),
        "title": alert.get("title", ""),
        "description": alert.get("description", ""),
        "src_ip": alert.get("src_ip", ""),
        "dst_ip": alert.get("dst_ip", ""),
        "dst_port": alert.get("dst_port", 0),
        "proto": alert.get("proto", ""),
        "category": alert.get("category", ""),
        "verdict": alert.get("verdict", ""),
        "confidence": alert.get("confidence", 0.0),
    }


def _parse_json_response(raw: str) -> list[dict] | None:
    """Parse a JSON array from an AI response, stripping markdown fences if needed.

    Returns the parsed list, or None on failure.
    """
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.splitlines()
        inner = lines[1:] if len(lines) > 1 else lines
        if inner and inner[-1].strip() == "```":
            inner = inner[:-1]
        raw = "\n".join(inner).strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        log.warning("Autopilot: JSON parse error: %s | raw: %.300s", exc, raw)
        return None

    if not isinstance(parsed, list):
        log.warning("Autopilot: expected JSON array, got %s", type(parsed).__name__)
        return None

    return parsed


def _should_raise_squawk(alert: dict[str, Any], assessment: str, should_squawk: bool) -> bool:
    """Local safety gate for high-noise squawk generation."""
    title = str(alert.get("title") or "").lower()
    category = str(alert.get("category") or "").lower()
    severity = str(alert.get("severity") or "").lower()

    # Never page the operator about an alert the pipeline already suppressed as noise.
    if str(alert.get("verdict") or "").lower() == "suppress":
        return False

    if any(fragment in title for fragment in _SQUAWK_BLOCK_TITLE_FRAGMENTS):
        return False

    if assessment == "critical" or severity == "critical":
        return True

    if assessment not in ("high", "critical") and not should_squawk:
        return False

    if any(fragment in title for fragment in _SQUAWK_ALLOW_TITLE_FRAGMENTS):
        return True
    if any(fragment in category for fragment in _SQUAWK_ALLOW_CATEGORIES):
        return True
    if alert.get("verdict") == "escalate":
        return True

    return False


def _detail_tuple(detail: str) -> tuple[str, str, int] | None:
    """Extract stable network tuple facts from a squawk detail JSON blob."""
    try:
        parsed = json.loads(detail)
    except json.JSONDecodeError:
        return None

    src_ip = str(parsed.get("src_ip") or "")
    dst_ip = str(parsed.get("dst_ip") or "")
    try:
        dst_port = int(parsed.get("dst_port") or 0)
    except (TypeError, ValueError):
        dst_port = 0

    if not src_ip or not dst_ip:
        return None
    return src_ip, dst_ip, dst_port


# ---------------------------------------------------------------------------
# AutopilotWorker
# ---------------------------------------------------------------------------


class AutopilotWorker:
    """Async background worker providing autonomous or co-pilot AI oversight.

    Responsibilities:
    1. Noise detection - identifies high-volume repetitive alert patterns.
    2. Threat assessment - sends actionable alerts to the AI for a second opinion.
    3. Squawk generation - raises high-priority notices for critical threats.
    4. Shift reports - periodic AI-generated shift summaries.

    Mode behaviour:
      copilot:   Creates 'pending' ai_decisions for human review. Never auto-suppresses.
      autopilot: Acts immediately - suppresses noise, creates silence rules, escalates.
      off:       No action. The worker loop runs but _process_batch returns immediately.
    """

    def __init__(
        self,
        cfg: AIConfig,
        db: AlertDB,
        ws_broadcast: WsBroadcastFn | None = None,
        on_silence_rule_created: Callable[[str, str, str], None] | None = None,
    ) -> None:
        self._cfg = cfg
        self._db = db
        self._ws_broadcast = ws_broadcast
        self._on_silence_rule_created = on_silence_rule_created
        self._client: OllamaClient | None = None
        self._running = False

        # Runtime mode - can be changed via set_mode() while running
        self._mode: str = cfg.autopilot.mode

        # Monotonic clock for shift report scheduling
        self._last_shift_report: float = 0.0

        # Cumulative stats
        self.total_processed: int = 0
        self.total_suppressed: int = 0
        self.total_escalated: int = 0
        self.total_squawks: int = 0

    # ── Lifecycle ────────────────────────────────────────────

    async def run(self, shutdown: asyncio.Event) -> None:
        """Run the autopilot worker until the shutdown event is set."""
        self._running = True
        ap = self._cfg.autopilot
        log.info(
            "AutopilotWorker started (mode=%s, noise_threshold=%d, interval=%ds)",
            self._mode,
            ap.noise_threshold,
            ap.batch_interval_sec,
        )

        if self._cfg.tier != "none":
            self._client = OllamaClient(
                base_url=self._cfg.ollama_url or "http://localhost:11434",
            )

        try:
            while not shutdown.is_set():
                try:
                    await self._process_batch()
                except asyncio.CancelledError:
                    return
                except Exception:
                    log.exception("AutopilotWorker: unhandled error in batch cycle")

                try:
                    await asyncio.sleep(ap.batch_interval_sec)
                except asyncio.CancelledError:
                    return
        finally:
            self._running = False
            if self._client:
                await self._client.close()
                self._client = None
            log.info("AutopilotWorker stopped")

    async def set_mode(self, mode: str) -> None:
        """Change the operating mode at runtime."""
        if mode not in ("off", "copilot", "autopilot"):
            raise ValueError(f"Invalid autopilot mode: {mode!r}")
        log.info("AutopilotWorker: mode changed %s → %s", self._mode, mode)
        self._mode = mode

    # ── Main batch cycle ──────────────────────────────────────

    async def _process_batch(self) -> None:
        """Core processing loop: cluster sweep → noise detection → threat assessment → shift report."""
        if self._mode == "off":
            return

        ap = self._cfg.autopilot

        # Phase 0: Cluster-based bulk noise sweep (works on ALL pending clusters,
        # not just recent alerts - critical for clearing backlogs).
        if self._mode == "autopilot":
            await self._sweep_noisy_clusters()

        # Fetch recently triaged (non-pending) alerts from the last few minutes.
        # The window is twice the batch interval to avoid gaps at cycle boundaries.
        window_min = max(2, (ap.batch_interval_sec * 2) // 60)
        window_str = f"{window_min}m"

        try:
            raw_alerts = await self._db.get_alerts(limit=100, since=window_str)
        except Exception:
            log.exception("AutopilotWorker: failed to fetch alerts")
            return

        # Filter to alerts that have been through triage
        alerts = [a for a in raw_alerts if a.get("verdict") not in (None, "pending", "")]
        if not alerts:
            log.debug("AutopilotWorker: no triaged alerts in window")
        else:
            log.info(
                "AutopilotWorker: processing %d triaged alerts (mode=%s)",
                len(alerts),
                self._mode,
            )
            self.total_processed += len(alerts)

            # Phase 1: heuristic noise detection (fast, no AI needed)
            noise_alerts, remaining = await self._detect_noise(alerts)

            # Phase 2: AI threat assessment on non-noise actionable alerts
            if remaining and self._cfg.tier != "none":
                await self._assess_threats(remaining)

        # Phase 3: shift report (time-gated, independent of alert volume)
        await self._maybe_shift_report()

    # Keywords in alert titles that should NEVER be auto-suppressed.
    # These get escalated instead - even if noisy, they indicate real threats.
    PROTECTED_KEYWORDS = {
        "exploit", "malware", "trojan", "backdoor", "ransomware", "c2",
        "command and control", "reverse shell", "webshell", "rootkit",
        "credential theft", "exfiltration", "brute force", "privilege escalation",
        "lateral movement", "persistence",
    }

    # Grace period: don't auto-suppress clusters younger than this (seconds)
    GRACE_PERIOD_SEC = 600  # 10 minutes

    async def _sweep_noisy_clusters(self) -> None:
        """Bulk-suppress noisy clusters with safety rails.

        Safety rails to prevent hiding real threats:
        1. Severity gate - never suppress critical/high clusters, escalate them
        2. Title keywords - protect exploit/malware/c2 patterns from suppression
        3. Grace period - don't suppress clusters created less than 10min ago
        """
        ap = self._cfg.autopilot
        try:
            noisy = await self._db.get_noisy_clusters(
                min_count=ap.noise_threshold,
                window_minutes=ap.noise_window_min,
            )
        except Exception:
            log.debug("AutopilotWorker: cluster sweep query failed")
            return

        if not noisy:
            return

        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        swept = 0
        escalated = 0
        skipped_grace = 0

        for cluster in noisy:
            sev = (cluster.get("severity") or "").lower()
            title = (cluster.get("title") or "").lower()
            created = cluster.get("first_seen") or ""

            # Grace period - skip clusters created less than 10 minutes ago
            try:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                age_sec = (now - created_dt).total_seconds()
                if age_sec < self.GRACE_PERIOD_SEC:
                    skipped_grace += 1
                    continue
            except (ValueError, TypeError):
                pass  # can't parse date, proceed anyway

            # Check if this cluster is protected from suppression
            is_high_sev = sev in ("critical", "high")
            is_protected_title = any(kw in title for kw in self.PROTECTED_KEYWORDS)

            if is_high_sev or is_protected_title:
                # Escalate instead of suppress - this is noisy BUT dangerous
                try:
                    updated = await self._db.set_cluster_verdict(
                        cluster["id"], "escalate",
                        reasoning=f"Autopilot: noisy but protected cluster "
                                  f"(sev={sev}, {cluster['alert_count']} events) - escalated for review",
                    )
                    escalated += updated
                    log.info("AutopilotWorker: ESCALATED protected cluster %s (%s, %dx, %s)",
                             cluster["id"], sev, cluster["alert_count"], title[:60])
                except Exception:
                    log.debug("AutopilotWorker: failed to escalate cluster %s", cluster.get("id"))
            else:
                # Safe to suppress - low/medium severity, no dangerous keywords
                try:
                    updated = await self._db.set_cluster_verdict(
                        cluster["id"], "suppress",
                        reasoning=f"Autopilot: noise cluster ({cluster['alert_count']} events, "
                                  f"{cluster.get('src_ip')}:{title[:60]})",
                    )
                    swept += updated
                    self.total_suppressed += updated
                except Exception:
                    log.debug("AutopilotWorker: failed to suppress cluster %s", cluster.get("id"))

        if swept or escalated:
            log.info("AutopilotWorker: cluster sweep - suppressed=%d, escalated=%d, grace_skipped=%d",
                     swept, escalated, skipped_grace)
            await self._broadcast({
                "type": "ai_decision",
                "data": {
                    "action": "cluster_sweep",
                    "status": "done",
                    "summary": f"Sweep: {swept} suppressed, {escalated} escalated, {skipped_grace} grace-skipped",
                    "alerts_suppressed": swept,
                    "alerts_escalated": escalated,
                    "grace_skipped": skipped_grace,
                },
            })

    # ── Phase 1: Noise Detection ──────────────────────────────

    async def _detect_noise(
        self, alerts: list[dict]
    ) -> tuple[list[dict], list[dict]]:
        """Partition alerts into (noise, remaining) using cluster-based heuristics.

        Noise is defined as: alerts belonging to a cluster with alert_count >= noise_threshold
        and pending verdict, OR matching a high-confidence known-noise verdict
        in the ai_verdicts table.
        """
        ap = self._cfg.autopilot
        noise_alerts: list[dict] = []
        remaining: list[dict] = []

        # Query clusters that qualify as noisy
        try:
            noisy_clusters = await self._db.get_noisy_clusters(
                min_count=ap.noise_threshold,
                window_minutes=ap.noise_window_min,
            )
            noisy_cluster_ids = {c["id"] for c in noisy_clusters}
        except Exception:
            log.debug("AutopilotWorker: could not query noisy clusters, falling back")
            noisy_clusters = []
            noisy_cluster_ids = set()

        # Also check known noise IPs from ai_verdicts
        known_noise_ips: set[str] = set()
        unique_ips = {a.get("src_ip") for a in alerts if a.get("src_ip")}
        for src_ip in unique_ips:
            try:
                verdict_rec = await self._db.get_verdict_for_pattern("src_ip", src_ip)
                if verdict_rec and verdict_rec.get("verdict") == "noise" and verdict_rec.get("confidence", 0) >= 0.8:
                    known_noise_ips.add(src_ip)
            except Exception:
                pass

        # Partition alerts - but protect high-severity / dangerous alerts from noise bucket
        noise_groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for alert in alerts:
            cluster_id = alert.get("cluster_id") or ""
            src_ip = alert.get("src_ip") or ""
            sev = (alert.get("severity") or "").lower()
            title_lower = (alert.get("title") or "").lower()
            is_in_noisy_cluster = cluster_id in noisy_cluster_ids
            is_known_noise = src_ip in known_noise_ips

            # Never classify protected alerts as noise - keep in remaining
            is_protected = (
                sev in ("critical", "high")
                or any(kw in title_lower for kw in self.PROTECTED_KEYWORDS)
            )

            if (is_in_noisy_cluster or is_known_noise) and not is_protected:
                key = (src_ip, alert.get("title") or "")
                noise_groups[key].append(alert)
                noise_alerts.append(alert)
            else:
                remaining.append(alert)

        if noise_groups:
            await self._handle_noise(noise_groups, self._mode)

        return noise_alerts, remaining

    async def _handle_noise(
        self,
        noise_groups: dict[tuple[str, str], list[dict]],
        mode: str,
    ) -> None:
        """Process identified noise groups: record decisions, optionally suppress."""
        ap = self._cfg.autopilot

        for (src_ip, title), group in noise_groups.items():
            alert_ids = [a["id"] for a in group if a.get("id")]
            count = len(group)
            summary = f"Noise pattern: {count}x [{title}] from {src_ip or '(unknown IP)'}"
            detail = json.dumps({
                "src_ip": src_ip,
                "title": title,
                "count": count,
                "alert_ids": alert_ids[:20],  # cap detail size
                "detected_at": now_iso(),
            })

            decision_status = "done" if mode == "autopilot" else "pending"

            try:
                decision_id = await self._db.add_ai_decision(
                    mode=mode,
                    action="suppress_noise",
                    summary=summary,
                    detail=detail,
                    alert_ids=alert_ids,
                    status=decision_status,
                )
                log.info(
                    "AutopilotWorker: noise decision %s (%s) for %s",
                    decision_id, decision_status, summary,
                )
            except Exception:
                log.exception("AutopilotWorker: failed to record noise decision")
                continue

            # Upsert ai_verdicts so future batches recognise this pattern quickly
            try:
                await self._db.upsert_ai_verdict(
                    pattern_type="src_ip",
                    pattern=src_ip,
                    verdict="noise",
                    confidence=0.85,
                    auto_rule_id=None,
                )
            except Exception:
                log.debug("AutopilotWorker: could not upsert ai_verdict for %s", src_ip)

            if mode == "autopilot":
                # Suppress individual alerts (only those not already handled by cluster verdict)
                for alert in group:
                    if alert.get("verdict") == "suppress":
                        continue  # already suppressed by cluster verdict
                    try:
                        await self._db.update_verdict(
                            alert_id=alert["id"],
                            verdict="suppress",
                            confidence=0.85,
                            reasoning=f"Autopilot: noise pattern ({count} events, same IP+title)",
                        )
                        self.total_suppressed += 1
                    except Exception:
                        log.debug("AutopilotWorker: could not suppress alert %s", alert.get("id"))

                # Auto-create a narrow combo rule once volume exceeds auto_silence_after
                if count >= ap.auto_silence_after and src_ip:
                    try:
                        existing_rule = await self._db.get_silence_rule(
                            match_type="src_ip+title",
                            pattern=src_ip,
                            pattern2=title,
                        )
                        if existing_rule:
                            rule_id = existing_rule["id"]
                        else:
                            rule_id = await self._db.add_silence_rule(
                                match_type="src_ip+title",
                                pattern=src_ip,
                                reason=(
                                    f"Autopilot: auto-silenced after {count} noise events "
                                    f"({title[:80]})"
                                ),
                                pattern2=title,
                            )
                            if callable(self._on_silence_rule_created):
                                self._on_silence_rule_created("src_ip+title", src_ip, title)
                        # Update the ai_verdict record with the new rule ID
                        await self._db.upsert_ai_verdict(
                            pattern_type="src_ip",
                            pattern=src_ip,
                            verdict="noise",
                            confidence=0.9,
                            auto_rule_id=rule_id,
                        )
                        log.info(
                            "AutopilotWorker: ensured silence rule %s for %s + %r (threshold=%d)",
                            rule_id, src_ip, title[:80], count,
                        )
                    except Exception:
                        log.exception("AutopilotWorker: failed to create silence rule for %s", src_ip)

            # Broadcast decision to WebSocket clients
            await self._broadcast({
                "type": "ai_decision" if mode == "autopilot" else "ai_suggestion",
                "data": {
                    "id": decision_id,
                    "action": "suppress_noise",
                    "status": decision_status,
                    "summary": summary,
                    "src_ip": src_ip,
                    "title": title,
                    "count": count,
                },
            })

    # ── Phase 2: Threat Assessment ────────────────────────────

    async def _assess_threats(self, alerts: list[dict]) -> None:
        """Send actionable alerts to the AI for threat assessment.

        Only processes alerts that are high/critical severity OR have an
        investigate/escalate verdict - i.e., alerts that warrant a second look.
        """
        # Filter to alerts that actually need attention
        candidates = [
            a for a in alerts
            if (
                a.get("severity") in _ACTIONABLE_SEVERITIES
                or a.get("verdict") in _ACTIONABLE_VERDICTS
            )
        ]
        if not candidates:
            log.debug("AutopilotWorker: no actionable alerts for threat assessment")
            return

        log.info("AutopilotWorker: sending %d alerts for threat assessment", len(candidates))

        slim = [_slim_alert(a) for a in candidates]
        prompt = AUTOPILOT_THREAT_TEMPLATE.format(
            count=len(slim),
            alerts_json=json.dumps(slim, indent=2),
        )

        try:
            raw = await self._call_ai(prompt, AUTOPILOT_THREAT_SYSTEM.strip())
        except Exception as exc:
            log.error("AutopilotWorker: threat assessment AI call failed: %s", exc)
            return

        parsed = _parse_json_response(raw)
        if not parsed:
            log.warning("AutopilotWorker: could not parse threat assessment response")
            return

        # Build an index map from the response
        indexed: dict[int, dict] = {}
        for item in parsed:
            if isinstance(item, dict):
                idx = item.get("index")
                if isinstance(idx, int) and 0 <= idx < len(candidates):
                    indexed[idx] = item

        for i, alert in enumerate(candidates):
            item = indexed.get(i)
            if not item:
                continue

            assessment = item.get("assessment", "medium")
            reasoning = str(item.get("reasoning", ""))
            should_squawk = bool(item.get("squawk", False))

            log.debug(
                "AutopilotWorker: alert %s assessed as %s (squawk=%s)",
                alert.get("id"), assessment, should_squawk,
            )

            if assessment == "noise":
                # Reclassify as noise
                if self._mode == "autopilot":
                    try:
                        await self._db.update_verdict(
                            alert_id=alert["id"],
                            verdict="suppress",
                            confidence=0.8,
                            reasoning=f"Autopilot threat-assess: {reasoning}",
                        )
                        self.total_suppressed += 1
                    except Exception:
                        log.debug("AutopilotWorker: could not suppress %s", alert.get("id"))

            elif _should_raise_squawk(alert, assessment, should_squawk):
                # Raise a squawk for significant threats
                squawk_severity = assessment if assessment in ("high", "critical") else "high"
                title = f"AI Threat: {alert.get('title', 'Unknown alert')}"
                detail = json.dumps({
                    "alert_id": alert.get("id"),
                    "src_ip": alert.get("src_ip"),
                    "dst_ip": alert.get("dst_ip"),
                    "dst_port": alert.get("dst_port"),
                    "original_severity": alert.get("severity"),
                    "assessment": assessment,
                    "reasoning": reasoning,
                })

                await self._create_squawk(
                    title=title,
                    detail=detail,
                    severity=squawk_severity,
                    alert_ids=[alert["id"]],
                )
                self.total_escalated += 1
            elif assessment in ("high", "critical") or should_squawk:
                log.info(
                    "AutopilotWorker: squawk blocked by local policy for alert %s (%s)",
                    alert.get("id"), alert.get("title", ""),
                )

    # ── Phase 3: Shift Reports ────────────────────────────────

    async def _maybe_shift_report(self) -> None:
        """Generate a shift report if the configured interval has elapsed."""
        ap = self._cfg.autopilot
        interval_sec = ap.shift_report_hours * 3600

        now = time.monotonic()
        if now - self._last_shift_report < interval_sec:
            return

        # First run: set baseline and skip (avoids generating a report on startup
        # before any real data has accumulated in the current shift).
        if self._last_shift_report == 0.0:
            self._last_shift_report = now
            return

        log.info("AutopilotWorker: generating shift report")
        self._last_shift_report = now
        await self._generate_shift_report()

    async def _generate_shift_report(self) -> None:
        """Pull stats, send to AI, store the report, and broadcast it."""
        ap = self._cfg.autopilot
        period_end = now_iso()

        try:
            stats = await self._db.get_ai_stats()
        except Exception:
            log.exception("AutopilotWorker: failed to get AI stats for shift report")
            return

        try:
            recent_alerts = await self._db.get_alerts(
                limit=20,
                severity="high",
                since=f"{ap.shift_report_hours}h",
            )
        except Exception:
            recent_alerts = []

        top_alerts = [_slim_alert(a) for a in recent_alerts]
        period_start = f"-{ap.shift_report_hours}h"  # relative notation for context

        prompt = AUTOPILOT_SHIFT_TEMPLATE.format(
            period_start=period_start,
            period_end=period_end,
            stats_json=json.dumps(stats, indent=2),
            top_alerts_json=json.dumps(top_alerts, indent=2),
        )

        try:
            summary = await self._call_ai(prompt, AUTOPILOT_SHIFT_SYSTEM.strip())
        except Exception as exc:
            log.error("AutopilotWorker: shift report AI call failed: %s", exc)
            return

        try:
            report_id = await self._db.add_shift_report(
                period_start=period_start,
                period_end=period_end,
                summary=summary,
                stats=json.dumps(stats),
                threats=json.dumps(top_alerts),
            )
            log.info("AutopilotWorker: shift report %s stored", report_id)
        except Exception:
            log.exception("AutopilotWorker: failed to store shift report")
            return

        await self._broadcast({
            "type": "shift_report",
            "data": {
                "id": report_id,
                "period_start": period_start,
                "period_end": period_end,
                "summary": summary[:500],  # truncate for WS payload
                "stats": stats,
            },
        })

    # ── Squawk helpers ────────────────────────────────────────

    async def _create_squawk(
        self,
        title: str,
        detail: str,
        severity: str,
        alert_ids: list[str],
    ) -> str:
        """Create a squawk in the DB and broadcast it.

        Returns the new squawk ID, or an empty string on failure.
        """
        existing_id = await self._find_active_tuple_squawk(title, detail)
        if existing_id:
            log.info(
                "AutopilotWorker: reused active squawk %s for tuple duplicate [%s]",
                existing_id, title,
            )
            return existing_id

        try:
            squawk_id = await self._db.add_squawk(
                severity=severity,
                title=title,
                detail=detail,
                alert_ids=alert_ids,
            )
            self.total_squawks += 1
            log.info(
                "AutopilotWorker: squawk %s raised [%s] %s",
                squawk_id, severity.upper(), title,
            )
        except Exception:
            log.exception("AutopilotWorker: failed to create squawk: %s", title)
            return ""

        await self._broadcast({
            "type": "squawk",
            "data": {
                "id": squawk_id,
                "severity": severity,
                "title": title,
                "detail": detail,
                "alert_ids": alert_ids,
                "created_at": now_iso(),
            },
        })

        return squawk_id

    async def _find_active_tuple_squawk(self, title: str, detail: str) -> str:
        """Find an active squawk for the same behavioral tuple.

        Exact alert-id dedupe happens in the DB. This catches repeated instances
        of the same behavior that arrive as new alerts, such as internal SSH scan
        bursts, without suppressing the original finding.
        """
        detail_tuple = _detail_tuple(detail)
        if detail_tuple is None:
            return ""

        src_ip, dst_ip, dst_port = detail_tuple
        params: list[Any] = [
            title,
            f'%"src_ip": "{src_ip}"%',
            f'%"dst_ip": "{dst_ip}"%',
        ]
        port_clause = ""
        if dst_port > 0:
            port_clause = "AND detail LIKE ?"
            params.append(f'%"dst_port": {dst_port}%')

        rows = await self._db.execute_sql(
            f"""
            SELECT id FROM squawks
            WHERE dismissed = 0
              AND title = ?
              AND detail LIKE ?
              AND detail LIKE ?
              {port_clause}
            ORDER BY ts DESC LIMIT 1
            """,
            tuple(params),
            max_rows=1,
        )
        if not rows and dst_port > 0:
            rows = await self._db.execute_sql(
                """
                SELECT id FROM squawks
                WHERE dismissed = 0
                  AND title = ?
                  AND detail LIKE ?
                  AND detail LIKE ?
                ORDER BY ts DESC LIMIT 1
                """,
                (title, f'%"src_ip": "{src_ip}"%', f'%"dst_ip": "{dst_ip}"%'),
                max_rows=1,
            )

        return str(rows[0]["id"]) if rows else ""

    # ── AI dispatch (mirrors TriageWorker._call_ai exactly) ───

    async def _call_ai(self, prompt: str, system: str) -> str:
        """Route the AI call to the appropriate backend based on configured tier."""
        cfg = self._cfg
        tier = cfg.tier

        if tier in ("remote_micro", "remote_standard", "local"):
            if self._client is None:
                raise RuntimeError("AI client not initialised - check tier configuration")
            return await self._client.generate(
                prompt=prompt,
                model=cfg.ollama_model,
                system=system,
            )

        if tier == "remote_api":
            if cfg.openai_api_key:
                if self._client is None:
                    raise RuntimeError("AI client not initialised - check tier configuration")
                return await self._client.generate_openai(
                    prompt=prompt,
                    model=cfg.ollama_model or "gpt-4o-mini",
                    api_key=cfg.openai_api_key,
                    system=system,
                )
            if cfg.anthropic_api_key:
                if self._client is None:
                    raise RuntimeError("AI client not initialised - check tier configuration")
                return await self._client.generate_anthropic(
                    prompt=prompt,
                    model=cfg.ollama_model or "claude-3-haiku-20240307",
                    api_key=cfg.anthropic_api_key,
                    system=system,
                )
            raise ValueError("remote_api tier requires openai_api_key or anthropic_api_key")

        raise ValueError(f"Unknown AI tier: {tier!r}")

    # ── WebSocket broadcast ───────────────────────────────────

    async def _broadcast(self, msg: dict) -> None:
        """Push a message to all connected WebSocket clients (if handler is set)."""
        if self._ws_broadcast is None:
            return
        try:
            await self._ws_broadcast(msg)
        except Exception:
            log.debug("AutopilotWorker: WS broadcast failed (non-fatal)")

    # ── Stats ─────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Return current worker statistics."""
        return {
            "mode": self._mode,
            "running": self._running,
            "total_processed": self.total_processed,
            "total_suppressed": self.total_suppressed,
            "total_escalated": self.total_escalated,
            "total_squawks": self.total_squawks,
            "tier": self._cfg.tier,
            "noise_threshold": self._cfg.autopilot.noise_threshold,
            "auto_silence_after": self._cfg.autopilot.auto_silence_after,
            "shift_report_hours": self._cfg.autopilot.shift_report_hours,
            "batch_interval_sec": self._cfg.autopilot.batch_interval_sec,
        }
