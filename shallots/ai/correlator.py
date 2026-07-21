"""Cross-alert correlation engine for Security Shallots."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.config import AIConfig
    from shallots.store.db import AlertDB

from shallots.ai.ollama_client import OllamaClient
from shallots.ai.prompts import CORRELATION_SYSTEM, CORRELATION_TEMPLATE
from shallots.store.models import Correlation, now_iso

log = logging.getLogger(__name__)

# How far back to look when pulling alerts for correlation
_WINDOW_MINUTES = 60
_RUN_INTERVAL_SEC = 300  # 5 minutes

# Thresholds for rule-based pre-grouping
_PORT_SCAN_THRESHOLD = 15      # distinct dst_ports from one src_ip → port scan
_BRUTE_FORCE_THRESHOLD = 15    # auth failures to same target in window
_BEACON_THRESHOLD = 12         # repeat connections to same dst at regular intervals
_BEACON_MAX_CV = 0.35          # max interval jitter (stddev/mean) to call it a beacon

# Known infrastructure IPs - never flag traffic between these as suspicious.
# Populated at runtime from config (suppression.source_ips) + auto-detected
# server IP. The default is empty - users add their own via config.yaml.
_INFRA_IPS: frozenset = frozenset()


def _entity_signature(alert_ids: list[str], alerts_by_id: dict[str, dict]) -> str:
    """Deterministic signature of the concrete entities involved, used as the
    dedup key INSTEAD OF pattern/summary - both are AI-generated free text that
    gets reworded every cycle even for an unchanged ongoing event, so text-based
    dedup barely ever matches itself twice.

    Prefers src/dst IP+port pairs when the underlying alerts carry structured
    network data. Host-local alerts (auditd/execmon command captures, which
    never populate src_ip/dst_ip) fall back to the sorted alert IDs themselves:
    the same recurring alert row(s) are unambiguously the same event no matter
    what label the AI puts on the correlation. Caught live 2026-07-21: two
    fresh "duplicate" incidents were still created post-fix from the exact
    same two auditd alerts because their empty IP columns made every
    IP-signature match trivially equal, so only the (still-varying) AI pattern
    label was left to distinguish them.
    """
    triples = set()
    for aid in alert_ids:
        a = alerts_by_id.get(aid)
        if not a:
            continue
        triples.add((a.get("src_ip") or "", a.get("dst_ip") or "", a.get("dst_port") or ""))
    sig = "|".join(sorted(f"{s}>{d}:{p}" for s, d, p in triples if s or d or p))
    if sig:
        return sig
    return "ids:" + "|".join(sorted(alert_ids))


class Correlator:
    """Background task that detects multi-alert patterns using AI and heuristics.

    Every _RUN_INTERVAL_SEC seconds:
    1. Pull all alerts from the last _WINDOW_MINUTES.
    2. Run lightweight rule-based grouping to find obvious candidates.
    3. Run ML anomaly detection and baseline deviation checks.
    4. Send candidate groups to AI for pattern identification.
    5. Persist new Correlation objects to the database.
    6. Feed correlations to kill chain detector.

    Detects:
    - Port scans:       many distinct dst_ports from the same src_ip.
    - Brute force:      repeated authentication failures to the same target.
    - Lateral movement: internal src → internal dst connections post-ingress.
    - Data exfiltration: large outbound traffic / unusual volume to external IPs.
    - C2 beaconing:     periodic repeat connections to the same external dst.
    - ML anomalies:     statistically unusual alerts (Isolation Forest).
    - Baseline deviations: first-time behaviors, volume spikes per device.
    - Kill chain stages: multi-stage attack progression.
    """

    def __init__(self, cfg: AIConfig, db: AlertDB, infra_ips: set[str] | None = None) -> None:
        global _INFRA_IPS
        self._cfg = cfg
        self._db = db
        self._client: OllamaClient | None = None
        self._running = False
        self._task: asyncio.Task | None = None
        # Threat engine references (injected by daemon after start)
        self._baselines = None   # BaselineEngine
        self._graph = None       # NetworkGraph
        self._ml_detector = None # MLDetectorEngine
        self._killchain = None   # KillChainDetector
        # Populate infra IPs from config
        if infra_ips:
            _INFRA_IPS = frozenset(infra_ips)

    # ── Lifecycle ────────────────────────────────────────────

    async def start(self) -> None:
        """Start the correlator background task."""
        if self._running:
            return
        self._running = True
        if self._cfg.tier != "none":
            self._client = OllamaClient(
                base_url=self._cfg.ollama_url or "http://localhost:11434",
            )
        self._task = asyncio.create_task(self._run(), name="correlator")
        log.info(
            "Correlator started (tier=%s, window=%dm, interval=%ds)",
            self._cfg.tier,
            _WINDOW_MINUTES,
            _RUN_INTERVAL_SEC,
        )

    async def stop(self) -> None:
        """Stop the correlator and clean up resources."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._client:
            await self._client.close()
            self._client = None
        log.info("Correlator stopped")

    # ── Main loop ────────────────────────────────────────────

    async def _run(self) -> None:
        """Periodic correlation loop."""
        while self._running:
            try:
                await self._correlate()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("Correlator: unhandled error in correlation cycle")

            try:
                await asyncio.sleep(_RUN_INTERVAL_SEC)
            except asyncio.CancelledError:
                return

    # ── Correlation cycle ────────────────────────────────────

    async def _correlate(self) -> None:
        """Run one correlation cycle: fetch, group, analyse, store."""
        alerts = await self._fetch_recent_alerts()
        if not alerts:
            log.debug("Correlator: no recent alerts to correlate")
            return

        log.info("Correlator: analysing %d alerts from last %dm", len(alerts), _WINDOW_MINUTES)

        # Step 1: rule-based grouping
        groups = _group_alerts(alerts)

        # Step 1b: ML anomaly detection (threat engine)
        if self._ml_detector is not None:
            try:
                ml_predictions = self._ml_detector.predict_batch(alerts)
                if ml_predictions:
                    anomaly_alerts = []
                    for pred in ml_predictions:
                        if pred.is_anomaly and pred.alert_id:
                            matching = [a for a in alerts if a.get("id") == pred.alert_id]
                            anomaly_alerts.extend(matching)
                    if anomaly_alerts:
                        groups[f"ml_anomaly:batch:{len(anomaly_alerts)}"] = anomaly_alerts
                        log.info("Correlator: ML detected %d anomalies", len(anomaly_alerts))
                    # Store predictions
                    await self._ml_detector.store_predictions(ml_predictions)
            except Exception:
                log.exception("Correlator: ML detection failed (non-fatal)")

        # Step 1c: Baseline deviation check (threat engine)
        if self._baselines is not None:
            try:
                deviations = self._baselines.check_deviations(alerts)
                for dev in deviations:
                    dev_alerts = [a for a in alerts if a.get("id") in dev.alert_ids]
                    if dev_alerts:
                        groups[f"baseline_deviation:{dev.ip}:{dev.deviation_type}"] = dev_alerts
                if deviations:
                    log.info("Correlator: baseline detected %d deviations", len(deviations))
            except Exception:
                log.exception("Correlator: baseline check failed (non-fatal)")

        if not groups:
            log.debug("Correlator: no candidate groups found")
            return

        log.info("Correlator: found %d candidate groups", len(groups))

        # Step 2: AI pattern identification (if AI is enabled)
        if self._cfg.tier != "none" and self._client is not None:
            correlations = await self._ai_correlate(alerts, groups)
        else:
            correlations = _rule_based_correlations(groups)

        # Step 3: persist (with deduplication - skip if same entities were
        # already correlated recently, regardless of pattern/summary wording)
        alerts_by_id = {a["id"]: a for a in alerts}
        existing = await self._get_recent_correlation_keys()
        for corr in correlations:
            # Dedup key: deterministic entity signature of the underlying
            # alerts (see _entity_signature). Deliberately does NOT include
            # corr.pattern - both pattern and summary are AI-generated free
            # text that gets reworded every cycle even for an unchanged
            # ongoing event, so keying on either (alone or combined with the
            # signature) let one recurring event generate a fresh "duplicate"
            # correlation every ~5min for 50 straight minutes (10 incidents,
            # 2026-07-20), and a second wave even after signature-only dedup
            # for host-local alerts with no IP columns to key on before the
            # alert-ID fallback was added.
            dedup_key = _entity_signature(corr.alert_ids, alerts_by_id)
            if dedup_key in existing:
                log.debug("Correlator: skipping duplicate correlation %s", dedup_key)
                continue
            try:
                corr_id = await self._db.insert_correlation(corr)
                existing.add(dedup_key)
                log.info(
                    "Correlator: stored correlation %s - pattern=%s severity=%s alerts=%d",
                    corr_id, corr.pattern, corr.severity, len(corr.alert_ids),
                )
            except Exception:
                log.exception("Correlator: failed to store correlation")

        # Step 4: Kill chain evaluation (threat engine)
        if self._killchain is not None:
            try:
                for corr in correlations:
                    corr_dict = {
                        "id": corr.id, "pattern": corr.pattern,
                        "summary": corr.summary, "alert_ids": corr.alert_ids,
                    }
                    escalated = self._killchain.evaluate_correlation(corr_dict)
                    if escalated:
                        log.warning(
                            "KILL CHAIN ESCALATED: %s - %d stages hit: %s",
                            escalated.entity, escalated.stage_count,
                            list(escalated.stages_hit.keys()),
                        )
                # Periodic cleanup
                self._killchain.cleanup_stale(hours=48)
            except Exception:
                log.exception("Correlator: kill chain evaluation failed (non-fatal)")

    async def _get_recent_correlation_keys(self) -> set[str]:
        """Get dedup keys for correlations from the last 2 hours to prevent duplicates.

        Keys use the same entity-signature format as the fresh correlations
        computed this cycle (see _entity_signature) so an ongoing event
        actually matches itself across cycles instead of drifting on
        reworded AI pattern/summary text.
        """
        try:
            rows = await self._db.execute_sql(
                """SELECT alert_ids FROM correlations
                   WHERE datetime(created_at) >= datetime('now', '-2 hours')""",
                (),
            )
        except Exception:
            log.exception("Correlator: failed to fetch recent correlation keys")
            return set()

        all_ids: set[str] = set()
        parsed_rows: list[list[str]] = []
        for r in rows:
            try:
                ids = json.loads(r["alert_ids"]) if r["alert_ids"] else []
            except (json.JSONDecodeError, TypeError):
                ids = []
            parsed_rows.append(ids)
            all_ids.update(ids)

        alerts_by_id: dict[str, dict] = {}
        if all_ids:
            try:
                placeholders = ",".join("?" for _ in all_ids)
                alert_rows = await self._db.execute_sql(
                    f"""SELECT id, src_ip, dst_ip, dst_port FROM alerts
                        WHERE id IN ({placeholders})""",
                    tuple(all_ids),
                )
                alerts_by_id = {a["id"]: a for a in alert_rows}
            except Exception:
                log.exception("Correlator: failed to fetch alerts for dedup keys")

        return {_entity_signature(ids, alerts_by_id) for ids in parsed_rows}

    async def _fetch_recent_alerts(self) -> list[dict[str, Any]]:
        """Pull alerts from the last _WINDOW_MINUTES."""
        try:
            rows = await self._db.execute_sql(
                """SELECT id, timestamp, source, severity, title, description,
                          src_ip, src_port, dst_ip, dst_port, proto, category,
                          signature_id, src_geo, dst_geo, src_dns, dst_dns,
                          src_asset, dst_asset, verdict
                   FROM alerts
                   WHERE datetime(timestamp) >= datetime('now', ?)
                     AND (verdict IS NULL OR verdict != 'suppress')
                   ORDER BY timestamp ASC
                   LIMIT 1000""",
                (f"-{_WINDOW_MINUTES} minutes",),
            )
            return rows
        except Exception:
            log.exception("Correlator: failed to fetch recent alerts")
            return []

    # ── AI correlation ───────────────────────────────────────

    async def _ai_correlate(
        self,
        all_alerts: list[dict[str, Any]],
        groups: dict[str, list[dict[str, Any]]],
    ) -> list[Correlation]:
        """Send alert groups to AI for pattern identification."""
        # Flatten to the most interesting alerts (rule-based hits + sample of rest)
        candidate_ids: set[str] = set()
        for group_alerts in groups.values():
            for a in group_alerts:
                candidate_ids.add(a["id"])

        # Include up to 200 candidates
        candidates = [a for a in all_alerts if a["id"] in candidate_ids][:200]
        if not candidates:
            return []

        alerts_json = json.dumps(candidates, indent=2, default=str)
        window_label = f"{_WINDOW_MINUTES} minutes"
        prompt = CORRELATION_TEMPLATE.format(
            count=len(candidates),
            window=window_label,
            alerts_json=alerts_json,
        )

        try:
            raw = await self._dispatch_ai(prompt, CORRELATION_SYSTEM.strip())
        except Exception as exc:
            log.error("Correlator: AI call failed: %s - falling back to rules", exc)
            return _rule_based_correlations(groups)

        return _parse_correlation_response(raw)

    async def _dispatch_ai(self, prompt: str, system: str) -> str:
        """Route to the configured AI backend."""
        cfg = self._cfg
        tier = cfg.tier
        client = self._client
        if client is None:
            raise RuntimeError("AI client not initialised - check tier configuration")

        if tier in ("remote_micro", "remote_standard", "local"):
            return await client.generate(
                prompt=prompt,
                model=cfg.ollama_model,
                system=system,
            )

        if tier == "remote_api":
            if cfg.openai_api_key:
                return await client.generate_openai(
                    prompt=prompt,
                    model=cfg.ollama_model or "gpt-4o-mini",
                    api_key=cfg.openai_api_key,
                    system=system,
                )
            if cfg.anthropic_api_key:
                return await client.generate_anthropic(
                    prompt=prompt,
                    model=cfg.ollama_model or "claude-3-haiku-20240307",
                    api_key=cfg.anthropic_api_key,
                    system=system,
                )
            raise ValueError("remote_api tier requires openai_api_key or anthropic_api_key")

        raise ValueError(f"Unknown AI tier: {tier!r}")


# ---------------------------------------------------------------------------
# Rule-based grouping
# ---------------------------------------------------------------------------

def _group_alerts(alerts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group alerts into correlation candidates using lightweight heuristics.

    Returns:
        Dict of group_key → list of alerts. Each group is a candidate
        for further AI analysis.
    """
    groups: dict[str, list[dict[str, Any]]] = {}

    # ── Port scan: same src_ip, many distinct dst_ports ─────
    by_src_ip: dict[str, list[dict]] = defaultdict(list)
    for a in alerts:
        src = a.get("src_ip") or ""
        if src and src not in _INFRA_IPS:
            by_src_ip[src].append(a)

    for src_ip, src_alerts in by_src_ip.items():
        dst_ports = {a["dst_port"] for a in src_alerts if a.get("dst_port")}
        if len(dst_ports) >= _PORT_SCAN_THRESHOLD:
            key = f"port_scan:{src_ip}"
            groups[key] = src_alerts

    # ── Brute force: repeated auth failures to same target ───
    auth_failures: dict[tuple, list[dict]] = defaultdict(list)
    for a in alerts:
        title_lower = (a.get("title") or "").lower()
        cat = (a.get("category") or "").lower()
        is_auth = (
            "authentication failure" in title_lower
            or "failed login" in title_lower
            or "invalid user" in title_lower
            or "brute" in title_lower
            or "authentication failure" in cat
        )
        if is_auth and a.get("src_ip") and a.get("dst_ip"):
            src, dst = a["src_ip"], a["dst_ip"]
            # Skip infra→infra (paramiko, ansible, etc.)
            if src in _INFRA_IPS and dst in _INFRA_IPS:
                continue
            auth_failures[(src, dst)].append(a)

    for (src, dst), fail_alerts in auth_failures.items():
        if len(fail_alerts) >= _BRUTE_FORCE_THRESHOLD:
            key = f"brute_force:{src}:{dst}"
            groups[key] = fail_alerts

    # ── Lateral movement: internal → internal, only if suspicious ─
    internal_to_internal: dict[str, list[dict]] = defaultdict(list)
    for a in alerts:
        src = a.get("src_ip") or ""
        dst = a.get("dst_ip") or ""
        # Skip all infra↔infra traffic - it's expected
        if src in _INFRA_IPS and dst in _INFRA_IPS:
            continue
        if _is_rfc1918(src) and _is_rfc1918(dst) and src != dst:
            internal_to_internal[src].append(a)

    for src_ip, lat_alerts in internal_to_internal.items():
        # Require significant volume - 10+ alerts from a non-infra internal host
        if len(lat_alerts) >= 10:
            key = f"lateral_movement:{src_ip}"
            groups[key] = lat_alerts

    # ── C2 beaconing: same src → same external dst, multiple times ──
    outbound: dict[tuple, list[dict]] = defaultdict(list)
    for a in alerts:
        src = a.get("src_ip") or ""
        dst = a.get("dst_ip") or ""
        # Skip known infra hosts talking outbound - normal internet use
        if src in _INFRA_IPS:
            continue
        if _is_rfc1918(src) and dst and not _is_rfc1918(dst):
            outbound[(src, dst)].append(a)

    for (src, dst), out_alerts in outbound.items():
        if len(out_alerts) < _BEACON_THRESHOLD:
            continue
        # Real beaconing is REGULAR, not merely frequent. Measure inter-arrival
        # jitter: a C2 heartbeat has low variance; ordinary traffic to a CDN /
        # update server / API is irregular. This gate removes the false positives
        # a raw count alone raises, and still catches the fixed-interval beacon
        # that no known-bad feed would flag (unknown C2).
        epochs = []
        for a in out_alerts:
            ts = a.get("timestamp") or a.get("ingested_at")
            if not ts:
                continue
            try:
                epochs.append(datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp())
            except Exception:
                pass
        epochs.sort()
        deltas = [epochs[i + 1] - epochs[i]
                  for i in range(len(epochs) - 1) if epochs[i + 1] > epochs[i]]
        if len(deltas) < 3:
            continue
        mean = sum(deltas) / len(deltas)
        if mean <= 0:
            continue
        cv = (sum((d - mean) ** 2 for d in deltas) / len(deltas)) ** 0.5 / mean
        if cv <= _BEACON_MAX_CV and 5.0 <= mean <= 21600.0:
            key = f"beacon:{src}:{dst}"
            groups[key] = out_alerts

    return groups


# ---------------------------------------------------------------------------
# Rule-based correlation (AI fallback)
# ---------------------------------------------------------------------------

def _rule_based_correlations(
    groups: dict[str, list[dict[str, Any]]],
) -> list[Correlation]:
    """Build Correlation objects from rule-based groups without AI."""
    correlations: list[Correlation] = []

    pattern_labels = {
        "port_scan": ("port_scan", "high"),
        "brute_force": ("brute_force", "high"),
        "lateral_movement": ("lateral_movement", "critical"),
        "beacon": ("c2_beacon", "critical"),
        "ml_anomaly": ("ml_anomaly", "medium"),
        "baseline_deviation": ("baseline_deviation", "medium"),
    }

    for group_key, group_alerts in groups.items():
        prefix = group_key.split(":")[0]
        pattern, severity = pattern_labels.get(prefix, ("other", "medium"))

        alert_ids = list({a["id"] for a in group_alerts if a.get("id")})
        ips = list({a.get("src_ip", "") for a in group_alerts if a.get("src_ip")})

        summary = _build_rule_summary(pattern, group_key, group_alerts)

        corr = Correlation(
            id=str(uuid.uuid4()),
            alert_ids=alert_ids,
            pattern=pattern,
            summary=summary,
            severity=severity,
            created_at=now_iso(),
        )
        correlations.append(corr)

    return correlations


def _build_rule_summary(
    pattern: str,
    group_key: str,
    alerts: list[dict[str, Any]],
) -> str:
    parts = group_key.split(":", 1)
    detail = parts[1] if len(parts) > 1 else ""

    if pattern == "port_scan":
        ports = sorted({a["dst_port"] for a in alerts if a.get("dst_port")})
        return (
            f"Port scan detected from {detail}: "
            f"{len(ports)} distinct destination ports targeted "
            f"across {len(alerts)} alerts. "
            f"Sample ports: {ports[:10]}."
        )
    if pattern == "brute_force":
        src, _, dst = detail.partition(":")
        return (
            f"Brute-force attack from {src} targeting {dst}: "
            f"{len(alerts)} authentication failure alerts in the window."
        )
    if pattern == "lateral_movement":
        dsts = list({a.get("dst_ip", "") for a in alerts if a.get("dst_ip")})
        return (
            f"Potential lateral movement from internal host {detail}: "
            f"connections to {len(dsts)} internal destination(s)."
        )
    if pattern == "c2_beacon":
        src, _, dst = detail.partition(":")
        return (
            f"Possible C2 beaconing: internal host {src} made "
            f"{len(alerts)} repeated connections to external host {dst}."
        )
    if pattern == "ml_anomaly":
        return (
            f"ML anomaly detection flagged {len(alerts)} statistically unusual alerts "
            f"in the current window."
        )
    if pattern == "baseline_deviation":
        return (
            f"Baseline deviation detected from {detail.split(':')[0] if ':' in detail else detail}: "
            f"{len(alerts)} alerts deviate from established behavioral norms."
        )
    return f"Correlation group '{group_key}': {len(alerts)} related alerts."


# ---------------------------------------------------------------------------
# AI response parsing
# ---------------------------------------------------------------------------

def _parse_correlation_response(raw: str) -> list[Correlation]:
    """Parse AI correlation response into Correlation objects."""
    raw = raw.strip()

    # Strip markdown fences
    if raw.startswith("```"):
        lines = raw.splitlines()
        inner = lines[1:] if len(lines) > 1 else lines
        if inner and inner[-1].strip() == "```":
            inner = inner[:-1]
        raw = "\n".join(inner).strip()

    # Extract first complete JSON array by bracket depth (strips trailing prose)
    start = raw.find("[")
    if start != -1:
        depth = 0
        for i, ch in enumerate(raw[start:], start):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    raw = raw[start : i + 1]
                    break

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        log.warning("Correlator: JSON parse error: %s | raw: %.300s", exc, raw)
        return []

    if not isinstance(parsed, list):
        log.warning("Correlator: expected JSON array, got %s", type(parsed))
        return []

    correlations: list[Correlation] = []
    valid_patterns = frozenset([
        "port_scan", "brute_force", "lateral_movement", "data_exfil",
        "c2_beacon", "recon", "privilege_escalation", "other",
        "ml_anomaly", "baseline_deviation",
    ])
    valid_severities = frozenset(["low", "medium", "high", "critical"])

    for item in parsed:
        if not isinstance(item, dict):
            continue

        pattern = str(item.get("pattern", "other")).strip().lower()
        if pattern not in valid_patterns:
            pattern = "other"

        severity = str(item.get("severity", "medium")).strip().lower()
        if severity not in valid_severities:
            severity = "medium"

        alert_ids = item.get("alert_ids", [])
        if not isinstance(alert_ids, list):
            alert_ids = []
        alert_ids = [str(aid) for aid in alert_ids]

        summary = str(item.get("summary", ""))

        if not alert_ids:
            log.debug("Correlator: skipping AI correlation item with no alert_ids")
            continue

        corr = Correlation(
            id=str(uuid.uuid4()),
            alert_ids=alert_ids,
            pattern=pattern,
            summary=summary,
            severity=severity,
            created_at=now_iso(),
        )
        correlations.append(corr)

    return correlations


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_rfc1918(ip: str) -> bool:
    """Return True if the IP is in RFC-1918 private address space."""
    if not ip:
        return False
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
    except (ValueError, IndexError):
        pass
    return False
