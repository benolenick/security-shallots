"""Incident generator — promotes correlations and escalated clusters to actionable incidents."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.config import AIConfig
    from shallots.store.db import AlertDB

from shallots.ai.ollama_client import OllamaClient
from shallots.ai.prompts import INCIDENT_SYSTEM, INCIDENT_TEMPLATE
from shallots.store.models import now_iso

log = logging.getLogger(__name__)

_RUN_INTERVAL_SEC = 120  # check every 2 minutes
_MIN_CLUSTER_ALERTS = 3  # minimum alerts in an escalated cluster to create incident
_MAX_INCIDENTS_PER_CYCLE = 5  # flood guard: cap new incidents created per source per cycle
_ESCALATE_LOOKBACK_HOURS = 72  # window for deterministic (Sigma/IoC) escalations; wide
# because these are rare + high-value and must survive a daemon restart a day later


class IncidentWorker:
    """Background task that creates incidents from correlations and escalated clusters.

    Sources:
    1. New correlations (port scan, brute force, lateral movement, etc.)
    2. Escalated clusters with enough alerts
    3. Squawks (critical threats flagged by autopilot)

    Each source is deduplicated against existing open incidents.
    """

    def __init__(self, cfg: AIConfig, db: AlertDB,
                 ws_broadcast=None, alerter=None) -> None:
        self._cfg = cfg
        self._db = db
        self._ws_broadcast = ws_broadcast
        self._alerter = alerter
        self._client: OllamaClient | None = None

    async def run(self, shutdown: asyncio.Event) -> None:
        """Main loop."""
        if self._cfg.tier != "none":
            self._client = OllamaClient(
                base_url=self._cfg.ollama_url or "http://localhost:11434",
            )

        log.info("Incident worker started (interval=%ds)", _RUN_INTERVAL_SEC)

        while not shutdown.is_set():
            try:
                await self._scan()
            except asyncio.CancelledError:
                break
            except Exception:
                log.exception("Incident worker: error in scan cycle")

            try:
                await asyncio.sleep(_RUN_INTERVAL_SEC)
            except asyncio.CancelledError:
                break

        if self._client:
            await self._client.close()
        log.info("Incident worker stopped")

    async def _scan(self) -> None:
        """One scan cycle: find new things to promote to incidents."""
        existing_keys = await self._db.get_existing_incident_keys()

        # Source 0: Deterministic escalations (Sigma / IoC / custom-rule set an
        # alert's verdict to 'escalate'). This is the local, high-precision path
        # that works with the cloud elder ladder disabled. Runs first so its cap
        # is reserved for the most trustworthy signal.
        await self._scan_deterministic_escalations(existing_keys)

        # Source 1: Correlations
        await self._scan_correlations(existing_keys)

        # Source 2: Escalated clusters (verdict promoted to 'escalate' at the
        # cluster level — e.g. by the ladder when enabled)
        await self._scan_escalated_clusters(existing_keys)

    async def _scan_deterministic_escalations(self, existing_keys: set[str]) -> None:
        """Promote clusters that contain a deterministically-escalated alert.

        Sigma rules, IoC feed matches, and custom rules set an alert's
        verdict='escalate' independently of the cloud elder ladder. Those
        alert-level escalations previously never propagated to an incident
        (clusters stay verdict='pending' with the ladder off), so the
        escalated-cluster path was starved. This bridges that gap using only
        local/deterministic signals — high precision, so a low minimum is safe.
        """
        try:
            cursor = await self._db.execute_sql(
                """SELECT cluster_id,
                          COUNT(*) AS c,
                          MAX(COALESCE(ingested_at, timestamp)) AS last_seen
                   FROM alerts
                   WHERE verdict = 'escalate'
                     AND cluster_id IS NOT NULL AND cluster_id <> ''
                     AND COALESCE(ingested_at, timestamp) > datetime('now', ?)
                   GROUP BY cluster_id
                   ORDER BY last_seen DESC
                   LIMIT 50""",
                (f"-{_ESCALATE_LOOKBACK_HOURS} hours",),
            )
        except Exception:
            return

        rows = list(cursor)
        if rows:
            log.info("Incident worker: %d deterministic-escalation candidate cluster(s)", len(rows))
        created = 0
        for row in rows:
            if created >= _MAX_INCIDENTS_PER_CYCLE:
                log.info("Incident worker: per-cycle cap (%d) reached for deterministic escalations",
                         _MAX_INCIDENTS_PER_CYCLE)
                break

            cluster_id = row["cluster_id"]
            if f"cluster:{cluster_id}" in existing_keys:
                continue
            # Escalated alerts keep verdict='escalate' permanently, so dedup against
            # ALL incidents (including resolved) here — otherwise resolving this
            # incident would let the next scan re-promote the same cluster forever.
            if await self._cluster_has_any_incident(cluster_id):
                continue

            alerts = await self._db.get_cluster_alerts(cluster_id, limit=10)
            if not alerts:
                continue

            ips = set()
            for a in alerts:
                if a.get("src_ip"):
                    ips.add(a["src_ip"])
                if a.get("dst_ip"):
                    ips.add(a["dst_ip"])
            ip_context = await self._build_ip_context(ips)

            # Label the incident by the escalated member's title where possible.
            esc_titles = [a.get("title") for a in alerts
                          if a.get("verdict") == "escalate" and a.get("title")]
            pattern = esc_titles[0] if esc_titles else (alerts[0].get("title") or "deterministic escalation")

            incident = await self._generate_incident(
                source="deterministic_escalation",
                pattern=pattern,
                alert_count=int(row["c"]),
                alerts=alerts,
                ip_context=ip_context,
            )
            if not incident:
                log.warning("deterministic escalation: generation returned None for cluster %s "
                            "— falling back to rule-based", cluster_id)
                incident = self._rule_based_incident(
                    "deterministic_escalation", pattern, int(row["c"]), alerts)

            incident["cluster_ids"] = [cluster_id]
            incident["alert_ids"] = [a["id"] for a in alerts if a.get("id")]
            incident["alert_count"] = int(row["c"])
            incident["affected_ips"] = list(ips)
            # A deterministic escalation is high-precision; don't let it land as low.
            if incident.get("severity") in (None, "", "low", "medium"):
                incident["severity"] = "high"

            iid = await self._db.insert_incident(incident)
            existing_keys.add(f"cluster:{cluster_id}")
            created += 1
            log.info("Incident created from deterministic escalation (cluster %s): %s",
                     cluster_id, incident["title"])
            try:
                await self._db.add_incident_event(
                    iid, "created",
                    f"Incident created from deterministic escalation: {pattern}",
                    f"{int(row['c'])} escalated alert(s)", "system",
                )
                await self._db.insert_audit(
                    "create_incident", "incident", iid, incident["title"])
            except Exception:
                pass
            await self._broadcast_incident(iid, incident)

    async def _cluster_has_any_incident(self, cluster_id: str) -> bool:
        """True if any incident (any status) is already linked to this cluster."""
        try:
            rows = await self._db.execute_sql(
                'SELECT 1 FROM incidents WHERE cluster_ids LIKE ? LIMIT 1',
                (f'%"{cluster_id}"%',),
            )
            return bool(rows)
        except Exception:
            return False

    async def _scan_correlations(self, existing_keys: set[str]) -> None:
        """Create incidents from correlations that don't have one yet."""
        try:
            cursor = await self._db.execute_sql(
                "SELECT * FROM correlations ORDER BY created_at DESC LIMIT 50", ()
            )
        except Exception:
            return

        for row in cursor:
            corr_id = row["id"]
            if f"corr:{corr_id}" in existing_keys:
                continue

            try:
                alert_ids = json.loads(row["alert_ids"]) if row["alert_ids"] else []
            except (json.JSONDecodeError, TypeError):
                alert_ids = []

            if not alert_ids:
                continue

            # Fetch sample alerts for AI context
            sample_alerts = await self._fetch_alerts(alert_ids[:10])
            if not sample_alerts:
                continue

            # Build IP context
            ips = set()
            for a in sample_alerts:
                if a.get("src_ip"):
                    ips.add(a["src_ip"])
                if a.get("dst_ip"):
                    ips.add(a["dst_ip"])
            ip_context = await self._build_ip_context(ips)

            incident = await self._generate_incident(
                source=f"correlation:{row['pattern']}",
                pattern=row["pattern"],
                alert_count=len(alert_ids),
                alerts=sample_alerts,
                ip_context=ip_context,
            )

            # Check if similar incidents were repeatedly dismissed
            if incident:
                pattern_key = f"correlation:{row['pattern']}"
                try:
                    candidates = await self._db.get_auto_dismiss_candidates()
                    auto_keys = {c["pattern_key"] for c in candidates}
                    if pattern_key in auto_keys:
                        incident["urgency"] = "noise"
                        incident["summary"] = f"[Auto-flagged as likely noise — you've dismissed similar incidents before] {incident.get('summary', '')}"
                except Exception:
                    pass

            if incident:
                incident["correlation_id"] = corr_id
                incident["alert_ids"] = alert_ids
                incident["alert_count"] = len(alert_ids)
                incident["affected_ips"] = list(ips)
                iid = await self._db.insert_incident(incident)
                log.info("Incident created from correlation %s: %s", corr_id, incident["title"])
                # Track timeline event
                try:
                    await self._db.add_incident_event(
                        iid, "created",
                        f"Incident created from correlation: {row['pattern']}",
                        f"{len(alert_ids)} alerts", "system",
                    )
                    await self._db.insert_audit(
                        "create_incident", "incident", iid, incident["title"])
                except Exception:
                    pass
                await self._broadcast_incident(iid, incident)

    async def _scan_escalated_clusters(self, existing_keys: set[str]) -> None:
        """Create incidents from escalated clusters."""
        try:
            cursor = await self._db.execute_sql(
                """SELECT * FROM clusters
                   WHERE verdict = 'escalate' AND alert_count >= ?
                   ORDER BY last_seen DESC LIMIT 50""",
                (_MIN_CLUSTER_ALERTS,),
            )
        except Exception:
            return

        for row in cursor:
            cluster_id = row["id"]
            if f"cluster:{cluster_id}" in existing_keys:
                continue

            # Fetch sample alerts
            alerts = await self._db.get_cluster_alerts(cluster_id, limit=10)
            if not alerts:
                continue

            ips = set()
            for a in alerts:
                if a.get("src_ip"):
                    ips.add(a["src_ip"])
                if a.get("dst_ip"):
                    ips.add(a["dst_ip"])
            ip_context = await self._build_ip_context(ips)

            incident = await self._generate_incident(
                source="escalated_cluster",
                pattern=row.get("title", "unknown"),
                alert_count=row["alert_count"],
                alerts=alerts,
                ip_context=ip_context,
            )

            # Check if similar incidents were repeatedly dismissed
            if incident:
                pattern_key = f"escalated_cluster:{row.get('title', 'unknown')}"
                try:
                    candidates = await self._db.get_auto_dismiss_candidates()
                    auto_keys = {c["pattern_key"] for c in candidates}
                    if pattern_key in auto_keys:
                        incident["urgency"] = "noise"
                        incident["summary"] = f"[Auto-flagged as likely noise — you've dismissed similar incidents before] {incident.get('summary', '')}"
                except Exception:
                    pass

            if incident:
                incident["cluster_ids"] = [cluster_id]
                incident["alert_ids"] = [a["id"] for a in alerts if a.get("id")]
                incident["alert_count"] = row["alert_count"]
                incident["affected_ips"] = list(ips)
                iid = await self._db.insert_incident(incident)
                log.info("Incident created from escalated cluster %s: %s",
                         cluster_id, incident["title"])
                try:
                    await self._db.add_incident_event(
                        iid, "created",
                        f"Incident created from escalated cluster: {row.get('title', 'unknown')}",
                        f"{row['alert_count']} alerts", "system",
                    )
                    await self._db.insert_audit(
                        "create_incident", "incident", iid, incident["title"])
                except Exception:
                    pass
                await self._broadcast_incident(iid, incident)

    async def _generate_incident(self, source: str, pattern: str,
                                  alert_count: int, alerts: list[dict],
                                  ip_context: str) -> dict | None:
        """Use AI to generate an incident report, or fall back to rule-based."""
        # Prepare alert summaries. Keep only decision-relevant fields and cap the
        # count — a large prompt overflows the model context and truncates the
        # JSON response mid-object (the #1 cause of parse failures on the local
        # Granite model), forcing a fallback that discards the AI narrative.
        _KEEP = ("id", "source", "severity", "title", "description",
                 "src_ip", "dst_ip", "category", "verdict", "timestamp", "ai_reasoning")
        trimmed = []
        for a in alerts[:5]:
            t = {k: a.get(k) for k in _KEEP if a.get(k) not in (None, "")}
            # bound any long free-text field so one verbose alert can't blow the budget
            for f in ("description", "ai_reasoning"):
                if isinstance(t.get(f), str) and len(t[f]) > 300:
                    t[f] = t[f][:300] + "…"
            trimmed.append(t)

        alerts_json = json.dumps(trimmed, indent=2, default=str)

        # Check learning history for this pattern
        learning_context = ""
        pattern_key = f"{source}:{pattern}"
        try:
            history = await self._db.get_pattern_history(pattern_key)
            if history:
                parts = [f"{h['decision']}: {h['count']} times" for h in history]
                learning_context = f"Previous decisions for similar incidents: {', '.join(parts)}"
        except Exception:
            pass

        if self._client and self._cfg.tier != "none":
            try:
                prompt = INCIDENT_TEMPLATE.format(
                    source=source,
                    pattern=pattern,
                    alert_count=alert_count,
                    alerts_json=alerts_json,
                    ip_context=ip_context or "No IP reputation data available.",
                    learning_context=learning_context,
                )
                # format="json" grammar-constrains the local model to emit a single
                # complete JSON object — far more reliable than free-form + regex,
                # which truncated mid-object under the model's context window.
                parsed = await self._client.generate_json(
                    prompt=prompt,
                    model=self._cfg.ollama_model,
                    system=INCIDENT_SYSTEM.strip(),
                )
                incident = self._incident_from_parsed(parsed, alerts)
                if incident:
                    return incident
                log.warning("Incident: AI JSON missing required fields — using fallback")
            except Exception as exc:
                log.warning("Incident AI generation failed: %s — using fallback", exc)

        # Fallback: rule-based incident
        return self._rule_based_incident(source, pattern, alert_count, alerts)

    def _incident_from_parsed(self, parsed: Any, alerts: list[dict]) -> dict | None:
        """Validate/normalize a model-produced JSON dict into an incident.

        Returns None when the object is empty or lacks the essentials (title AND
        summary), so the caller falls back to the rule-based incident.
        """
        if not isinstance(parsed, dict) or not parsed:
            return None
        if not (parsed.get("title") or parsed.get("summary")):
            return None

        valid_sevs = {"low", "medium", "high", "critical"}
        sev = parsed.get("severity", "medium")
        if sev not in valid_sevs:
            sev = "medium"

        valid_urgency = {"noise", "check", "act_now"}
        urgency = parsed.get("urgency", "check")
        if urgency not in valid_urgency:
            urgency = "check"

        runbook = parsed.get("runbook", [])
        if not isinstance(runbook, list):
            runbook = [{"description": str(runbook)}]
        # Normalize: accept both string steps and dict steps
        normalized_runbook = []
        for step in runbook:
            if isinstance(step, str):
                normalized_runbook.append({"description": step})
            elif isinstance(step, dict):
                normalized_runbook.append(step)
        runbook = normalized_runbook

        return {
            "id": str(uuid.uuid4()),
            "title": str(parsed.get("title", "Untitled Incident")),
            "summary": str(parsed.get("summary", "")),
            "severity": sev,
            "urgency": urgency,
            "category": str(parsed.get("category", "other")),
            "runbook": runbook,
            "ai_analysis": json.dumps(parsed)[:4000],
            "status": "new",
            "created_at": now_iso(),
        }

    def _rule_based_incident(self, source: str, pattern: str,
                              alert_count: int, alerts: list[dict]) -> dict:
        """Generate a basic incident without AI."""
        # Collect IPs
        src_ips = set()
        dst_ips = set()
        for a in alerts:
            if a.get("src_ip"):
                src_ips.add(a["src_ip"])
            if a.get("dst_ip"):
                dst_ips.add(a["dst_ip"])

        title_map = {
            "port_scan": f"Port Scan from {next(iter(src_ips), 'unknown')}",
            "brute_force": f"Brute Force Attack ({alert_count} attempts)",
            "lateral_movement": f"Lateral Movement Detected from {next(iter(src_ips), 'unknown')}",
            "c2_beacon": f"Possible C2 Beaconing to {next(iter(dst_ips), 'unknown')}",
            "data_exfil": f"Possible Data Exfiltration to {next(iter(dst_ips), 'unknown')}",
        }

        summary_map = {
            "port_scan": f"{next(iter(src_ips), 'An IP')} scanned multiple ports on your network. This could be reconnaissance before an attack.",
            "brute_force": f"{alert_count} failed login attempts detected. Someone may be trying to guess passwords.",
            "lateral_movement": f"An internal machine is connecting to other internal machines in unusual ways. This could indicate a compromised device.",
            "c2_beacon": f"A device on your network is making repeated connections to an external server. This pattern is common in malware.",
            "data_exfil": f"Unusual outbound data transfer detected. A device may be sending data to an external server.",
        }

        sev_map = {
            "port_scan": "high",
            "brute_force": "high",
            "lateral_movement": "critical",
            "c2_beacon": "critical",
            "data_exfil": "critical",
        }

        urgency_map = {
            "port_scan": "check",
            "brute_force": "act_now",
            "lateral_movement": "act_now",
            "c2_beacon": "act_now",
            "data_exfil": "act_now",
        }

        title = title_map.get(pattern, f"Security Incident: {pattern} ({alert_count} alerts)")
        summary = summary_map.get(pattern, f"{alert_count} related security alerts detected matching pattern '{pattern}'.")
        severity = sev_map.get(pattern, "medium")

        # Basic runbook
        src_ip = next(iter(src_ips), "unknown")
        runbook = [
            {"description": f"Check if {src_ip} is a device you recognize on your network",
             "command": f"nslookup {src_ip}" if src_ip != "unknown" else None,
             "expect": "A hostname you recognize (e.g. your-laptop, printer, etc.)",
             "bad_sign": "Unknown hostname or no result",
             "decision": "If you recognize it, this may be normal activity"},
            {"description": f"Review the {alert_count} alerts in this incident for details",
             "command": None,
             "expect": "Familiar services and ports",
             "bad_sign": "Connections to unusual ports or unknown services",
             "decision": "Look for patterns — same port, same time of day, etc."},
            {"description": "If the source is external and unexpected, block it",
             "command": f"sudo ufw deny from {src_ip}" if src_ip != "unknown" else None,
             "expect": "Rule added",
             "bad_sign": None,
             "decision": "Block and monitor for 24 hours"},
        ]

        return {
            "id": str(uuid.uuid4()),
            "title": title,
            "summary": summary,
            "severity": severity,
            "urgency": urgency_map.get(pattern, "check"),
            "category": pattern or "other",
            "runbook": runbook,
            "ai_analysis": "",
            "status": "new",
            "created_at": now_iso(),
        }

    async def _fetch_alerts(self, alert_ids: list[str]) -> list[dict]:
        """Fetch alerts by IDs."""
        if not alert_ids:
            return []
        placeholders = ",".join("?" for _ in alert_ids)
        try:
            cursor = await self._db.execute_sql(
                f"SELECT * FROM alerts WHERE id IN ({placeholders}) LIMIT 20",
                alert_ids,
            )
            return cursor
        except Exception:
            return []

    async def _build_ip_context(self, ips: set[str]) -> str:
        """Build IP reputation context string."""
        parts = []
        for ip in list(ips)[:5]:
            try:
                rep = await self._db.get_ip_reputation(ip)
                if rep:
                    parts.append(f"- {ip}: verdict={rep.get('verdict','unknown')}, "
                                f"vt_detections={rep.get('vt_positives',0)}, "
                                f"abuse_score={rep.get('abuse_score',0)}")
            except Exception:
                pass
        if parts:
            return "IP Reputation:\n" + "\n".join(parts)
        return ""

    async def _broadcast_incident(self, iid: str, incident: dict) -> None:
        """Push new incident to WebSocket clients and fire out-of-band notifications."""
        if self._ws_broadcast:
            try:
                await self._ws_broadcast({
                    "type": "incident",
                    "data": {
                        "id": iid,
                        "title": incident.get("title", ""),
                        "severity": incident.get("severity", "medium"),
                        "status": "new",
                        "category": incident.get("category", ""),
                        "alert_count": incident.get("alert_count", 0),
                    },
                })
            except Exception:
                pass

        if self._alerter and incident.get("urgency") == "act_now":
            try:
                await self._alerter.notify_incident({**incident, "id": iid})
            except Exception:
                log.warning("act_now notification failed for incident %s", iid, exc_info=True)
