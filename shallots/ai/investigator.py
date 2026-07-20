"""Deep AI investigation module — 'Jesus Take The Wheel' mode."""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.config import AIConfig
    from shallots.store.db import AlertDB

from shallots.ai.ollama_client import OllamaClient
from shallots.ai.prompts import INVESTIGATION_SYSTEM, INVESTIGATION_TEMPLATE
from shallots.store.models import now_iso

log = logging.getLogger(__name__)


@dataclass
class AlertVerdict:
    """AI-recommended verdict for a single alert."""
    alert_id: str
    verdict: str  # suppress | investigate | escalate
    reasoning: str


@dataclass
class InvestigationReport:
    """Full investigation output."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=now_iso)
    since_window: str = "24h"
    alert_count: int = 0
    executive_summary: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    verdicts: list[AlertVerdict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    model: str = ""
    latency_ms: int = 0
    verdicts_applied: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "since_window": self.since_window,
            "alert_count": self.alert_count,
            "executive_summary": self.executive_summary,
            "findings": self.findings,
            "verdicts": [
                {"alert_id": v.alert_id, "verdict": v.verdict, "reasoning": v.reasoning}
                for v in self.verdicts
            ],
            "recommendations": self.recommendations,
            "model": self.model,
            "latency_ms": self.latency_ms,
            "verdicts_applied": self.verdicts_applied,
        }


class DeepInvestigator:
    """Autonomous AI investigator that analyzes all pending/escalated alerts.

    Pipeline:
    1. Fetch matching alerts from DB
    2. Fetch IP reputation data for all unique IPs
    3. Search knowledge base for context
    4. Build consolidated investigation prompt
    5. Send to AI
    6. Parse structured response
    7. Optionally auto-apply verdicts
    8. Store report in investigations table
    """

    def __init__(self, cfg: AIConfig, db: AlertDB) -> None:
        self._cfg = cfg
        self._db = db

    async def investigate(
        self,
        since: str = "24h",
        min_severity: str = "medium",
        auto_verdict: bool = False,
    ) -> InvestigationReport:
        """Run a full investigation.

        Args:
            since: Time window (e.g. "24h", "7d")
            min_severity: Minimum severity to include ("low", "medium", "high", "critical")
            auto_verdict: If True, auto-apply AI verdicts to alerts

        Returns:
            InvestigationReport with narrative, verdicts, and recommendations
        """
        report = InvestigationReport(since_window=since)

        # 1. Fetch alerts
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_sev_val = severity_order.get(min_severity, 1)

        all_alerts = await self._db.get_alerts(limit=500, since=since)
        alerts = [
            a for a in all_alerts
            if severity_order.get(a.get("severity", "medium"), 1) >= min_sev_val
        ]

        if not alerts:
            report.executive_summary = "No alerts matching criteria found."
            report.alert_count = 0
            return report

        report.alert_count = len(alerts)

        # 2. Collect unique IPs and fetch reputation
        ips = set()
        for a in alerts:
            if a.get("src_ip"):
                ips.add(a["src_ip"])
            if a.get("dst_ip"):
                ips.add(a["dst_ip"])

        ip_reputation: dict[str, dict] = {}
        for ip in ips:
            rep = await self._db.get_ip_reputation(ip)
            if rep:
                ip_reputation[ip] = rep

        # 3. Search knowledge base for top alert titles
        kb_context: list[dict] = []
        seen_topics: set[str] = set()
        top_titles = set()
        for a in alerts[:20]:  # Top 20 alerts for KB search
            title = a.get("title", "")
            if title and title not in top_titles:
                top_titles.add(title)
                results = await self._db.search_knowledge(title, limit=2)
                for r in results:
                    topic = r.get("topic", "")
                    if topic not in seen_topics:
                        seen_topics.add(topic)
                        kb_context.append(r)

        # 4. Build investigation prompt
        prompt = self._build_prompt(alerts, ip_reputation, kb_context)

        # 5. Call AI
        if self._cfg.tier == "none":
            report.executive_summary = "AI is disabled. Cannot run deep investigation."
            report.model = "none"
            return report

        t0 = time.monotonic()
        try:
            raw_response = await self._call_ai(prompt)
        except Exception as exc:
            log.error("Investigation AI call failed: %s", exc)
            report.executive_summary = f"AI call failed: {exc}"
            report.model = self._model_name()
            return report

        report.latency_ms = int((time.monotonic() - t0) * 1000)
        report.model = self._model_name()

        # 6. Parse response
        self._parse_response(raw_response, report)

        # 7. Auto-apply verdicts if requested
        if auto_verdict and report.verdicts:
            await self._apply_verdicts(report)
            report.verdicts_applied = True

        # 8. Store in DB
        await self._store_report(report)

        return report

    def _build_prompt(
        self,
        alerts: list[dict],
        ip_reputation: dict[str, dict],
        kb_context: list[dict],
    ) -> str:
        """Build the consolidated investigation prompt."""
        # Group alerts by source IP
        by_src: dict[str, list[dict]] = {}
        for a in alerts:
            src = a.get("src_ip", "unknown")
            by_src.setdefault(src, []).append(a)

        # Build alert summaries
        alert_summaries = []
        for src_ip, group in sorted(by_src.items(), key=lambda x: -len(x[1])):
            lines = [f"\n## Source IP: {src_ip} ({len(group)} alerts)"]
            rep = ip_reputation.get(src_ip, {})
            if rep:
                lines.append(
                    f"  Reputation: VT={rep.get('vt_malicious', 0)} malicious, "
                    f"AbuseIPDB={rep.get('abuse_score', 0)}, "
                    f"Country={rep.get('country', '?')}, ISP={rep.get('isp', '?')}"
                )
            for a in group[:10]:  # Max 10 per IP
                lines.append(
                    f"  - [{a.get('severity', '?')}] {a.get('title', '?')} "
                    f"\u2192 {a.get('dst_ip', '?')}:{a.get('dst_port', '?')} "
                    f"({a.get('timestamp', '?')}) [id={a.get('id', '?')}]"
                )
            if len(group) > 10:
                lines.append(f"  ... and {len(group) - 10} more")
            alert_summaries.append("\n".join(lines))

        # Build IP reputation section
        rep_lines = []
        for ip, rep in ip_reputation.items():
            if rep.get("vt_malicious", 0) > 0 or rep.get("abuse_score", 0) > 50:
                rep_lines.append(
                    f"  {ip}: VT={rep.get('vt_malicious', 0)}/{rep.get('vt_total', 0)} malicious, "
                    f"AbuseIPDB={rep.get('abuse_score', 0)}/100, "
                    f"Country={rep.get('country', '?')}, ISP={rep.get('isp', '?')}"
                )

        # Build knowledge section
        kb_lines = []
        for k in kb_context[:10]:
            kb_lines.append(f"  - [{k.get('category', '')}] {k.get('topic', '')}: {k.get('content', '')[:200]}")

        return INVESTIGATION_TEMPLATE.format(
            alert_count=len(alerts),
            since=alerts[-1].get("timestamp", "?") if alerts else "?",
            until=alerts[0].get("timestamp", "?") if alerts else "?",
            alert_summaries="\n".join(alert_summaries),
            ip_reputation="\n".join(rep_lines) if rep_lines else "  No flagged IPs",
            knowledge_context="\n".join(kb_lines) if kb_lines else "  No relevant knowledge base entries",
            alert_ids_json=json.dumps([a.get("id", "") for a in alerts]),
        )

    def _parse_response(self, raw: str, report: InvestigationReport) -> None:
        """Parse the AI response into the report structure."""
        raw = raw.strip()

        # Strip markdown fences
        if raw.startswith("```"):
            lines = raw.splitlines()
            inner = lines[1:] if len(lines) > 1 else lines
            if inner and inner[-1].strip() == "```":
                inner = inner[:-1]
            raw = "\n".join(inner).strip()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("Investigation response JSON parse failed: %.500s", raw)
            report.executive_summary = raw[:2000]  # Use raw text as summary
            return

        if not isinstance(data, dict):
            report.executive_summary = str(data)[:2000]
            return

        report.executive_summary = data.get("executive_summary", "")

        findings = data.get("findings", [])
        if isinstance(findings, list):
            report.findings = [f for f in findings if isinstance(f, dict)]

        verdicts_raw = data.get("verdicts", [])
        if isinstance(verdicts_raw, list):
            valid = {"suppress", "investigate", "escalate"}
            for v in verdicts_raw:
                if not isinstance(v, dict):
                    continue
                verdict_val = v.get("verdict", "")
                if verdict_val in valid:
                    report.verdicts.append(AlertVerdict(
                        alert_id=str(v.get("alert_id", "")),
                        verdict=verdict_val,
                        reasoning=str(v.get("reasoning", "")),
                    ))

        recommendations = data.get("recommendations", [])
        if isinstance(recommendations, list):
            report.recommendations = [str(r) for r in recommendations]

    async def _apply_verdicts(self, report: InvestigationReport) -> None:
        """Apply AI verdicts to alerts in the database."""
        applied = 0
        for v in report.verdicts:
            try:
                await self._db.update_verdict(
                    alert_id=v.alert_id,
                    verdict=v.verdict,
                    confidence=0.8,
                    reasoning=f"[JTTW] {v.reasoning}",
                )
                applied += 1
            except Exception:
                log.warning("Failed to apply verdict for alert %s", v.alert_id)
        log.info("JTTW: applied %d/%d verdicts", applied, len(report.verdicts))

    async def _store_report(self, report: InvestigationReport) -> None:
        """Store investigation report in the database."""
        try:
            await self._db.insert_investigation(report)
        except Exception:
            log.exception("Failed to store investigation report %s", report.id)

    async def _call_ai(self, prompt: str) -> str:
        """Route the AI call based on tier config."""
        cfg = self._cfg
        system = INVESTIGATION_SYSTEM.strip()

        import aiohttp
        client = OllamaClient(
            base_url=cfg.ollama_url or "http://localhost:11434",
            timeout=aiohttp.ClientTimeout(total=300, connect=10),
        )

        try:
            if cfg.tier in ("remote_micro", "remote_standard", "local"):
                return await client.generate(prompt=prompt, model=cfg.ollama_model, system=system)
            if cfg.tier == "remote_api":
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
                        max_tokens=8192,
                    )
                raise ValueError("remote_api tier requires openai_api_key or anthropic_api_key")
            raise ValueError(f"Unknown AI tier: {cfg.tier!r}")
        finally:
            await client.close()

    def _model_name(self) -> str:
        cfg = self._cfg
        if cfg.ollama_model:
            return cfg.ollama_model
        if cfg.openai_api_key:
            return "openai"
        if cfg.anthropic_api_key:
            return "anthropic"
        return cfg.tier
