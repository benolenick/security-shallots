"""Batched AI triage worker for Security Shallots."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.config import AIConfig
    from shallots.store.db import AlertDB

from shallots.ai.obfuscate import Obfuscator
from shallots.ai.ollama_client import OllamaClient
from shallots.ai.prompts import TRIAGE_BATCH, TRIAGE_BATCH_WITH_CONTEXT, TRIAGE_SYSTEM
from shallots.store.models import TriageResult, TriageVerdict, now_iso

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rule-based fallback
# ---------------------------------------------------------------------------

_RULE_ESCALATE_KEYWORDS = frozenset([
    "exploit", "shellcode", "ransomware", "trojan", "c2", "command and control",
    "reverse shell", "mimikatz", "meterpreter", "cobalt strike", "lateral movement",
    "exfiltration", "privilege escalation",
])

_RULE_SUPPRESS_CATEGORIES = frozenset([
    "ET INFO", "Not Suspicious", "Misc activity", "Potential Corporate Privacy Violation",
])

# Mirrors config suppression.title_patterns - applied even when AI is down
_RULE_SUPPRESS_TITLE_FRAGMENTS = (
    "root session opened",
    "cron/timer configuration changed",
    "package changes detected",
    "ssh login:",
    "ssh brute force from 192.168.0",
    "internal ssh",
    "ufw blocked",
    "suricata stream",
    "protocol anomaly",
    "user account modified",
    "internal port scan detected",
    "curl user-agent to dotted quad",
    "external ip lookup domain",
    "llmnr query",
    "registry persistence keys changed",
    "heartbeat overdue",
    "agent offline:",
    "firewall not active",
    "required systemd unit missing",
    "vulnerable openssh version",
    "pam: login session",
    "sshd: authentication",
    "sudo authentication failure",
)


def _rule_based_verdict(alert: dict[str, Any]) -> tuple[str, float, str]:
    """Apply simple rule-based triage when AI is unavailable."""
    title_lower = (alert.get("title") or "").lower()
    category = alert.get("category") or ""
    severity = alert.get("severity") or "medium"
    src_ip = alert.get("src_ip") or ""

    # Suppress known-benign title patterns (mirrors config suppression list)
    for fragment in _RULE_SUPPRESS_TITLE_FRAGMENTS:
        if fragment in title_lower:
            return (
                TriageVerdict.SUPPRESS,
                0.9,
                f"Rule-based: known-benign pattern '{fragment}'.",
            )

    # Suppress low/medium severity from internal LAN - internal noise
    if src_ip.startswith(("192.168.0.", "192.168.2.")) and severity in ("low", "medium"):
        return (
            TriageVerdict.SUPPRESS,
            0.8,
            "Rule-based: internal LAN source, low/medium severity.",
        )

    # Check escalate keywords in title
    for kw in _RULE_ESCALATE_KEYWORDS:
        if kw in title_lower:
            return (
                TriageVerdict.ESCALATE,
                0.7,
                f"Rule-based: title contains high-risk keyword '{kw}'.",
            )

    # Check suppress categories
    for cat in _RULE_SUPPRESS_CATEGORIES:
        if category.startswith(cat):
            return (
                TriageVerdict.SUPPRESS,
                0.8,
                f"Rule-based: category '{category}' is low-signal noise.",
            )

    # Severity-based defaults
    if severity == "critical":
        return (TriageVerdict.ESCALATE, 0.6, "Rule-based: critical severity alert.")
    if severity == "high":
        return (TriageVerdict.INVESTIGATE, 0.6, "Rule-based: high severity alert.")
    if severity == "low":
        return (TriageVerdict.SUPPRESS, 0.5, "Rule-based: low severity, no other indicators.")

    return (TriageVerdict.INVESTIGATE, 0.5, "Rule-based: medium severity, needs review.")


# ---------------------------------------------------------------------------
# RAG context lookup
# ---------------------------------------------------------------------------

async def _rag_context(db: "AlertDB", alerts: list[dict[str, Any]]) -> str:
    """Query the knowledge table for facts relevant to this batch of alerts.

    Searches by unique IPs, hostnames, and alert title keywords. Returns a
    formatted context block to inject into the triage prompt, or empty string
    if nothing relevant is found.
    """
    # Collect search terms from the batch
    terms: set[str] = set()
    for a in alerts:
        for field in ("src_ip", "dst_ip", "src_dns", "dst_dns"):
            val = a.get(field)
            if val and val not in ("", "0.0.0.0"):
                terms.add(val)
        # Add first two words of title as keywords
        title = (a.get("title") or "").strip()
        if title:
            words = title.split()[:3]
            terms.add(" ".join(words))

    if not terms:
        return ""

    seen_ids: set[int] = set()
    facts: list[str] = []

    try:
        for term in terms:
            cursor = await db._db.execute(
                "SELECT id, category, topic, content FROM knowledge WHERE content LIKE ? OR topic LIKE ? LIMIT 4",
                (f"%{term}%", f"%{term}%"),
            )
            rows = await cursor.fetchall()
            for row in rows:
                if row[0] not in seen_ids:
                    seen_ids.add(row[0])
                    facts.append(f"[{row[1]}] {row[2]}: {row[3]}")
    except Exception:
        return ""

    if not facts:
        return ""

    return "\n".join(facts[:12])  # cap at 12 facts to keep prompt size sane


# ---------------------------------------------------------------------------
# AI response parsing
# ---------------------------------------------------------------------------

def _parse_batch_response(
    raw: str,
    alerts: list[dict[str, Any]],
) -> list[dict[str, Any] | None]:
    """Parse the AI batch triage JSON response.

    The model should return a JSON array of triage objects indexed by position.
    Returns a list parallel to `alerts`; entries are None on parse failure.
    """
    raw = raw.strip()

    # Strip markdown fences if present
    if raw.startswith("```"):
        lines = raw.splitlines()
        inner = lines[1:] if len(lines) > 1 else lines
        if inner and inner[-1].strip() == "```":
            inner = inner[:-1]
        raw = "\n".join(inner).strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        log.warning("Batch triage JSON parse error: %s | raw: %.300s", exc, raw)
        return [None] * len(alerts)

    if not isinstance(parsed, list):
        log.warning("Batch triage: expected JSON array, got %s", type(parsed))
        return [None] * len(alerts)

    # Build index map from response (each item should have an "index" field)
    indexed: dict[int, dict] = {}
    for item in parsed:
        if not isinstance(item, dict):
            continue
        idx = item.get("index")
        if isinstance(idx, int) and 0 <= idx < len(alerts):
            indexed[idx] = item

    results: list[dict[str, Any] | None] = []
    for i in range(len(alerts)):
        results.append(indexed.get(i))

    return results


def _safe_confidence(value, default: float = 0.5) -> float:
    """Coerce model-supplied confidence to [0,1]; never raise (one bad item used
    to ValueError and abort storing the rest of the batch -> perpetual re-triage)."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    if f > 1.0:  # some models answer 95 meaning 0.95
        f = f / 100.0 if f <= 100.0 else 1.0
    return min(max(f, 0.0), 1.0)


def _build_triage_result(
    alert_id: str,
    item: dict[str, Any],
    model: str,
    latency_ms: int,
) -> TriageResult:
    """Build a TriageResult from a parsed AI response item."""
    # Local models emit "Escalate"/"SUPPRESS"/etc. - normalize before validating,
    # else a real escalate silently becomes investigate and never notifies.
    verdict_raw = str(item.get("verdict", "investigate")).strip().lower()
    valid_verdicts = {v.value for v in TriageVerdict}
    verdict = verdict_raw if verdict_raw in valid_verdicts else TriageVerdict.INVESTIGATE

    iocs = item.get("iocs", [])
    if not isinstance(iocs, list):
        iocs = []

    return TriageResult(
        alert_id=alert_id,
        verdict=verdict,
        confidence=_safe_confidence(item.get("confidence")),
        reasoning=str(item.get("reasoning", "")),
        iocs=[str(ioc) for ioc in iocs],
        suggested_action=str(item.get("suggested_action", "")),
        model=model,
        latency_ms=latency_ms,
        created_at=now_iso(),
    )


# ---------------------------------------------------------------------------
# TriageWorker
# ---------------------------------------------------------------------------

class TriageWorker:
    """Async background task that pulls pending alerts and triages them via AI.

    Supports all AI tiers from AIConfig:
    - none            - rule-based fallback only (AI disabled)
    - remote_micro    - Ollama at ollama_url with a small/fast model
    - remote_standard - Ollama at ollama_url with a full model
    - remote_api      - OpenAI (openai_api_key set) or Anthropic (anthropic_api_key set)
    - local           - Ollama at localhost:11434

    On AI failure, alerts are marked pending and retried on the next cycle.
    """

    def __init__(self, cfg: AIConfig, db: AlertDB) -> None:
        self._cfg = cfg
        self._db = db
        self._client: OllamaClient | None = None
        self._running = False
        self._task: asyncio.Task | None = None

        # Stats
        self.total_triaged: int = 0
        self.total_errors: int = 0
        self.total_latency_ms: int = 0

        # Circuit breaker: pause AI triage if consecutive failures exceed threshold
        self._cb_failures: int = 0
        self._cb_tripped: bool = False
        self._cb_tripped_at: float = 0.0
        _CB_THRESHOLD = 5      # trip after N consecutive AI failures
        _CB_COOLDOWN_SEC = 300 # reopen after 5 minutes
        self._CB_THRESHOLD = _CB_THRESHOLD
        self._CB_COOLDOWN_SEC = _CB_COOLDOWN_SEC

    # ── Lifecycle ────────────────────────────────────────────

    async def run(self, shutdown: asyncio.Event) -> None:
        """Run the triage worker until shutdown event is set.

        Called by the daemon as an asyncio task.
        """
        self._running = True
        log.info(
            "TriageWorker started (tier=%s, batch=%d, interval=%ds)",
            self._cfg.tier,
            self._cfg.batch_size,
            self._cfg.batch_interval_sec,
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
                    log.exception("TriageWorker: unhandled error in batch cycle")

                try:
                    await asyncio.sleep(self._cfg.batch_interval_sec)
                except asyncio.CancelledError:
                    return
        finally:
            self._running = False
            if self._client:
                await self._client.close()
                self._client = None
            log.info("TriageWorker stopped")

    # ── Batch processing ─────────────────────────────────────

    _BACKLOG_THRESHOLD = 5000  # skip AI if more than this many pending

    async def _process_batch(self) -> None:
        """Fetch a batch of pending alerts and triage them."""
        alerts = await self._db.get_pending_alerts(limit=self._cfg.batch_size)
        if not alerts:
            log.debug("TriageWorker: no pending alerts")
            return

        # Backpressure: if backlog is huge, use rule-based only to drain it
        if self._cfg.tier != "none":
            cursor = await self._db._db.execute(
                "SELECT COUNT(*) FROM alerts WHERE verdict = 'pending'"
            )
            row = await cursor.fetchone()
            pending_count = row[0] if row else 0
            if pending_count > self._BACKLOG_THRESHOLD:
                log.warning(
                    "TriageWorker: backlog=%d exceeds threshold=%d, using rule-based triage",
                    pending_count, self._BACKLOG_THRESHOLD,
                )
                await self._triage_rule_based(alerts)
                return

        log.info("TriageWorker: triaging batch of %d alerts", len(alerts))
        t0 = time.monotonic()

        if self._cfg.tier == "none":
            await self._triage_rule_based(alerts)
        else:
            await self._triage_ai(alerts)

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        log.info(
            "TriageWorker: batch done in %dms (total triaged=%d, errors=%d)",
            elapsed_ms,
            self.total_triaged,
            self.total_errors,
        )

    async def _triage_rule_based(self, alerts: list[dict]) -> None:
        """Apply rule-based triage to all alerts in the batch."""
        for alert in alerts:
            verdict, confidence, reasoning = _rule_based_verdict(alert)
            result = TriageResult(
                alert_id=alert["id"],
                verdict=verdict,
                confidence=confidence,
                reasoning=reasoning,
                iocs=[],
                suggested_action="",
                model="rule-based",
                latency_ms=0,
                created_at=now_iso(),
            )
            await self._store_triage(result)

    async def _triage_ai(self, alerts: list[dict]) -> None:
        """Send batch to AI, parse response, fall back on failure."""
        import time as _time

        # Circuit breaker: if tripped, skip AI and use rules until cooldown expires
        if self._cb_tripped:
            elapsed = _time.monotonic() - self._cb_tripped_at
            if elapsed < self._CB_COOLDOWN_SEC:
                log.warning(
                    "TriageWorker: circuit breaker open (%.0fs remaining) - using rules",
                    self._CB_COOLDOWN_SEC - elapsed,
                )
                await self._triage_rule_based(alerts)
                return
            else:
                log.info("TriageWorker: circuit breaker reset - retrying AI")
                self._cb_tripped = False
                self._cb_failures = 0

        # Sanitize alert data for prompt: drop heavy fields
        slim_alerts = [_slim_alert(a) for a in alerts]

        # RAG: inject environment context relevant to this batch
        context_block = await _rag_context(self._db, alerts)

        # Privacy layer: for the cloud tier, pseudonymize network identifiers before
        # anything leaves the box, and restore them in the reply. No-op on local/none.
        obf = await self._build_obfuscator(slim_alerts)
        if obf is not None:
            slim_alerts = [obf.obfuscate_alert(a) for a in slim_alerts]
            if context_block:
                context_block = obf._redact_residue(obf.scrub_text(context_block))

        alerts_json = json.dumps(slim_alerts, indent=2)
        if context_block:
            prompt = TRIAGE_BATCH_WITH_CONTEXT.format(
                count=len(alerts), alerts_json=alerts_json, context=context_block
            )
        else:
            prompt = TRIAGE_BATCH.format(count=len(alerts), alerts_json=alerts_json)

        t0 = time.monotonic()
        try:
            raw_response = await self._call_ai(prompt, TRIAGE_SYSTEM.strip())
            if obf is not None:
                raw_response = obf.deobfuscate(raw_response)
        except Exception as exc:
            log.error("TriageWorker: AI call failed: %s - falling back to rules", exc)
            self.total_errors += 1
            self._cb_failures += 1
            if self._cb_failures >= self._CB_THRESHOLD:
                self._cb_tripped = True
                self._cb_tripped_at = _time.monotonic()
                log.error(
                    "TriageWorker: circuit breaker TRIPPED after %d consecutive AI failures "
                    "(will retry in %ds)",
                    self._CB_THRESHOLD, self._CB_COOLDOWN_SEC,
                )
            await self._triage_rule_based(alerts)
            return

        # Successful AI call - reset circuit breaker failure counter
        self._cb_failures = 0

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        model_name = self._model_name()

        parsed_items = _parse_batch_response(raw_response, alerts)

        for i, alert in enumerate(alerts):
            item = parsed_items[i]
            if item is None:
                log.warning(
                    "TriageWorker: no result for alert %s at index %d - using rules",
                    alert["id"], i,
                )
                self.total_errors += 1
                verdict, confidence, reasoning = _rule_based_verdict(alert)
                result = TriageResult(
                    alert_id=alert["id"],
                    verdict=verdict,
                    confidence=confidence,
                    reasoning=f"AI parse failure; {reasoning}",
                    iocs=[],
                    suggested_action="",
                    model=f"rule-based (fallback from {model_name})",
                    latency_ms=elapsed_ms,
                    created_at=now_iso(),
                )
            else:
                result = _build_triage_result(
                    alert_id=alert["id"],
                    item=item,
                    model=model_name,
                    latency_ms=elapsed_ms // len(alerts),
                )

            await self._store_triage(result)

        self.total_latency_ms += elapsed_ms

    # ── Privacy / obfuscation ────────────────────────────────

    async def _build_obfuscator(self, slim_alerts: list[dict]) -> Obfuscator | None:
        """Build a seeded Obfuscator for the cloud tier, or None when not applicable.

        Only active when tier == remote_api and ai.obfuscate_cloud is set. Seeds
        known hostnames/IPs/users from the asset inventory and from the batch's own
        structured fields so those identifiers are masked even when they appear in
        prose (titles/descriptions), not just in structured columns. Structural
        identifiers (IP/MAC/email/home-path) are masked without seeding.
        """
        if self._cfg.tier != "remote_api" or not getattr(self._cfg, "obfuscate_cloud", False):
            return None

        obf = Obfuscator(strict=True)
        hostnames: set[str] = set()
        ips: set[str] = set()
        users: set[str] = set()

        # Seed from the persistent asset inventory (best-effort - never block triage).
        try:
            for row in await self._db.get_assets(limit=500):
                if row.get("hostname"):
                    hostnames.add(row["hostname"])
                if row.get("ip"):
                    ips.add(row["ip"])
        except Exception:
            log.debug("Obfuscator: asset seed skipped", exc_info=True)
        try:
            for row in await self._db.get_known_devices(limit=500):
                if row.get("hostname"):
                    hostnames.add(row["hostname"])
                if row.get("ip"):
                    ips.add(row["ip"])
        except Exception:
            log.debug("Obfuscator: device seed skipped", exc_info=True)

        # Seed from the batch itself so a hostname in a title is also caught.
        for a in slim_alerts:
            for f in ("src_asset", "dst_asset", "src_dns", "dst_dns"):
                if a.get(f):
                    hostnames.add(str(a[f]))
            for f in ("src_ip", "dst_ip"):
                if a.get(f):
                    ips.add(str(a[f]))

        obf.seed_assets(hostnames=hostnames, ips=ips, users=users)
        return obf

    # ── AI dispatch ──────────────────────────────────────────

    async def _call_ai(self, prompt: str, system: str) -> str:
        """Route the AI call to the appropriate backend based on tier."""
        cfg = self._cfg
        tier = cfg.tier

        if tier in ("remote_micro", "remote_standard", "local"):
            # Ollama native
            assert self._client is not None
            return await self._client.generate(
                prompt=prompt,
                model=cfg.ollama_model,
                system=system,
            )

        if tier == "remote_api":
            if cfg.openai_api_key:
                assert self._client is not None
                return await self._client.generate_openai(
                    prompt=prompt,
                    model=cfg.ollama_model or "gpt-4o-mini",
                    api_key=cfg.openai_api_key,
                    system=system,
                )
            if cfg.anthropic_api_key:
                assert self._client is not None
                return await self._client.generate_anthropic(
                    prompt=prompt,
                    model=cfg.ollama_model or "claude-3-haiku-20240307",
                    api_key=cfg.anthropic_api_key,
                    system=system,
                )
            raise ValueError("remote_api tier requires openai_api_key or anthropic_api_key")

        raise ValueError(f"Unknown AI tier: {tier!r}")

    def _model_name(self) -> str:
        """Return a descriptive model identifier string."""
        cfg = self._cfg
        if cfg.ollama_model:
            return cfg.ollama_model
        if cfg.openai_api_key:
            return "openai"
        if cfg.anthropic_api_key:
            return "anthropic"
        return cfg.tier

    # ── DB helpers ───────────────────────────────────────────

    async def _store_triage(self, result: TriageResult) -> None:
        """Write triage result to DB and update alert verdict."""
        try:
            await self._db.insert_triage(result)
            await self._db.update_verdict(
                alert_id=result.alert_id,
                verdict=result.verdict,
                confidence=result.confidence,
                reasoning=result.reasoning,
            )
            self.total_triaged += 1
            log.debug(
                "Triaged alert %s → %s (conf=%.2f)",
                result.alert_id, result.verdict, result.confidence,
            )
        except Exception:
            log.exception("TriageWorker: failed to store triage for alert %s", result.alert_id)
            self.total_errors += 1

    # ── Stats ────────────────────────────────────────────────

    @property
    def avg_latency_ms(self) -> float:
        """Average AI call latency in milliseconds (0 if no calls yet)."""
        if self.total_triaged == 0:
            return 0.0
        return self.total_latency_ms / self.total_triaged

    def get_stats(self) -> dict[str, Any]:
        """Return current worker statistics."""
        import time as _time
        cb_info: dict[str, Any] = {"tripped": self._cb_tripped}
        if self._cb_tripped:
            cb_info["cooldown_remaining_sec"] = max(
                0, self._CB_COOLDOWN_SEC - int(_time.monotonic() - self._cb_tripped_at)
            )
        return {
            "total_triaged": self.total_triaged,
            "total_errors": self.total_errors,
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "tier": self._cfg.tier,
            "model": self._model_name(),
            "batch_size": self._cfg.batch_size,
            "batch_interval_sec": self._cfg.batch_interval_sec,
            "circuit_breaker": cb_info,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slim_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Return a trimmed alert dict for sending to AI (excludes raw JSON)."""
    return {
        "id": alert.get("id", ""),
        "timestamp": alert.get("timestamp", ""),
        "source": alert.get("source", ""),
        "severity": alert.get("severity", "medium"),
        "title": alert.get("title", ""),
        "description": alert.get("description", ""),
        "src_ip": alert.get("src_ip", ""),
        "src_port": alert.get("src_port", 0),
        "dst_ip": alert.get("dst_ip", ""),
        "dst_port": alert.get("dst_port", 0),
        "proto": alert.get("proto", ""),
        "category": alert.get("category", ""),
        "signature_id": alert.get("signature_id", 0),
        "src_geo": alert.get("src_geo", ""),
        "dst_geo": alert.get("dst_geo", ""),
        "src_dns": alert.get("src_dns", ""),
        "dst_dns": alert.get("dst_dns", ""),
        "src_asset": alert.get("src_asset", ""),
        "dst_asset": alert.get("dst_asset", ""),
    }
