"""Non-judgmental edge scout for candidate missed signals."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import sqlite3
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from shallots.ai.ollama_client import OllamaClient

if TYPE_CHECKING:
    from shallots.config import ScoutConfig
    from shallots.store.db import AlertDB

log = logging.getLogger(__name__)

_MGMT_PORTS = {22, 3389, 445, 5985, 5986, 4000, 8844, 8855}
_VALID_SOURCES = {"suricata", "wazuh", "crowdsec", "syslog", "pfsense", "pihole", "argus", "webapp"}
_ARGUS_CANARY_RE = re.compile(r"argus-scout-canary-\d+-[0-9a-f]+", re.IGNORECASE)
_RECENT_CARD_DEDUPE_MINUTES = 60
_NODE_INVARIANTS_PATH = Path("data/scout_node_invariants.json")

_SCOUT_SYSTEM = """You are Security Shallots edge scout.
You do not decide benign/malicious. You do not suppress, escalate, page, or assign severity.
The code has already decided this alert is worth surfacing mechanically.
Return only valid JSON with keys: context_facts, scout_note, verdict_recommendation.
verdict_recommendation must be "none".
Use retrieved context only for context_facts and scout_note. Do not change extracted fields.
Use neutral observation language. Avoid judgment words such as malicious, benign,
threat, concern, suspicious, unauthorized, compromise, exploit, or attack unless
those exact words appear in the log title. Say "candidate for higher-tier review"
instead of recommending an action. Do not use the phrases "further investigation",
"warrants review", "raises concerns", or "potential implications"."""


class ScoutWorker:
    """Surface candidate missed signals without changing alert verdicts."""

    def __init__(self, cfg: "ScoutConfig", db: "AlertDB", repo_root: Path | None = None) -> None:
        self._cfg = cfg
        self._db = db
        self._repo_root = repo_root or Path.cwd()
        self._client: OllamaClient | None = None
        self.total_scanned = 0
        self.total_cards = 0
        self.total_errors = 0
        self._node_invariants: dict[str, Any] = {}
        self._node_invariants_mtime = 0.0

    async def run(self, shutdown: asyncio.Event) -> None:
        if not self._cfg.enabled:
            return

        self._client = OllamaClient(
            base_url=self._cfg.ollama_url or "http://localhost:11434",
        )
        log.info(
            "ScoutWorker started (model=%s, batch=%d, interval=%ds, min_score=%d)",
            self._cfg.model,
            self._cfg.batch_size,
            self._cfg.interval_sec,
            self._cfg.min_score,
        )

        try:
            while not shutdown.is_set():
                try:
                    await self._process_batch()
                except asyncio.CancelledError:
                    return
                except Exception:
                    self.total_errors += 1
                    log.exception("ScoutWorker: unhandled batch error")

                try:
                    await asyncio.sleep(self._cfg.interval_sec)
                except asyncio.CancelledError:
                    return
        finally:
            if self._client:
                await self._client.close()
                self._client = None
            log.info("ScoutWorker stopped")

    async def _process_batch(self) -> None:
        alerts = await self._db.get_unscouted_alerts(
            limit=self._cfg.batch_size,
            lookback_hours=self._cfg.lookback_hours,
        )
        if not alerts:
            return

        for alert in alerts:
            self.total_scanned += 1
            if _is_known_argus_canary(alert):
                await self._mark_skipped(
                    alert=alert,
                    status="ignored_synthetic",
                    reasons=["known_argus_scout_canary"],
                    note="Known synthetic Argus canary recorded for processing bookkeeping. No Scout card was surfaced.",
                )
                continue

            score, reasons = await self._score_alert(alert)
            if score < self._cfg.min_score:
                continue
            if await self._has_recent_similar_card(alert):
                await self._mark_skipped(
                    alert=alert,
                    status="duplicate",
                    score=score,
                    reasons=reasons,
                    note="Duplicate Scout candidate recorded for processing bookkeeping. No new Scout card was surfaced.",
                )
                log.info(
                    "ScoutWorker: skipped duplicate card for alert %s (%s)",
                    alert.get("id"), alert.get("title", ""),
                )
                continue

            extracted = _extract_alert_fields(alert)
            context = self._retrieve_context(alert, reasons)
            context_facts: list[str] | dict | str = []
            scout_note = _fallback_note(alert, reasons)

            try:
                llm = await self._call_model(alert, extracted, reasons, context)
                context_facts = llm.get("context_facts", [])
            except Exception as exc:
                self.total_errors += 1
                log.warning("ScoutWorker: model note failed for alert %s: %s", alert.get("id"), exc)

            await self._db.insert_scout_card(
                alert_id=alert["id"],
                model=self._cfg.model,
                score=score,
                reasons=reasons,
                extracted=extracted,
                context_facts=context_facts,
                scout_note=scout_note,
            )
            self.total_cards += 1
            log.info("ScoutWorker: surfaced alert %s score=%d reasons=%s", alert["id"], score, reasons)

    async def _score_alert(self, alert: dict[str, Any]) -> tuple[int, list[str]]:
        """Mechanical surfacing score. No model judgment here."""
        reasons: list[str] = []
        source = str(alert.get("source") or "").lower()
        title = str(alert.get("title") or "")
        signature_id = int(alert.get("signature_id") or 0)
        src_ip = str(alert.get("src_ip") or "")
        dst_ip = str(alert.get("dst_ip") or "")
        dst_port = int(alert.get("dst_port") or 0)
        proto = str(alert.get("proto") or "")
        verdict = str(alert.get("verdict") or "")

        if _is_known_argus_canary(alert):
            return 0, []

        if source and source not in _VALID_SOURCES:
            reasons.append(f"unknown_collector_source:{source}")

        signature_count = await self._db.count_alerts_matching(
            source=source,
            signature_id=signature_id,
            title=title,
            lookback_hours=24 * 30,
        )
        if title and signature_count <= 1:
            reasons.append("first_seen_signature_or_title_30d")

        tuple_count = await self._db.count_alerts_matching(
            source=source,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=proto,
            lookback_hours=24 * 30,
        )
        if src_ip and dst_ip and tuple_count <= 1:
            reasons.append("first_seen_src_dst_port_tuple_30d")

        if dst_port in _MGMT_PORTS and _is_private(src_ip) and _is_private(dst_ip):
            reasons.append(f"internal_management_port:{dst_port}")

        if dst_port in _MGMT_PORTS and src_ip and not _is_private(src_ip) and _is_private(dst_ip):
            reasons.append(f"external_to_internal_management_port:{dst_port}")

        if verdict == "suppress" and src_ip and dst_ip and tuple_count <= 1:
            reasons.append("suppressed_but_rare")

        router_ip = getattr(self._cfg, "router_ip", "")
        router_hint = getattr(self._cfg, "router_syslog_hint", "")
        if (
            source == "syslog" and router_ip and router_hint
            and src_ip and src_ip != router_ip
            and router_hint.lower() in title.lower()
        ):
            reasons.append("router_syslog_source_mismatch")

        sensor_ips = getattr(self._cfg, "sensor_ips", []) or []
        if source == "suricata" and sensor_ips and (src_ip in sensor_ips or dst_ip in sensor_ips):
            reasons.append("local_sensor_suricata_scope")

        reasons.extend(self._score_node_invariants(alert))

        title_lower = title.lower()
        category_lower = str(alert.get("category") or "").lower()
        strong_reasons = [
            reason for reason in reasons
            if reason.startswith("internal_management_port:")
            or reason.startswith("external_to_internal_management_port:")
            or reason.startswith("internal_to_management_plane:")
            or reason == "router_syslog_source_mismatch"
            or reason.startswith("unknown_collector_source:")
            or reason.startswith("baseline_volume_anomaly_candidate")
            or reason.startswith("process_semantics_candidate:")
            or reason.startswith("watched_dns_tld:")
        ]
        novelty_reasons = {
            "first_seen_signature_or_title_30d",
            "first_seen_src_dst_port_tuple_30d",
            "suppressed_but_rare",
        }
        # Suppressed Suricata stream/protocol-decode noise stays unsurfaced even when
        # it is first-seen — check this before the novelty early-return so the
        # suppression holds on any network (not just traffic to a local sensor).
        if (
            source == "suricata"
            and verdict == "suppress"
            and ("suricata stream" in title_lower or "protocol command decode" in category_lower)
            and not strong_reasons
        ):
            return 0, []
        if not strong_reasons and reasons and all(reason in novelty_reasons for reason in reasons):
            return min(1, len(reasons)), reasons
        if (
            source == "suricata"
            and "et info" in title_lower
            and (
                "dns query to ." in title_lower
                or "observed dns query" in title_lower
                or "observed ip lookup domain" in title_lower
                or "abused hosting domain" in title_lower
            )
            and not strong_reasons
        ):
            return min(1, len(reasons)), reasons

        return len(reasons), reasons

    def _score_node_invariants(self, alert: dict[str, Any]) -> list[str]:
        """Apply reviewed node-local invariants from the elder audit file."""
        invariants = self._load_node_invariants()
        if not invariants:
            return []

        reasons: list[str] = []
        title = str(alert.get("title") or "")
        description = str(alert.get("description") or "")
        category = str(alert.get("category") or "")
        haystack = f"{title}\n{description}\n{category}".lower()
        src_ip = str(alert.get("src_ip") or "")
        dst_ip = str(alert.get("dst_ip") or "")
        dst_port = int(alert.get("dst_port") or 0)
        source = str(alert.get("source") or "").lower()

        critical_hosts = set(str(x) for x in invariants.get("critical_hosts", []))
        management_hosts = set(str(x) for x in invariants.get("management_plane_hosts", []))
        volume_terms = [str(x).lower() for x in invariants.get("volume_anomaly_terms", [])]
        process_terms = [str(x).lower() for x in invariants.get("suspicious_process_terms", [])]
        watched_tlds = [str(x).lower().lstrip(".") for x in invariants.get("watched_dns_tlds", [])]

        if (
            src_ip in critical_hosts
            and dst_ip
            and not _is_private(dst_ip)
            and dst_port in (80, 443, 8443)
            and any(term in haystack for term in volume_terms)
        ):
            reasons.append("baseline_volume_anomaly_candidate")

        if (
            dst_ip in management_hosts
            and src_ip
            and _is_private(src_ip)
            and dst_port in (22, 80, 443, 623, 17988)
        ):
            reasons.append(f"internal_to_management_plane:{dst_port}")

        for term in process_terms:
            if term and term in haystack and dst_ip and not _is_private(dst_ip):
                reasons.append(f"process_semantics_candidate:{term}")
                break

        if source == "suricata" and watched_tlds:
            for tld in watched_tlds:
                if re.search(rf"\.{re.escape(tld)}\b", haystack) or f" {tld} tld" in haystack:
                    reasons.append(f"watched_dns_tld:{tld}")
                    break

        return reasons

    def _load_node_invariants(self) -> dict[str, Any]:
        path = _NODE_INVARIANTS_PATH
        if not path.is_absolute():
            path = self._repo_root / path
        try:
            stat = path.stat()
        except FileNotFoundError:
            self._node_invariants = {}
            self._node_invariants_mtime = 0.0
            return {}

        if stat.st_mtime == self._node_invariants_mtime:
            return self._node_invariants

        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            log.warning("ScoutWorker: could not read node invariants from %s", path)
            self._node_invariants = {}
            self._node_invariants_mtime = stat.st_mtime
            return {}

        self._node_invariants = data if isinstance(data, dict) else {}
        self._node_invariants_mtime = stat.st_mtime
        return self._node_invariants

    async def _has_recent_similar_card(self, alert: dict[str, Any]) -> bool:
        """Avoid repeated Scout cards for the same alert family and flow tuple."""
        rows = await self._db.execute_sql(
            """
            SELECT sc.id
            FROM scout_cards sc
            JOIN alerts a ON a.id = sc.alert_id
            WHERE sc.created_at > datetime('now', ?)
              AND a.source = ?
              AND a.title = ?
              AND COALESCE(a.src_ip, '') = ?
              AND COALESCE(a.dst_ip, '') = ?
              AND COALESCE(a.dst_port, 0) = ?
            ORDER BY sc.created_at DESC
            LIMIT 1
            """,
            (
                f"-{_RECENT_CARD_DEDUPE_MINUTES} minutes",
                str(alert.get("source") or ""),
                str(alert.get("title") or ""),
                str(alert.get("src_ip") or ""),
                str(alert.get("dst_ip") or ""),
                int(alert.get("dst_port") or 0),
            ),
            max_rows=1,
        )
        return bool(rows)

    async def _mark_skipped(
        self,
        *,
        alert: dict[str, Any],
        status: str,
        reasons: list[str],
        note: str,
        score: int = 0,
    ) -> None:
        await self._db.insert_scout_card(
            alert_id=alert["id"],
            model=self._cfg.model,
            score=score,
            reasons=reasons,
            extracted=_extract_alert_fields(alert),
            context_facts=[],
            scout_note=note,
            status=status,
        )

    def _retrieve_context(self, alert: dict[str, Any], reasons: list[str]) -> str:
        corpus_path = Path(self._cfg.corpus_path)
        if not corpus_path.is_absolute():
            corpus_path = self._repo_root / corpus_path
        if not corpus_path.exists():
            return ""

        terms = " ".join(
            str(x)
            for x in (
                alert.get("source"),
                alert.get("title"),
                alert.get("src_ip"),
                alert.get("dst_ip"),
                alert.get("dst_port"),
                " ".join(reasons),
            )
            if x
        )
        fts_query = " ".join(
            f'"{token.replace(chr(34), chr(34) + chr(34))}"'
            for token in re.findall(r"[A-Za-z0-9_.:-]+", terms)
        )
        if not fts_query:
            return ""

        conn = sqlite3.connect(corpus_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                """
                SELECT d.category, d.title, d.source,
                       snippet(documents_fts, 1, '[', ']', ' ... ', 28) AS snippet
                FROM documents_fts
                JOIN documents d ON d.rowid = documents_fts.rowid
                WHERE documents_fts MATCH ?
                ORDER BY bm25(documents_fts)
                LIMIT 5
                """,
                (fts_query,),
            ).fetchall()
        except sqlite3.OperationalError:
            return ""
        finally:
            conn.close()

        return "\n\n".join(
            f"[{row['category']}] {row['title']} ({row['source']})\n{row['snippet']}"
            for row in rows
        )

    async def _call_model(
        self,
        alert: dict[str, Any],
        extracted: dict[str, Any],
        reasons: list[str],
        context: str,
    ) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("ScoutWorker model client is not initialized")

        prompt = f"""Retrieved fleet context:
{context or "(none)"}

Mechanical surfacing reasons:
{json.dumps(reasons, indent=2)}

Frozen extracted alert fields:
{json.dumps(extracted, indent=2, sort_keys=True)}

Original alert title:
{alert.get("title") or ""}

Write a concise scout card in neutral language. State which mechanical reasons
made it a candidate and which fleet facts are relevant. Do not infer intent,
malice, compromise, authorization status, risk severity, or next action."""

        raw = await self._client.generate_json(
            prompt=prompt,
            model=self._cfg.model,
            system=_SCOUT_SYSTEM,
        )
        if str(raw.get("verdict_recommendation", "none")).lower() != "none":
            raw["verdict_recommendation"] = "none"
        return raw

    def get_stats(self) -> dict[str, Any]:
        return {
            "enabled": self._cfg.enabled,
            "model": self._cfg.model,
            "total_scanned": self.total_scanned,
            "total_cards": self.total_cards,
            "total_errors": self.total_errors,
            "min_score": self._cfg.min_score,
        }


def _extract_alert_fields(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": alert.get("id", ""),
        "timestamp": alert.get("timestamp", ""),
        "source": alert.get("source", ""),
        "severity": alert.get("severity", ""),
        "verdict": alert.get("verdict", ""),
        "title": alert.get("title", ""),
        "category": alert.get("category", ""),
        "signature_id": alert.get("signature_id") or 0,
        "src_ip": alert.get("src_ip", ""),
        "src_port": alert.get("src_port") or 0,
        "dst_ip": alert.get("dst_ip", ""),
        "dst_port": alert.get("dst_port") or 0,
        "proto": alert.get("proto", ""),
    }


def _fallback_note(alert: dict[str, Any], reasons: list[str]) -> str:
    return (
        "Candidate missed signal surfaced by mechanical scout checks. "
        f"Mechanical reasons: {', '.join(reasons)}. "
        "No benign/malicious verdict was made."
    )


def _is_known_argus_canary(alert: dict[str, Any]) -> bool:
    if str(alert.get("source") or "").lower() != "argus":
        return False
    haystack = " ".join(
        str(alert.get(field) or "")
        for field in ("title", "description", "category")
    )
    return bool(_ARGUS_CANARY_RE.search(haystack))


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
