"""Argus endpoint security event ingestor.

Ingests events from Argus (Windows endpoint monitor) via two paths:
1. JSONL file tailer - tails daily-rotated argus_events_YYYY-MM-DD.jsonl files
2. HTTP webhook receiver - accepts POSTed ArgusEvent JSON from Argus webhook sink

Argus event_types: state_change, heartbeat, process_tripwire, file_sentinel,
persistence_detected, session_alert, evidence_capture, anti_tamper
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import secrets
from datetime import date
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shallots.config import ArgusConfig

from aiohttp import web

from shallots.store.models import Alert, AlertSource, now_iso

log = logging.getLogger(__name__)

# Argus event_type → signature_id (900xxx range avoids Suricata/Wazuh collisions)
_EVENT_TYPE_SIG_IDS: dict[str, int] = {
    "state_change": 900001,
    "heartbeat": 900002,
    "process_tripwire": 900003,
    "file_sentinel": 900004,
    "persistence_detected": 900005,
    "session_alert": 900006,
    "evidence_capture": 900007,
    "anti_tamper": 900008,
    "network_egress_suspicious": 900009,
}


class ArgusIngestor:
    """Dual-mode ingestor: JSONL file tailer + optional HTTP webhook."""

    def __init__(self, config: ArgusConfig, queue: asyncio.Queue, daemon=None):
        self.config = config
        self.queue = queue
        self._daemon = daemon
        # JSONL tailer state
        self._position = 0
        self._inode = 0
        self._current_date: str = ""
        # Webhook state
        self._webhook_runner: web.AppRunner | None = None

    async def run(self) -> None:
        """Start both ingestion paths."""
        tasks: list[asyncio.Task] = []

        if self.config.jsonl_dir:
            tasks.append(asyncio.create_task(self._tail_loop()))
            log.info("Argus JSONL tailer watching: %s", self.config.jsonl_dir)

        if self.config.webhook_enabled:
            tasks.append(asyncio.create_task(self._run_webhook()))
            log.info("Argus webhook listener on port %d", self.config.webhook_port)

        if not tasks:
            log.warning("Argus ingestor enabled but no jsonl_dir or webhook configured")
            return

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            if self._webhook_runner:
                await self._webhook_runner.cleanup()

    # ── JSONL file tailer ──────────────────────────────────────────────

    def _today_file(self) -> str:
        """Build path to today's JSONL file."""
        today = date.today().isoformat()  # YYYY-MM-DD
        return os.path.join(self.config.jsonl_dir, f"argus_events_{today}.jsonl")

    async def _tail_loop(self) -> None:
        """Main tail loop - handles daily file rotation."""
        # Wait for directory to exist
        while not os.path.isdir(self.config.jsonl_dir):
            log.debug("Waiting for Argus events dir: %s", self.config.jsonl_dir)
            await asyncio.sleep(5)

        # Start at end of today's file
        path = self._today_file()
        self._current_date = date.today().isoformat()
        if os.path.exists(path):
            try:
                stat = os.stat(path)
                self._inode = stat.st_ino
                self._position = stat.st_size
            except OSError:
                pass

        while True:
            try:
                await self._tail_once()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("Argus tailer error")
            await asyncio.sleep(0.5)

    async def _tail_once(self) -> None:
        """Read new lines, handling daily date rotation."""
        today = date.today().isoformat()
        path = self._today_file()

        # Date rolled over - reset to new file
        if today != self._current_date:
            log.info("Argus date rotation: %s -> %s", self._current_date, today)
            self._current_date = today
            self._position = 0
            self._inode = 0

        if not os.path.exists(path):
            return

        try:
            stat = os.stat(path)
        except FileNotFoundError:
            return

        # Detect rotation (inode change or truncation)
        if stat.st_ino != self._inode or stat.st_size < self._position:
            log.info("Argus JSONL file rotated, resetting position")
            self._inode = stat.st_ino
            self._position = 0

        if stat.st_size <= self._position:
            return

        loop = asyncio.get_running_loop()
        lines = await loop.run_in_executor(None, self._read_lines, path)

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
                if evt.get("event_type") == "heartbeat":
                    await self._route_heartbeat(evt)
                    continue
                alert = _parse_argus_event(evt, line)
                if alert:
                    await self.queue.put(alert)
            except json.JSONDecodeError:
                log.debug("Argus: skipping non-JSON line")

    def _read_lines(self, path: str) -> list[str]:
        """Read new lines from file (called in executor)."""
        try:
            with open(path, "r", errors="replace") as f:
                f.seek(self._position)
                lines = f.readlines()
                self._position = f.tell()
                return lines
        except OSError as e:
            log.warning("Error reading Argus events file: %s", e)
            return []

    # ── HTTP webhook receiver ──────────────────────────────────────────

    async def _run_webhook(self) -> None:
        """Run a small aiohttp server for Argus webhook POSTs."""
        app = web.Application()
        app.router.add_post(self.config.webhook_path, self._handle_webhook)
        app.router.add_get(self.config.webhook_path, self._handle_health)

        self._webhook_runner = web.AppRunner(app)
        await self._webhook_runner.setup()
        ssl_ctx = None
        if self.config.webhook_tls_enabled:
            import ssl

            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(self.config.webhook_tls_cert, self.config.webhook_tls_key)
        site = web.TCPSite(
            self._webhook_runner,
            "0.0.0.0",
            self.config.webhook_port,
            ssl_context=ssl_ctx,
        )
        await site.start()

        # Block until cancelled
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            await self._webhook_runner.cleanup()

    async def _handle_webhook(self, request: web.Request) -> web.Response:
        """Handle POST from Argus webhook sink."""
        if not argus_source_allowed(request.remote or "", self.config.allowed_source_cidrs):
            return web.json_response({"error": "source not allowed"}, status=403)
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            return web.json_response({"error": "invalid JSON"}, status=400)

        events = normalize_argus_events(body)
        if events is None:
            return web.json_response({"error": "event body must be an object or list of objects"}, status=400)
        if not argus_secret_allowed(
            request.headers.get("X-Argus-Secret", ""),
            events,
            shared_secret=self.config.webhook_secret,
            agent_secrets=self.config.agent_secrets,
            require_per_agent=self.config.require_per_agent_secret,
        ):
            return web.json_response({"error": "unauthorized"}, status=401)
        accepted = 0

        for evt in events:
            if evt.get("event_type") == "heartbeat":
                await self._route_heartbeat(evt)
                accepted += 1
                continue
            raw_line = json.dumps(evt)
            alert = _parse_argus_event(evt, raw_line)
            if alert:
                try:
                    self.queue.put_nowait(alert)
                    accepted += 1
                except asyncio.QueueFull:
                    if self._daemon is not None:
                        self._daemon._dropped_alerts = getattr(self._daemon, "_dropped_alerts", 0) + 1
                    log.warning("Argus webhook: alert queue full, dropping event")

        return web.json_response({"accepted": accepted})

    async def _handle_health(self, request: web.Request) -> web.Response:
        """GET health check for the webhook endpoint."""
        return web.json_response({"status": "ok", "source": "argus"})

    async def _route_heartbeat(self, evt: dict) -> dict:
        """Route a heartbeat event to the agent_status DB table."""
        if not self._daemon or not hasattr(self._daemon, 'db'):
            return {}
        try:
            return await route_argus_heartbeat(self._daemon.db, evt)
        except Exception:
            log.debug("Failed to store Argus heartbeat")
            return {}


def argus_source_allowed(remote_ip: str, allowed_source_cidrs: list[str]) -> bool:
    """Return whether a remote Argus source is allowed by configured CIDRs."""
    if not allowed_source_cidrs:
        return True
    try:
        ip = ipaddress.ip_address(remote_ip)
    except ValueError:
        return False
    for raw in allowed_source_cidrs:
        try:
            if ip in ipaddress.ip_network(str(raw), strict=False):
                return True
        except ValueError:
            log.warning("Ignoring invalid Argus allowed_source_cidrs entry: %s", raw)
    return False


def normalize_argus_events(body: object) -> list[dict] | None:
    """Return a normalized Argus event list or None for unsupported JSON shapes."""
    events = body if isinstance(body, list) else [body]
    if not all(isinstance(evt, dict) for evt in events):
        return None
    return events


def argus_secret_allowed(
    header_secret: str,
    events: list[dict],
    *,
    shared_secret: str = "",
    agent_secrets: dict[str, str] | None = None,
    require_per_agent: bool = False,
) -> bool:
    """Validate an Argus secret against per-agent or legacy shared credentials."""
    configured = agent_secrets or {}
    if require_per_agent:
        if not configured:
            log.error("Argus per-agent auth required but no agent_secrets are configured")
            return False
        hosts = {str(evt.get("host", "") or "unknown") for evt in events}
        if len(hosts) != 1:
            return False
        expected = configured.get(next(iter(hosts)), "")
        return bool(expected) and secrets.compare_digest(header_secret, expected)

    for expected in configured.values():
        if expected and secrets.compare_digest(header_secret, expected):
            return True
    if shared_secret:
        return secrets.compare_digest(header_secret, shared_secret)
    log.error("Argus ingest route is missing configured secret")
    return False


async def route_argus_heartbeat(db, evt: dict, remote_ip: str = "") -> dict:
    """Store an Argus heartbeat in both agent tables and return commands."""
    host = evt.get("host", "") or "unknown"
    details = evt.get("details", {})
    ip = details.get("ip_address") or remote_ip or ""
    health = {
        "uptime": details.get("uptime", 0),
        "state": evt.get("state", ""),
        "services": details.get("services", {}),
        "active_monitors": details.get("active_monitors", []),
        "timelock_active": details.get("timelock_active", False),
        "host_metrics": details.get("host_metrics", {}),
        "telemetry": details.get("telemetry", {}),
    }
    health_json = json.dumps(health)
    await db.upsert_agent_heartbeat(
        agent_name=host,
        agent_type="argus",
        os=details.get("os", "unknown"),
        ip=ip,
        version=str(details.get("version", "")),
        health_data=health_json,
    )
    return await db.upsert_clove_heartbeat(
        agent_name=host,
        agent_type="argus",
        os=details.get("os", "unknown"),
        ip=ip,
        version=str(details.get("version", "")),
        health=health_json,
        baselines="{}",
    )


def _parse_argus_event(evt: dict, raw_line: str) -> Alert | None:
    """Parse an Argus event dict into a normalized Alert.

    Field mapping:
        ArgusEvent.severity    → Alert.severity  (direct: low/medium/high/critical)
        ArgusEvent.confidence  → Alert.confidence (direct: 0.0-1.0)
        ArgusEvent.title       → Alert.title
        ArgusEvent.description → Alert.description (+ MITRE ATT&CK if present)
        ArgusEvent.category    → Alert.category
        ArgusEvent.event_type  → Alert.source_ref + signature_id lookup
        ArgusEvent.host        → Alert.src_asset
        ArgusEvent.details     → Alert.src_ip (from ip_address field)
        Full event JSON        → Alert.raw
    """
    event_type = evt.get("event_type", "")

    # Skip heartbeats by default - they're high volume, low value for the SIEM
    if event_type == "heartbeat":
        return None

    severity = evt.get("severity", "medium")
    # Validate severity against known values
    if severity not in ("low", "medium", "high", "critical"):
        severity = "medium"

    title = evt.get("title", "Argus Event")
    description = evt.get("description", "")

    # Append MITRE ATT&CK info if present
    mitre = evt.get("mitre_attack")
    if mitre:
        description = f"{description} | MITRE: {mitre}"

    # Extract network details from the details dict (a malicious/buggy agent may
    # send a non-dict here - coerce so one bad event can't crash the tail loop).
    details = evt.get("details")
    if not isinstance(details, dict):
        details = {}
    src_ip = details.get("ip_address", "") or details.get("source_ip", "")
    dst_ip = details.get("dest_ip", "") or details.get("remote_ip", "")
    dst_port = 0
    try:
        dst_port = int(details.get("dest_port", 0) or details.get("remote_port", 0))
    except (ValueError, TypeError):
        pass

    # Signature ID from event type
    sig_id = _EVENT_TYPE_SIG_IDS.get(event_type, 900000)

    confidence = 0.0
    try:
        confidence = float(evt.get("confidence", 0.0))
    except (ValueError, TypeError):
        pass
    confidence = min(max(confidence, 0.0), 1.0)

    host = evt.get("host", "")

    # Argus events lack network tuples, so the default dedup hash
    # (source+sig_id+src_ip+dst_ip+proto) collapses distinct events.
    # Include stable event content because concurrent events can share a
    # millisecond timestamp.
    ts = evt.get("timestamp", "")
    content_key = json.dumps(
        {
            "title": title,
            "description": description,
            "category": evt.get("category", "") or "",
            "details": details,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    dedup_key = f"argus:{event_type}:{host}:{ts}:{content_key}"
    dedup_hash = hashlib.sha256(dedup_key.encode()).hexdigest()[:16]

    return Alert(
        timestamp=ts or now_iso(),
        source=AlertSource.ARGUS,
        source_ref=event_type,
        severity=severity,
        title=title,
        description=description,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        category=evt.get("category", "") or "",
        signature_id=sig_id,
        raw=raw_line,
        confidence=confidence,
        src_asset=host,
        dedup_hash=dedup_hash,
    )
