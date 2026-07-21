"""Main asyncio daemon - orchestrates all components."""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shallots.config import Config

log = logging.getLogger(__name__)

_NON_PROD_AGENT_PREFIXES = ("shallot-load-", "shallot-experiment", "shallot-auth-boundary", "tls-smoke")

# alert_pipeline health check thresholds: a queue backing up past this depth
# with no successful insert in this long is unambiguous (real backlog); an
# empty/low queue with no recent insert just means a quiet network, not a
# stall, so both conditions must hold before this fails.
_PIPELINE_STALL_QUEUE_DEPTH = 50
_PIPELINE_STALL_SECONDS = 120


def _pipeline_stall_check(qdepth: int, stalled_sec: float) -> tuple[bool, str]:
    ok = not (qdepth > _PIPELINE_STALL_QUEUE_DEPTH and stalled_sec > _PIPELINE_STALL_SECONDS)
    return ok, f"queue_depth={qdepth}, last_insert={int(stalled_sec)}s ago"


class Daemon:
    """Central daemon that starts ingestors, pipeline, AI workers, and web server."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._shutdown = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        # Shared alert queue: ingestors → pipeline → storage/AI
        # Smaller queue on low-memory systems to cap RAM usage
        queue_size = 2000 if cfg.threat_engine.tier == "pi" else 10000
        self.alert_queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self._dropped_alerts: int = 0
        # Set at startup (not left at 0) so source_health_worker doesn't see a
        # false "stalled" reading before the first alert has ever arrived.
        self._last_alert_insert_at: float = time.time()
        # Custom rules cache
        self._custom_rules_cache: list = []
        self._custom_rules_cache_ts: float = 0.0
        # WebSocket broadcast set (filled by web module)
        self.ws_clients: set = set()
        # Track agents that have already triggered an offline alert (dedup)
        self._offline_alerted: set[str] = set()

    def _apply_silence_rule_to_classifier(
        self, match_type: str, pattern: str, pattern2: str = ""
    ) -> None:
        """Hot-load a silence rule into the live classifier."""
        if not hasattr(self, "classifier"):
            return

        import ipaddress as _ipaddress
        import re as _re

        if match_type == "title":
            existing = [p.pattern for p in self.classifier._suppress_patterns]
            if pattern not in existing:
                self.classifier._suppress_patterns.append(
                    _re.compile(pattern, _re.IGNORECASE)
                )
        elif match_type == "sig_id":
            try:
                self.classifier._cfg.suppress_sig_ids.add(int(pattern))
            except (ValueError, TypeError):
                pass
        elif match_type == "src_ip":
            self.classifier._cfg.suppress_source_ips.add(pattern)
        elif match_type == "dst_ip":
            self.classifier._cfg.suppress_dest_ips.add(pattern)
        elif match_type == "dst_cidr":
            try:
                net = _ipaddress.ip_network(pattern, strict=False)
                existing = [str(n) for n in self.classifier._cfg.suppress_dest_cidrs]
                if str(net) not in existing:
                    self.classifier._cfg.suppress_dest_cidrs.append(net)
            except ValueError:
                pass
        elif match_type == "src_cidr":
            try:
                net = _ipaddress.ip_network(pattern, strict=False)
                existing = [str(n) for n in self.classifier._cfg.suppress_source_cidrs]
                if str(net) not in existing:
                    self.classifier._cfg.suppress_source_cidrs.append(net)
            except ValueError:
                pass
        elif match_type == "src_ip+title" and pattern and pattern2:
            combo = (pattern, pattern2)
            if combo not in self.classifier._combo_rules:
                self.classifier._combo_rules.append(combo)

    async def run(self) -> None:
        """Start all components and run until shutdown."""
        te = self.cfg.threat_engine
        log.info("Security Shallots starting (profile=%s, ai=%s, threat_tier=%s)",
                 self.cfg.profile, self.cfg.ai.tier, te.tier)
        log.info("Threat engine auto-config: baselines=%s, graph=%s, ml=%s, killchain=%s, "
                 "correlator_interval=%ds, ml_retrain=%ds, graph_max=%d",
                 te.baselines, te.graph, te.ml_detector, te.killchain,
                 te.correlator_interval_sec, te.ml_retrain_sec, te.graph_max_nodes)

        # Set up signal handlers
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._shutdown.set)
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                pass

        # Initialize storage
        from shallots.store.db import AlertDB
        self.db = AlertDB(self.cfg.storage.db_path)
        await self.db.connect()
        log.info("Database connected: %s", self.cfg.storage.db_path)

        # Seed knowledge base on first run
        await self._seed_knowledge()

        # Seed default silence rules (self-traffic, internal noise)
        await self._seed_silence_rules()

        # Initialize clusterer and backfill existing alerts
        from shallots.ai.clusterer import AlertClusterer
        self._clusterer = AlertClusterer(self.db)
        backfilled = await self._clusterer.backfill()
        if backfilled:
            log.info("Cluster backfill: assigned %d existing alerts", backfilled)

        # Start components
        await self._start_ingestors()
        self._tasks.append(asyncio.create_task(self._pipeline_worker()))

        if self.cfg.ai.tier != "none":
            await self._start_ai_workers()
        else:
            # No-AI / Pi mode (ai.tier: none): the triage worker still runs, but in
            # rule-based-only mode - TriageWorker.run() creates NO Ollama client when
            # tier=none and routes every batch through _triage_rule_based(). Without
            # this, pending alerts got no verdict and rotted forever. Nothing here
            # calls an LLM, so this works on a Pi with no GPU.
            await self._start_ai_workers()
            # Autopilot cluster sweep also runs (no AI triage) - deterministic only.
            from shallots.ai.autopilot import AutopilotWorker
            self._autopilot = AutopilotWorker(
                self.cfg.ai,
                self.db,
                ws_broadcast=self._ws_broadcast,
                on_silence_rule_created=self._apply_silence_rule_to_classifier,
            )
            self._tasks.append(asyncio.create_task(
                self._autopilot.run(self._shutdown)
            ))
            log.info("No-AI mode: rule-based triage + autopilot cluster sweep, no LLM (mode=%s)", self.cfg.ai.autopilot.mode)

        if self.cfg.scout.enabled:
            await self._start_scout_worker()

        # Start correlator (works with or without AI)
        # Pass suppression IPs + auto-detected server IP as infra IPs
        from shallots.ai.correlator import Correlator
        infra_ips = set(self.cfg.suppression.source_ips)
        if hasattr(self, '_own_ip') and self._own_ip:
            infra_ips.add(self._own_ip)
        self._correlator = Correlator(self.cfg.ai, self.db, infra_ips=infra_ips or None)
        await self._correlator.start()

        # Start threat engine modules independently (each is optional)
        # Modules are enabled/disabled + tuned by auto-detected hardware tier
        te = self.cfg.threat_engine

        if te.baselines:
            try:
                from shallots.ai.baselines import BaselineEngine
                self._baselines = BaselineEngine(
                    self.db,
                    rebuild_interval_sec=te.baseline_rebuild_sec,
                    window_days=te.baseline_window_days,
                )
                await self._baselines.start()
                self._correlator._baselines = self._baselines
                log.info("Threat engine: baselines started (rebuild=%ds, window=%dd)",
                         te.baseline_rebuild_sec, te.baseline_window_days)
            except Exception:
                log.debug("Threat engine: baselines not available")
        else:
            log.info("Threat engine: baselines disabled (tier=%s)", te.tier)

        if te.graph:
            try:
                from shallots.ai.graph_engine import NetworkGraph
                self._graph = NetworkGraph(self.db, max_nodes=te.graph_max_nodes)
                await self._graph.start()
                self._correlator._graph = self._graph
                log.info("Threat engine: network graph started (max_nodes=%d)", te.graph_max_nodes)
            except Exception:
                log.exception("Threat engine: graph failed to start")
        else:
            log.info("Threat engine: graph disabled (tier=%s)", te.tier)

        if te.ml_detector:
            try:
                from shallots.ai.ml_detector import MLDetectorEngine
                self._ml_detector = MLDetectorEngine(
                    self.db,
                    baselines=getattr(self, '_baselines', None),
                    retrain_interval_sec=te.ml_retrain_sec,
                    training_samples=te.ml_training_samples,
                )
                await self._ml_detector.start()
                self._correlator._ml_detector = self._ml_detector
                log.info("Threat engine: ML detector started (retrain=%ds, samples=%d)",
                         te.ml_retrain_sec, te.ml_training_samples)
            except Exception:
                log.debug("Threat engine: ML detector not available")
        else:
            log.info("Threat engine: ML detector disabled (tier=%s)", te.tier)

        if te.killchain:
            try:
                from shallots.ai.killchain import KillChainDetector
                self._killchain = KillChainDetector()
                self._correlator._killchain = self._killchain
                log.info("Threat engine: kill chain detector started")
            except Exception:
                log.debug("Threat engine: kill chain not available")
        else:
            log.info("Threat engine: kill chain disabled (tier=%s)", te.tier)

        # Start incident worker
        from shallots.ai.incidents import IncidentWorker
        from shallots.alerter import Alerter as _Alerter
        _incident_alerter = _Alerter(self.cfg.alerting)
        self._alerter = _incident_alerter
        self._incident_worker = IncidentWorker(
            self.cfg.ai, self.db, ws_broadcast=self._ws_broadcast,
            alerter=_incident_alerter,
        )
        self._tasks.append(asyncio.create_task(
            self._incident_worker.run(self._shutdown)
        ))

        await self._start_web()

        # Start remote shipper if configured
        if self.cfg.storage.elasticsearch_url or self.cfg.storage.victorialogs_url:
            from shallots.store.shipper import Shipper
            shipper = Shipper(self.cfg.storage, self.db)
            self._tasks.append(asyncio.create_task(shipper.run(self._shutdown)))
            log.info("Remote shipper started")

        if (self.cfg.alerting.webhook_url or self.cfg.alerting.email.enabled
                or self.cfg.alerting.sms.enabled or self.cfg.alerting.ntfy.enabled
                or self.cfg.alerting.syslog.enabled):
            self._tasks.append(asyncio.create_task(self._alerter_worker()))

        # IP reputation background worker
        any_reputation = (
            (self.cfg.virustotal.enabled and self.cfg.virustotal.ip_lookup_enabled)
            or self.cfg.abuseipdb.enabled
            or self.cfg.shodan.enabled
            or self.cfg.greynoise.enabled
        )
        if any_reputation:
            self._tasks.append(asyncio.create_task(self._reputation_worker()))
            log.info("IP reputation worker started (vt=%s, abuseipdb=%s, shodan=%s, greynoise=%s)",
                     self.cfg.virustotal.ip_lookup_enabled,
                     self.cfg.abuseipdb.enabled,
                     self.cfg.shodan.enabled,
                     self.cfg.greynoise.enabled)

        # Agent health monitoring
        if self.cfg.agent_monitor.enabled:
            self._tasks.append(asyncio.create_task(self._agent_health_worker()))
            log.info("Agent health worker started (check every %ds, offline after %ds)",
                     self.cfg.agent_monitor.check_interval_sec,
                     self.cfg.agent_monitor.offline_after_sec)

        # Clove agent stale-heartbeat alerting (only if agent monitoring is on)
        if self.cfg.agent_monitor.enabled:
            self._tasks.append(asyncio.create_task(self._stale_agent_worker()))
            log.info("Stale clove-agent worker started (check every 5min)")
            # Argus agents live in `agent_status`, not `agent_heartbeats`, so
            # _stale_agent_worker above won't see them. agent_watchdog covers
            # that gap and persists cooldown in DB so it survives restarts.
            self._tasks.append(asyncio.create_task(self._argus_watchdog_worker()))
            log.info("Argus watchdog worker started (check every 10min)")

        # Data-source health: file-growth/reachability checks that already
        # existed as a manual CLI command, now run automatically and alert
        # (LOW/suppressed, operational signal) when a source goes silent.
        self._tasks.append(asyncio.create_task(self._source_health_worker()))
        log.info("Source health watchdog started (check every 10min)")

        # Sigma rule engine
        if self.cfg.sigma.enabled and self.cfg.sigma.rules_dir:
            try:
                from shallots.sigma_engine import SigmaEngine
                self._sigma_engine = SigmaEngine(self.cfg.sigma.rules_dir)
                count = self._sigma_engine.load_rules()
                if count:
                    log.info("Sigma engine loaded %d rules from %s", count, self.cfg.sigma.rules_dir)
                    # Persist to DB
                    for rule in self._sigma_engine.rules:
                        await self.db.upsert_sigma_rule({
                            "id": rule.id, "title": rule.title, "level": rule.level,
                            "category": rule.logsource_category,
                            "description": rule.description,
                            "tags": rule.tags, "filename": rule.filename,
                        })
            except Exception:
                log.exception("Failed to load Sigma rules")

        # TLS certificate monitoring
        if self.cfg.tls_monitor.enabled and self.cfg.tls_monitor.targets:
            from shallots.tls_monitor import TlsCertWorker
            self._tls_worker = TlsCertWorker(self.cfg.tls_monitor, self.db)
            self._tasks.append(asyncio.create_task(
                self._tls_worker.run(self._shutdown)
            ))
            log.info("TLS cert monitor started (%d targets)",
                     len(self.cfg.tls_monitor.targets))

        # IoC feed ingestion
        if self.cfg.ioc_feeds.enabled:
            from shallots.ioc_feeds import IocFeedWorker
            self._ioc_worker = IocFeedWorker(self.cfg.ioc_feeds, self.db)
            self._tasks.append(asyncio.create_task(
                self._ioc_worker.run(self._shutdown)
            ))
            log.info("IoC feed worker started (%d feeds)",
                     len(self._ioc_worker._feeds))

        # Periodic DB retention cleanup
        self._tasks.append(asyncio.create_task(self._retention_worker()))

        # Scheduled email reports (daily digest)
        if self.cfg.alerting.email.enabled:
            self._tasks.append(asyncio.create_task(self._scheduled_report_worker()))
            log.info("Scheduled email report worker started")

        stats = await self.db.get_stats()
        log.info("Ready. %d alerts in database.", stats["total_alerts"])

        # Wait for shutdown
        await self._shutdown.wait()
        log.info("Shutdown signal received")
        await self._cleanup()

    async def _start_ingestors(self) -> None:
        """Start enabled ingestors."""
        # Shared queue for pfSense filterlog lines routed from syslog
        pfsense_queue: asyncio.Queue | None = None
        if self.cfg.pfsense.enabled and self.cfg.syslog.enabled:
            pfsense_queue = asyncio.Queue(maxsize=5000)

        if self.cfg.components.suricata:
            from shallots.ingest.eve import EveIngestor
            flow_detector = None
            if getattr(self.cfg.suricata, "flow_scan", True):
                from shallots.ingest.flow_scan import FlowScanDetector
                ignore = set(getattr(self.cfg.suppression, "source_ips", []) or [])
                flow_detector = FlowScanDetector(
                    home_net=getattr(self.cfg.suricata, "home_net", "192.168.0.0/16"),
                    ignore_src=ignore,
                )
                log.info("Flow-scan detector enabled (fan-out port-scan/host-sweep, ignore_src=%d)", len(ignore))
            ingestor = EveIngestor(self.cfg.suricata, self.alert_queue, flow_detector=flow_detector)
            self._tasks.append(asyncio.create_task(ingestor.run()))
            log.info("Suricata EVE ingestor started: %s", self.cfg.suricata.eve_path)

        if self.cfg.components.wazuh:
            from shallots.ingest.wazuh import WazuhIngestor
            ingestor = WazuhIngestor(self.cfg.wazuh, self.alert_queue)
            self._tasks.append(asyncio.create_task(ingestor.run()))
            log.info("Wazuh ingestor started: %s", self.cfg.wazuh.alerts_path)

        if self.cfg.components.crowdsec:
            from shallots.ingest.crowdsec import CrowdSecIngestor
            ingestor = CrowdSecIngestor(self.cfg.crowdsec, self.alert_queue)
            self._tasks.append(asyncio.create_task(ingestor.run()))
            log.info("CrowdSec ingestor started")

        if self.cfg.execmon.enabled:
            from shallots.ingest.execlog import ExecLogIngestor
            self._execlog = ExecLogIngestor(self.cfg.execmon, self.alert_queue)
            self._tasks.append(asyncio.create_task(self._execlog.run()))
            log.info("ExecLog (command execution) ingestor started: %s", self.cfg.execmon.audit_log_path)

        if self.cfg.syslog.enabled:
            from shallots.ingest.syslog_receiver import SyslogReceiver
            receiver = SyslogReceiver(self.cfg.syslog, self.alert_queue, pfsense_queue)
            self._tasks.append(asyncio.create_task(receiver.run()))
            log.info("Syslog receiver started on UDP:%d TCP:%d",
                     self.cfg.syslog.udp_port, self.cfg.syslog.tcp_port)

        if self.cfg.pfsense.enabled:
            from shallots.ingest.pfsense import PfSenseIngestor
            self._pfsense_ingestor = PfSenseIngestor(
                self.cfg.pfsense, self.cfg.syslog, self.alert_queue, pfsense_queue
            )
            self._tasks.append(asyncio.create_task(self._pfsense_ingestor.run()))
            log.info("pfSense ingestor started")
            # DHCP lease history persistence
            if self.cfg.pfsense.api_url:
                self._tasks.append(asyncio.create_task(self._dhcp_history_worker()))

        if self.cfg.pihole.enabled and self.cfg.pihole.api_url:
            from shallots.ingest.pihole import PiHoleIngestor
            ingestor = PiHoleIngestor(self.cfg.pihole, self.alert_queue)
            self._tasks.append(asyncio.create_task(ingestor.run()))
            log.info("Pi-hole ingestor started")

        if self.cfg.pihole.dns_enabled:
            from shallots.ingest.pihole_dns import PiholeDnsIngestor
            self._pihole_dns = PiholeDnsIngestor(self.cfg.pihole, self.db, self.alert_queue)
            self._tasks.append(asyncio.create_task(self._pihole_dns.run(self._shutdown)))
            log.info("Pi-hole DNS detector started: %s", self.cfg.pihole.db_path)

        if self.cfg.components.argus:
            from shallots.ingest.argus import ArgusIngestor
            ingestor = ArgusIngestor(self.cfg.argus, self.alert_queue, daemon=self)
            self._tasks.append(asyncio.create_task(ingestor.run()))
            log.info("Argus ingestor started (jsonl=%s, webhook=%s)",
                     self.cfg.argus.jsonl_dir or "off",
                     f"port {self.cfg.argus.webhook_port}" if self.cfg.argus.webhook_enabled else "off")

        if self.cfg.components.webapp and self.cfg.webapp.enabled:
            from shallots.ingest.webapp import WebAppIngestor
            ingestor = WebAppIngestor(self.cfg.webapp, self.alert_queue)
            self._tasks.append(asyncio.create_task(ingestor.run()))
            log.info("WebApp ingestor started: %s (%d log files)",
                     self.cfg.webapp.app_name, len(self.cfg.webapp.log_paths))

    async def _pipeline_worker(self) -> None:
        """Process alerts from queue: normalize → dedup → enrich → classify → store."""
        from shallots.pipeline.normalizer import normalize
        from shallots.pipeline.dedup import Deduplicator
        from shallots.pipeline.classifier import Classifier

        dedup = Deduplicator()
        classifier = Classifier.from_config(self.cfg)
        self.classifier = classifier  # expose for silence rule reload
        home_cidr = self.cfg.network.home_cidr if self.cfg.network else ""

        # Load user silence rules from DB
        try:
            rules = await self.db.get_silence_rules()
            self._silence_rules = rules
            for rule in rules:
                self._apply_silence_rule_to_classifier(
                    rule["match_type"],
                    rule["pattern"],
                    rule.get("pattern2", ""),
                )
            if rules:
                log.info("Loaded %d user silence rules from DB", len(rules))
        except Exception:
            pass

        while not self._shutdown.is_set():
            try:
                alert = await asyncio.wait_for(self.alert_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            try:
                alert = normalize(alert)
                if dedup.is_duplicate(alert):
                    continue

                # Enrich if enricher is available
                try:
                    from shallots.pipeline.enricher import enrich
                    alert = await enrich(alert, self.cfg)
                except ImportError:
                    pass

                # Classify (suppression + severity adjustment)
                alert = classifier.classify(alert, home_cidr)

                # Apply custom detection rules
                if alert.verdict != 'suppress':
                    try:
                        alert = await self._apply_custom_rules(alert)
                    except Exception:
                        pass

                # Apply Sigma rules (if engine loaded)
                if alert.verdict != 'suppress' and hasattr(self, '_sigma_engine'):
                    try:
                        alert = await self._apply_sigma_rules(alert)
                    except Exception:
                        pass

                # Check IoC feeds
                if alert.verdict != 'suppress' and hasattr(self, '_ioc_worker'):
                    try:
                        alert = await self._apply_ioc_check(alert)
                    except Exception:
                        pass

                # Store
                await self.db.insert_alert(alert)
                self._last_alert_insert_at = time.time()

                # Auto-discover assets from alert IPs
                try:
                    if alert.src_ip:
                        await self.db.upsert_asset(
                            ip=alert.src_ip,
                            hostname=alert.src_dns or alert.src_asset or "",
                        )
                        await self.db.increment_asset_alerts(alert.src_ip)
                    if alert.dst_ip:
                        await self.db.upsert_asset(
                            ip=alert.dst_ip,
                            hostname=alert.dst_dns or alert.dst_asset or "",
                        )
                except Exception:
                    pass

                # Feed to network graph
                if hasattr(self, '_graph'):
                    try:
                        self._graph.ingest_alert(alert.to_dict())
                    except Exception:
                        pass

                # Assign to cluster
                if hasattr(self, '_clusterer'):
                    try:
                        await self._clusterer.assign(alert)
                    except Exception:
                        log.debug("Cluster assignment failed for alert %s", alert.id)

                # Broadcast to WebSocket clients
                if self.ws_clients:
                    import json
                    msg = json.dumps({"type": "alert", "data": alert.to_dict()})
                    dead = set()
                    for ws in self.ws_clients:
                        try:
                            await ws.send_str(msg)
                        except Exception:
                            dead.add(ws)
                    self.ws_clients -= dead

            except Exception:
                log.exception("Pipeline error processing alert")

    async def _start_ai_workers(self) -> None:
        """Start AI triage worker and autopilot."""
        from shallots.ai.triage import TriageWorker
        worker = TriageWorker(self.cfg.ai, self.db)
        self._triage_worker = worker
        self._tasks.append(asyncio.create_task(worker.run(self._shutdown)))
        log.info("AI triage worker started (tier=%s)", self.cfg.ai.tier)

        # Start autopilot worker (runs in any mode including 'off' - just idles)
        from shallots.ai.autopilot import AutopilotWorker
        self._autopilot = AutopilotWorker(
            self.cfg.ai,
            self.db,
            ws_broadcast=self._ws_broadcast,
            on_silence_rule_created=self._apply_silence_rule_to_classifier,
        )
        self._tasks.append(asyncio.create_task(
            self._autopilot.run(self._shutdown)
        ))
        log.info("AI autopilot started (mode=%s)", self.cfg.ai.autopilot.mode)

    async def _start_scout_worker(self) -> None:
        """Start non-judgmental edge scout worker."""
        from shallots.ai.scout import ScoutWorker
        worker = ScoutWorker(self.cfg.scout, self.db, repo_root=Path.cwd())
        self._scout_worker = worker
        self._tasks.append(asyncio.create_task(worker.run(self._shutdown)))
        log.info("Edge scout worker started (model=%s)", self.cfg.scout.model)

    async def _ws_broadcast(self, msg: dict) -> None:
        """Broadcast a JSON message to all connected WebSocket clients."""
        if not self.ws_clients:
            return
        import json
        payload = json.dumps(msg)
        dead = set()
        for ws in self.ws_clients:
            try:
                await ws.send_str(payload)
            except Exception:
                dead.add(ws)
        self.ws_clients -= dead

    async def _start_web(self) -> None:
        """Start the web dashboard."""
        from shallots.web.app import create_app
        from aiohttp import web

        app = create_app(self)
        runner = web.AppRunner(app)
        await runner.setup()

        ssl_ctx = None
        scheme = "http"
        if self.cfg.web.tls_cert and self.cfg.web.tls_key:
            import ssl
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(self.cfg.web.tls_cert, self.cfg.web.tls_key)
            scheme = "https"

        site = web.TCPSite(runner, self.cfg.web.host, self.cfg.web.port, ssl_context=ssl_ctx)
        await site.start()
        self._web_runner = runner
        log.info("Web dashboard: %s://%s:%d", scheme, self.cfg.web.host, self.cfg.web.port)

    async def _alerter_worker(self) -> None:
        """Watch for escalated alerts and send notifications (rate-limited)."""
        from shallots.alerter import Alerter
        alerter = Alerter(self.cfg.alerting)
        from datetime import datetime, timezone
        last_check = datetime.now(timezone.utc).isoformat()

        # Rate limiting: per-signature AND global cap
        _rate_window = {}  # sig_id → [timestamps]
        _global_window = []  # all notification timestamps
        _MAX_PER_SIG = 3
        _MAX_GLOBAL = 10      # max 10 emails per window total
        _WINDOW_SEC = 3600    # 1 hour window

        while not self._shutdown.is_set():
            await asyncio.sleep(10)
            try:
                alerts = await self.db.get_alerts(limit=20, verdict="escalate")
                now = datetime.now(timezone.utc)

                # Prune global window
                _global_window = [
                    t for t in _global_window
                    if (now - t).total_seconds() < _WINDOW_SEC
                ]

                for a in alerts:
                    if a["ingested_at"] > last_check:
                        # Skip if alert is already suppressed
                        if a.get("verdict") == "suppress":
                            continue

                        # Skip alerts from our own server (self-traffic noise)
                        src_ip = a.get("src_ip", "")
                        if src_ip and hasattr(self, '_own_ip') and src_ip == self._own_ip:
                            continue

                        # Global rate limit
                        if len(_global_window) >= _MAX_GLOBAL:
                            log.debug("Global rate limit hit, skipping notification")
                            continue

                        # Per-signature rate limit
                        rate_key = str(a.get("signature_id") or a.get("title", ""))
                        if rate_key not in _rate_window:
                            _rate_window[rate_key] = []
                        _rate_window[rate_key] = [
                            t for t in _rate_window[rate_key]
                            if (now - t).total_seconds() < _WINDOW_SEC
                        ]
                        if len(_rate_window[rate_key]) < _MAX_PER_SIG:
                            await alerter.send(a)
                            _rate_window[rate_key].append(now)
                            _global_window.append(now)
                        else:
                            log.debug("Rate-limited notification for %s", rate_key)
                if alerts:
                    newest = max(a["ingested_at"] for a in alerts)
                    if newest > last_check:
                        last_check = newest
            except Exception:
                log.exception("Alerter error")

    async def _reputation_worker(self) -> None:
        """Background IP reputation enrichment. Runs continuously.

        Queries up to 4 sources per IP:
          1. VirusTotal (4/min, needs API key)
          2. AbuseIPDB (1000/day, needs API key)
          3. Shodan InternetDB (free, no key, no documented rate limit)
          4. GreyNoise Community (50/day, needs API key)
        """
        from shallots.pipeline.enricher import (
            is_private, vt_ip_lookup, abuseipdb_lookup,
            shodan_internetdb_lookup, greynoise_lookup,
        )
        from shallots.store.models import now_iso
        from datetime import datetime, timezone, timedelta
        import json

        vt_enabled = self.cfg.virustotal.enabled and self.cfg.virustotal.ip_lookup_enabled
        vt_key = self.cfg.virustotal.api_key if vt_enabled else ""
        abuse_enabled = self.cfg.abuseipdb.enabled
        abuse_key = self.cfg.abuseipdb.api_key if abuse_enabled else ""
        shodan_enabled = self.cfg.shodan.enabled
        greynoise_enabled = self.cfg.greynoise.enabled
        greynoise_key = self.cfg.greynoise.api_key if greynoise_enabled else ""

        # Budget tracking for AbuseIPDB (1000/day)
        abuse_daily_count = 0
        abuse_day_start = datetime.now(timezone.utc).date()

        # Initial delay to let the pipeline populate some alerts first
        await asyncio.sleep(30)

        while not self._shutdown.is_set():
            try:
                ips = await self.db.get_ips_needing_reputation(limit=50)

                # Filter out private IPs
                ips = [ip for ip in ips if not is_private(ip)]

                if not ips:
                    await asyncio.sleep(60)
                    continue

                for ip in ips:
                    if self._shutdown.is_set():
                        break

                    result = {}
                    now = datetime.now(timezone.utc)

                    # ── Shodan InternetDB (free, fast, no key) ──
                    if shodan_enabled:
                        shodan_data = await shodan_internetdb_lookup(ip)
                        if shodan_data:
                            try:
                                existing = json.loads(result.get("details", "{}"))
                                existing["shodan"] = shodan_data
                                result["details"] = json.dumps(existing)
                            except (json.JSONDecodeError, TypeError):
                                result["details"] = json.dumps({"shodan": shodan_data})
                            # Shodan vulns contribute to verdict
                            if shodan_data.get("vulns"):
                                result.setdefault("shodan_vulns", len(shodan_data["vulns"]))
                            if shodan_data.get("ports"):
                                result.setdefault("shodan_ports", shodan_data["ports"])

                    # ── GreyNoise Community (50/day, needs key) ──
                    if greynoise_enabled and greynoise_key:
                        gn_data = await greynoise_lookup(ip, greynoise_key)
                        if gn_data:
                            try:
                                existing = json.loads(result.get("details", "{}"))
                                existing["greynoise"] = gn_data
                                result["details"] = json.dumps(existing)
                            except (json.JSONDecodeError, TypeError):
                                result["details"] = json.dumps({"greynoise": gn_data})
                            result["greynoise_classification"] = gn_data.get("classification", "unknown")
                            result["greynoise_noise"] = gn_data.get("noise", False)

                    # ── VirusTotal: 4 req/min = 1 every 15s ──
                    if vt_enabled and vt_key:
                        vt_result = await vt_ip_lookup(ip, vt_key)
                        if vt_result:
                            result.update(vt_result)
                        await asyncio.sleep(15)  # respect 4/min rate limit

                    # ── AbuseIPDB: 1000/day ──
                    today = now.date()
                    if today != abuse_day_start:
                        abuse_daily_count = 0
                        abuse_day_start = today

                    if abuse_enabled and abuse_key and abuse_daily_count < 1000:
                        abuse_result = await abuseipdb_lookup(ip, abuse_key)
                        if abuse_result:
                            if abuse_result.get("abuse_score", 0) > 0:
                                result["abuse_score"] = abuse_result["abuse_score"]
                            if not result.get("country") and abuse_result.get("country"):
                                result["country"] = abuse_result["country"]
                            if not result.get("isp") and abuse_result.get("isp"):
                                result["isp"] = abuse_result["isp"]
                            try:
                                existing = json.loads(result.get("details", "{}"))
                                abuse_details = json.loads(abuse_result.get("details", "{}"))
                                existing["abuseipdb"] = abuse_details
                                result["details"] = json.dumps(existing)
                            except (json.JSONDecodeError, TypeError):
                                pass
                        abuse_daily_count += 1

                    if not result:
                        result = {"verdict": "unknown"}

                    # ── Composite verdict (all sources contribute) ──
                    vt_mal = result.get("vt_malicious", 0)
                    abuse_score = result.get("abuse_score", 0)
                    gn_class = result.get("greynoise_classification", "")
                    shodan_vuln_count = result.get("shodan_vulns", 0)

                    if (vt_mal > 3 or abuse_score > 50
                            or gn_class == "malicious"):
                        result["verdict"] = "malicious"
                    elif (vt_mal > 0 or abuse_score > 20
                          or result.get("vt_suspicious", 0) > 0
                          or shodan_vuln_count > 3
                          or gn_class == "unknown" and result.get("greynoise_noise")):
                        result["verdict"] = "suspicious"
                    elif gn_class == "benign" or result.get("vt_total", 0) > 0 or abuse_score == 0:
                        result["verdict"] = "clean"

                    # Expiry: 6h for malicious, 24h for clean
                    if result.get("verdict") == "malicious":
                        expires = now + timedelta(hours=6)
                    else:
                        expires = now + timedelta(hours=24)

                    result["checked_at"] = now.isoformat()
                    result["expires_at"] = expires.isoformat()

                    await self.db.upsert_ip_reputation(ip, result)
                    log.debug("IP reputation: %s → %s (sources: VT=%s Abuse=%s Shodan=%s GN=%s)",
                              ip, result.get("verdict", "unknown"),
                              "yes" if vt_enabled else "off",
                              "yes" if abuse_enabled else "off",
                              "yes" if shodan_enabled else "off",
                              "yes" if greynoise_enabled else "off")

                log.info("Reputation worker: processed %d IPs", len(ips))

            except Exception:
                log.exception("Reputation worker error")

            # Sleep before next batch
            await asyncio.sleep(30)

    async def _agent_health_worker(self) -> None:
        """Monitor agent heartbeats, transition status, inject alerts for offline agents."""
        from shallots.store.models import Alert, AlertSource, now_iso
        from datetime import datetime, timezone

        cfg = self.cfg.agent_monitor
        interval = cfg.check_interval_sec

        while not self._shutdown.is_set():
            await asyncio.sleep(interval)
            try:
                agents = await self.db.get_agents()
                now = datetime.now(timezone.utc)

                for agent in agents:
                    hb = agent.get("last_heartbeat")
                    if not hb:
                        continue

                    try:
                        last = datetime.fromisoformat(hb.replace("Z", "+00:00"))
                        if last.tzinfo is None:
                            last = last.replace(tzinfo=timezone.utc)
                        age = (now - last).total_seconds()
                    except (ValueError, TypeError):
                        continue

                    name = agent["agent_name"]
                    if name.startswith(_NON_PROD_AGENT_PREFIXES):
                        continue
                    status = agent.get("status", "offline")

                    if age > cfg.offline_after_sec and status != "offline":
                        await self.db.update_agent_status(name, "offline")
                        # Only inject alert on first offline transition (dedup)
                        if name not in self._offline_alerted:
                            self._offline_alerted.add(name)
                            await self.db.update_agent_alert_count(name)
                            alert = Alert(
                                timestamp=now_iso(),
                                source=AlertSource.ARGUS,
                                source_ref="agent_offline",
                                severity="critical",
                                title=f"Agent offline: {name}",
                                description=f"Agent '{name}' ({agent.get('agent_type', 'unknown')}) "
                                            f"has not sent a heartbeat in {int(age)}s. "
                                            f"Last IP: {agent.get('ip', 'unknown')}",
                                src_asset=name,
                                src_ip=agent.get("ip", ""),
                                category="agent_health",
                                signature_id=999001,
                                verdict="escalate",
                                confidence=1.0,
                            )
                            try:
                                self.alert_queue.put_nowait(alert)
                            except asyncio.QueueFull:
                                self._dropped_alerts += 1
                                log.warning("Alert queue full, dropping agent offline alert for %s", name)
                            log.warning("Agent offline: %s (no heartbeat for %ds)", name, int(age))

                    elif age > cfg.degraded_after_sec and status == "online":
                        await self.db.update_agent_status(name, "degraded")
                        log.info("Agent degraded: %s (heartbeat age %ds)", name, int(age))

                    elif age <= cfg.degraded_after_sec and status != "online":
                        await self.db.update_agent_status(name, "online")
                        # Clear dedup flag on recovery
                        self._offline_alerted.discard(name)
                        log.info("Agent recovered: %s", name)

            except Exception:
                log.exception("Agent health worker error")

    async def _argus_watchdog_worker(self) -> None:
        """Detect Argus agents (in agent_status) that have stopped heartbeating.

        Complements _stale_agent_worker which only covers Clove (agent_heartbeats).
        Uses shallots.agent_watchdog with a DB-backed cooldown table so a single
        offline agent fires once per 6h, not on every poll.
        """
        from shallots import agent_watchdog
        from shallots.store.db import SQLITE_BUSY_TIMEOUT_MS, SQLITE_TIMEOUT_SECONDS
        from shallots.store.models import Alert as _Alert  # noqa: F401

        # Open a sync connection on the same DB. We do this lazily once.
        import sqlite3
        conn = sqlite3.connect(self.db.db_path, timeout=SQLITE_TIMEOUT_SECONDS)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        agent_watchdog.ensure_state_table(conn)

        while not self._shutdown.is_set():
            try:
                await asyncio.sleep(600)  # 10 minutes
            except asyncio.CancelledError:
                break
            try:
                # Filter to argus rows only; clove is handled by _stale_agent_worker
                offline = [
                    a for a in agent_watchdog.detect_offline_agents(conn)
                    if a.kind.lower() == "argus" and not a.name.startswith(_NON_PROD_AGENT_PREFIXES)
                ]
                if not offline:
                    continue
                alerts = agent_watchdog.offline_alerts_to_emit(conn, offline)
                for alert in alerts:
                    await self.db.insert_alert(alert)
                    log.warning(
                        "Argus watchdog: agent %s offline %dm - alert emitted",
                        alert.source_ref, int(alert.raw and 0 or 0),  # noqa
                    )
            except Exception:
                log.exception("Argus watchdog error")

    async def _source_health_worker(self) -> None:
        """Run health.check_all() periodically and alert (LOW/suppressed) on
        any failing check, same cooldown-plus-auto-recover pattern as the
        Argus watchdog above. check_all() already existed - it was only ever
        invoked by hand from the CLI, so a source going silent (Suricata,
        Wazuh, Pi-hole, execmon, CrowdSec, disk/RAM) was invisible unless
        someone happened to run `shallotctl health`.
        """
        from shallots import health, source_watchdog
        from shallots.store.db import SQLITE_BUSY_TIMEOUT_MS, SQLITE_TIMEOUT_SECONDS

        import sqlite3
        conn = sqlite3.connect(self.db.db_path, timeout=SQLITE_TIMEOUT_SECONDS)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        source_watchdog.ensure_state_table(conn)

        # Give ingestors a chance to start producing data before the first check.
        await asyncio.sleep(120)
        while not self._shutdown.is_set():
            try:
                results = await health.check_all(self.cfg)

                # Detect a stalled pipeline: every ingestor shares one queue
                # feeding one serial DB-writer (_pipeline_worker). If that
                # writer stalls (e.g. SQLite lock contention), every source
                # backs up behind it in lockstep with zero visible symptom -
                # the dashboard and /api/health stay fully responsive the
                # whole time. Caught live on 2026-07-21: 22+ minutes with
                # zero new alerts from any source. A high queue depth with
                # no recent successful insert is unambiguous; an empty
                # queue with no recent insert just means a quiet network.
                qdepth = self.alert_queue.qsize()
                stalled_sec = time.time() - self._last_alert_insert_at
                results.append((
                    "alert_pipeline",
                    *_pipeline_stall_check(qdepth, stalled_sec),
                ))

                alerts = source_watchdog.results_to_alerts(conn, results)
                for alert in alerts:
                    await self.db.insert_alert(alert)
                    log.warning("Source watchdog: %s - alert emitted", alert.source_ref)
            except Exception:
                log.exception("Source health watchdog error")
            try:
                await asyncio.sleep(600)  # 10 minutes
            except asyncio.CancelledError:
                break

    async def _stale_agent_worker(self) -> None:
        """Check for stale clove agents every 5 minutes and inject alerts."""
        import hashlib
        from shallots.store.models import Alert, now_iso
        from datetime import datetime, timezone

        # Track which agents have already been alerted at which staleness level
        _alerted: dict[str, str] = {}  # agent_name → "stale" or "dead"

        while not self._shutdown.is_set():
            await asyncio.sleep(300)  # 5 minutes
            try:
                stale_agents = await self.db.get_stale_agents(stale_minutes=10)
                now = datetime.now(timezone.utc)

                for agent in stale_agents:
                    name = agent["agent_name"]
                    if name.startswith(_NON_PROD_AGENT_PREFIXES):
                        continue
                    try:
                        last = datetime.fromisoformat(
                            agent["last_seen"].replace("Z", "+00:00")
                        )
                        if last.tzinfo is None:
                            last = last.replace(tzinfo=timezone.utc)
                        age_min = (now - last).total_seconds() / 60
                    except (ValueError, TypeError, KeyError):
                        age_min = 999

                    if age_min > 30:
                        level = "dead"
                        severity = "critical"
                        sev_num = 4
                    else:
                        level = "stale"
                        severity = "high"
                        sev_num = 3

                    # Dedup: only alert once per agent per staleness level
                    if _alerted.get(name) == level:
                        continue
                    _alerted[name] = level

                    sig_id_str = f"{name}:stale"
                    sig_id = int(hashlib.sha256(sig_id_str.encode()).hexdigest()[:8], 16)

                    alert = Alert(
                        timestamp=now_iso(),
                        source="shallotd",
                        source_ref=f"stale_agent:{name}",
                        severity=severity,
                        title=f"Agent {name} heartbeat overdue ({int(age_min)} min)",
                        description=(
                            f"Clove agent '{name}' has not checked in for "
                            f"{int(age_min)} minutes. Last seen: {agent.get('last_seen', 'unknown')}"
                        ),
                        src_ip=agent.get("ip", ""),
                        category="agent_health",
                        signature_id=sig_id,
                        verdict="escalate",
                        confidence=1.0,
                    )
                    try:
                        self.alert_queue.put_nowait(alert)
                    except asyncio.QueueFull:
                        self._dropped_alerts += 1
                        log.warning("Alert queue full, dropping stale-agent alert for %s", name)
                    log.warning("Stale clove agent: %s (%d min, level=%s)",
                                name, int(age_min), level)

                # Clear dedup for agents that came back online
                online_names = set()
                all_agents = await self.db.get_agent_heartbeats()
                for agent in all_agents:
                    try:
                        last = datetime.fromisoformat(
                            agent["last_seen"].replace("Z", "+00:00")
                        )
                        if last.tzinfo is None:
                            last = last.replace(tzinfo=timezone.utc)
                        age_min = (now - last).total_seconds() / 60
                        if age_min <= 10:
                            online_names.add(agent["agent_name"])
                    except (ValueError, TypeError, KeyError):
                        pass
                for name in list(_alerted):
                    if name in online_names:
                        del _alerted[name]

            except Exception:
                log.exception("Stale agent worker error")

    async def _retention_worker(self) -> None:
        """Periodically delete old alerts, rotate backups, and optimize the database."""
        interval = 3600 * 6  # run every 6 hours
        max_age = self.cfg.storage.retention_days
        vacuum_counter = 0  # VACUUM every 4th run (once per day)
        while not self._shutdown.is_set():
            await asyncio.sleep(interval)
            try:
                deleted = await self.db.retention_cleanup(max_age)
                if deleted:
                    log.info("Retention cleanup: deleted %d alerts older than %dd", deleted, max_age)

                # VACUUM + optimize once per day (every 4th run at 6h interval)
                vacuum_counter += 1
                if vacuum_counter >= 4:
                    vacuum_counter = 0
                    await self.db._db.execute("PRAGMA optimize")
                    await self.db._db.execute("VACUUM")
                    await self.db._db.commit()
                    log.info("Database optimized (PRAGMA optimize + VACUUM)")

                    # Rotate old backups
                    await self._rotate_backups()
            except Exception:
                log.exception("Retention cleanup error")

    async def _rotate_backups(self) -> None:
        """Delete old backups, keeping only the N most recent."""
        max_backups = self.cfg.storage.max_backups
        if max_backups <= 0:
            return

        backup_dir = self.cfg.storage.backup_dir
        if not backup_dir:
            backup_dir = str(Path(self.cfg.storage.db_path).parent / "backups")

        bp = Path(backup_dir)
        if not bp.is_dir():
            return

        backups = sorted(bp.glob("shallots-*.db"), key=lambda f: f.stat().st_mtime, reverse=True)
        if len(backups) <= max_backups:
            return

        for old in backups[max_backups:]:
            try:
                old.unlink()
                log.info("Backup rotation: deleted %s", old.name)
            except Exception:
                log.warning("Failed to delete old backup %s", old.name)

    async def _apply_sigma_rules(self, alert) -> object:
        """Check alert against loaded Sigma rules."""
        engine = getattr(self, '_sigma_engine', None)
        if not engine or not engine.rules:
            return alert
        alert_dict = {
            "src_ip": alert.src_ip, "dst_ip": alert.dst_ip,
            "title": alert.title, "description": alert.description,
            "category": alert.category, "severity": alert.severity,
            "source": alert.source, "dst_port": str(alert.dst_port),
            "src_port": str(alert.src_port), "proto": alert.proto,
        }
        matches = engine.match(alert_dict)
        if matches:
            best = matches[0]
            sev_map = {"critical": "critical", "high": "high", "medium": "medium",
                       "low": "low", "informational": "low"}
            new_sev = sev_map.get(best.level, alert.severity)
            alert = alert._replace(
                verdict="escalate", confidence=0.85,
                severity=new_sev,
                ai_reasoning=f"Sigma rule: {best.title}",
            )
            await self.db.bump_sigma_rule_hit(best.id)
        return alert

    async def _apply_ioc_check(self, alert) -> object:
        """Check alert IPs against IoC feeds."""
        ioc = getattr(self, '_ioc_worker', None)
        if not ioc:
            return alert
        matches = await ioc.match_alert({
            "src_ip": alert.src_ip, "dst_ip": alert.dst_ip,
            "title": alert.title, "description": alert.description,
        })
        if matches:
            best = matches[0]
            alert = alert._replace(
                verdict="escalate", confidence=0.95,
                severity="critical" if alert.severity != "critical" else "critical",
                ai_reasoning=f"IoC match: {best['value']} (feed: {best['feed']})",
            )
        return alert

    async def _dhcp_history_worker(self) -> None:
        """Periodically persist DHCP leases from pfSense to history table."""
        interval = 600  # every 10 minutes
        while not self._shutdown.is_set():
            await asyncio.sleep(interval)
            try:
                pf = getattr(self, '_pfsense_ingestor', None)
                if pf and pf.assets:
                    for ip, info in pf.assets.items():
                        mac = info.get("mac", "")
                        if not mac:
                            continue
                        is_new = await self.db.upsert_dhcp_lease(
                            ip=ip, mac=mac,
                            hostname=info.get("hostname", ""),
                            interface=info.get("interface", ""),
                            lease_type=info.get("type", "dynamic"),
                        )
                        if is_new:
                            log.info("DHCP history: new IP-MAC pair %s -> %s", ip, mac)
            except Exception:
                log.exception("DHCP history worker error")

    async def _scheduled_report_worker(self) -> None:
        """Send daily email digest at 08:00 local time."""
        import datetime as _dt
        while not self._shutdown.is_set():
            # Calculate time until next 8am
            now = _dt.datetime.now()
            next_8am = now.replace(hour=8, minute=0, second=0, microsecond=0)
            if now >= next_8am:
                next_8am += _dt.timedelta(days=1)
            wait_seconds = (next_8am - now).total_seconds()
            log.info("Scheduled report: next send in %.0f hours", wait_seconds / 3600)

            # Wait (but check shutdown every 60s)
            waited = 0
            while waited < wait_seconds and not self._shutdown.is_set():
                await asyncio.sleep(min(60, wait_seconds - waited))
                waited += 60

            if self._shutdown.is_set():
                return

            try:
                summary = await self.db.get_report_summary(hours=24)
                alerter = getattr(self, '_alerter', None)
                if not alerter:
                    continue

                email_cfg = alerter._cfg.email
                if not email_cfg.enabled:
                    continue

                lines = [
                    "Security Shallots - Daily Report",
                    "=" * 40,
                    f"Period: last 24 hours",
                    f"Total new alerts: {summary['total_alerts']}",
                    f"Escalated: {summary['escalated']}",
                    f"New incidents: {summary['new_incidents']}",
                    f"Unique source IPs: {summary['unique_src_ips']}",
                    "",
                    "Severity breakdown:",
                ]
                for sev, count in summary.get("by_severity", {}).items():
                    lines.append(f"  {sev}: {count}")
                lines.append("")
                lines.append("Top alerts:")
                for item in summary.get("top_alerts", [])[:10]:
                    lines.append(f"  [{item['count']}x] {item['title']}")

                body_text = "\n".join(lines)
                subject = f"[Security Shallots] Daily Report - {summary['total_alerts']} alerts"

                try:
                    import aiosmtplib
                    await alerter._send_email_async(email_cfg, subject, body_text, aiosmtplib)
                except ImportError:
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(
                        None, alerter._send_email_sync, email_cfg, subject, body_text
                    )
                log.info("Daily report sent to %s", email_cfg.to_addr)
            except Exception:
                log.exception("Scheduled report error")

    async def _seed_knowledge(self) -> None:
        """Load and seed the netsec knowledge base on first run."""
        try:
            import json as _json
            # Try multiple possible locations for the seed file
            candidates = [
                Path(__file__).parent / "data" / "netsec_knowledge.json",
                Path(".") / "shallots" / "data" / "netsec_knowledge.json",
            ]
            seed_path = None
            for p in candidates:
                if p.exists():
                    seed_path = p
                    break
            if not seed_path:
                log.debug("Knowledge seed file not found, skipping")
                return
            facts = _json.loads(seed_path.read_text(encoding="utf-8"))
            count = await self.db.seed_knowledge(facts, version="1")
            if count:
                log.info("Seeded %d knowledge base facts from %s", count, seed_path.name)
            else:
                log.debug("Knowledge base already seeded")
        except Exception:
            log.exception("Failed to seed knowledge base")

    async def _apply_custom_rules(self, alert) -> object:
        """Check alert against custom detection rules, apply actions."""
        if not hasattr(self, '_custom_rules_cache') or not self._custom_rules_cache_ts:
            self._custom_rules_cache = []
            self._custom_rules_cache_ts = 0

        # Reload rules every 60s
        import time as _time
        now = _time.time()
        if now - self._custom_rules_cache_ts > 60:
            self._custom_rules_cache = await self.db.get_custom_rules(enabled_only=True)
            self._custom_rules_cache_ts = now

        alert_dict = {
            "src_ip": alert.src_ip, "dst_ip": alert.dst_ip,
            "title": alert.title, "description": alert.description,
            "category": alert.category, "severity": alert.severity,
            "source": alert.source, "dst_port": str(alert.dst_port),
            "src_port": str(alert.src_port), "proto": alert.proto,
        }

        for rule in self._custom_rules_cache:
            if self.db.match_custom_rule(rule, alert_dict):
                action = rule.get("action", "escalate")
                if action == "escalate":
                    alert = alert._replace(verdict="escalate", confidence=0.9,
                                           ai_reasoning=f"Custom rule: {rule['name']}")
                elif action == "investigate":
                    alert = alert._replace(verdict="investigate", confidence=0.8,
                                           ai_reasoning=f"Custom rule: {rule['name']}")
                elif action == "suppress":
                    alert = alert._replace(verdict="suppress", confidence=1.0,
                                           ai_reasoning=f"Custom rule: {rule['name']}")
                if rule.get("severity_override"):
                    alert = alert._replace(severity=rule["severity_override"])
                # Bump hit count async (fire and forget)
                await self.db.bump_custom_rule_hit(rule["id"])
                break  # First matching rule wins
        return alert

    async def _seed_silence_rules(self) -> None:
        """Seed default silence rules on first run to suppress known self-traffic noise.

        Prevents the platform from alerting on its own dashboard access,
        internal protocol anomalies between known hosts, and common
        Suricata stream noise from legitimate internal traffic.
        """
        try:
            existing = await self.db.get_silence_rules()
            # Check if we already seeded (look for our marker reason)
            if any(r.get("reason", "").startswith("[auto-seed]") for r in existing):
                return

            home_cidr = self.cfg.network.home_cidr if self.cfg.network else ""
            web_port = self.cfg.web.port if self.cfg.web else 8844

            # Detect our own IP and store for alerter filtering
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                my_ip = s.getsockname()[0]
                s.close()
            except Exception:
                my_ip = ""
            self._own_ip = my_ip

            rules = [
                # Internal Suricata stream noise (very common false positives)
                {"match_type": "title", "pattern": "SURICATA STREAM reassembly overlap with different data",
                 "reason": "[auto-seed] Common Suricata stream reassembly noise on internal networks"},
                {"match_type": "title", "pattern": "SURICATA STREAM Packet with invalid timestamp",
                 "reason": "[auto-seed] TCP timestamp noise between internal hosts"},
                {"match_type": "title", "pattern": "SURICATA STREAM 3way handshake wrong seq wrong ack",
                 "reason": "[auto-seed] TCP handshake anomaly noise"},
                {"match_type": "title", "pattern": "SURICATA STREAM ESTABLISHED packet out of window",
                 "reason": "[auto-seed] Common TCP window noise"},
                {"match_type": "title", "pattern": "SURICATA STREAM CLOSEWAIT FIN out of window",
                 "reason": "[auto-seed] TCP close noise"},
            ]

            # If we know our IP, suppress self-originated protocol noise
            if my_ip:
                rules.extend([
                    {"match_type": "src_ip+title", "pattern": my_ip,
                     "pattern2": "Protocol anomaly: applayer",
                     "reason": f"[auto-seed] Shallots server ({my_ip}) internal protocol noise"},
                    {"match_type": "src_ip+title", "pattern": my_ip,
                     "pattern2": "SURICATA Applayer Wrong direction",
                     "reason": f"[auto-seed] Shallots server ({my_ip}) applayer direction noise"},
                    {"match_type": "src_ip+title", "pattern": my_ip,
                     "pattern2": "SURICATA HTTP Request excessive header",
                     "reason": f"[auto-seed] Shallots server ({my_ip}) HTTP header noise from API calls"},
                    {"match_type": "src_ip+title", "pattern": my_ip,
                     "pattern2": "SHALLOTS Internal port scan",
                     "reason": f"[auto-seed] Shallots server ({my_ip}) health checks misidentified as scan"},
                ])

            # Suppress internal-to-internal protocol noise for home CIDR
            if home_cidr:
                rules.extend([
                    {"match_type": "title", "pattern": "SURICATA Applayer Wrong direction first Data",
                     "reason": "[auto-seed] Common applayer direction noise on home networks"},
                    {"match_type": "title", "pattern": "SURICATA HTTP Request line incomplete",
                     "reason": "[auto-seed] Partial HTTP request noise from keepalive connections"},
                ])

            count = 0
            for rule in rules:
                await self.db.add_silence_rule(
                    match_type=rule["match_type"],
                    pattern=rule["pattern"],
                    reason=rule["reason"],
                    pattern2=rule.get("pattern2", ""),
                )
                count += 1

            if count:
                log.info("Seeded %d default silence rules for self-traffic noise", count)

        except Exception:
            log.exception("Failed to seed silence rules")

    async def _cleanup(self) -> None:
        """Clean shutdown of all components."""
        if hasattr(self, "_correlator"):
            await self._correlator.stop()

        # Stop threat engine modules
        if hasattr(self, '_ml_detector'):
            try:
                await self._ml_detector.stop()
            except Exception:
                pass
        if hasattr(self, '_graph'):
            try:
                await self._graph.stop()
            except Exception:
                pass
        if hasattr(self, '_baselines'):
            try:
                await self._baselines.stop()
            except Exception:
                pass

        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

        if hasattr(self, "_web_runner"):
            await self._web_runner.cleanup()

        await self.db.close()
        log.info("Shutdown complete")
