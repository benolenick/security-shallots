from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path
from typing import Awaitable

from .actions import capture_evidence, lock_workstation
from .config import ArgusConfig
from .core import (
    ArgusEvent,
    ArgusMode,
    ArgusStateMachine,
    StateStore,
    make_heartbeat_event,
    utc_now_iso,
    engage_timelock,
    is_timelocked,
    check_timelock,
    release_timelock,
    enforce_timelock,
)
from .core.updater import get_current_version, perform_update, restart_daemon
from .monitors import (
    AntiTamperConfig,
    AntiTamperMonitor,
    FileSentinelConfig,
    FileSentinelMonitor,
    PersistenceMonitor,
    PersistenceMonitorConfig,
    ProcessMonitor,
    ProcessMonitorConfig,
    SessionMonitor,
    ThreatSignal,
    WindowsEventsMonitor,
    get_idle_seconds,
    UsbMonitor,
    UsbMonitorConfig,
    DnsMonitor,
    DnsMonitorConfig,
    RegistryMonitor,
    RegistryMonitorConfig,
    ServiceMonitor,
    ServiceMonitorConfig,
    AuditPolicyMonitor,
    AuditPolicyConfig,
    FirewallMonitor,
    FirewallMonitorConfig,
    NetworkEgressMonitor,
    NetworkEgressConfig,
    PostureMonitor,
    PostureMonitorConfig,
    BrowserExtensionMonitor,
    BrowserExtensionConfig,
    WmiSubsMonitor,
    WmiSubsConfig,
    AdsMonitor,
    AdsMonitorConfig,
)
from .metering import MeteredSignalQueue, await_with_budget, disk_has_capacity, jittered_seconds
from .sinks import JsonlSink, SmsSink, SyslogSink, WebhookSink


class ArgusDaemon:
    def __init__(self, config: ArgusConfig, state_store: StateStore, config_path: str = "config.toml") -> None:
        self.config = config
        self.host = config.resolved_hostname()
        st = state_store.load()
        init_mode = ArgusMode(st.get("current_state", ArgusMode.DISARMED.value))
        self.state = ArgusStateMachine(host=self.host, initial=init_mode)
        self.state_store = state_store
        self.runtime_state = st
        self.config_path = str(Path(config_path).resolve())

        self.signal_queue: asyncio.Queue[ThreatSignal] = asyncio.Queue(
            maxsize=max(1, int(config.metering.queue_max_signals))
        )
        self.monitor_queue = MeteredSignalQueue(
            self.signal_queue,
            max_payload_bytes=config.metering.max_signal_payload_bytes,
            max_signals_per_minute=config.metering.max_signals_per_minute,
            backoff_seconds=config.metering.backoff_seconds,
            cpu_max_load_per_core=config.metering.cpu_max_load_per_core,
            reserve_severity=config.metering.reserve_severity,
        )
        self._tasks: list[asyncio.Task] = []
        self._jsonl = JsonlSink(directory=self._resolve_dir(config.jsonl.directory))
        self._webhook = WebhookSink(
            enabled=config.webhook.enabled,
            url=config.webhook.url,
            secret=config.webhook.secret,
            timeout_seconds=config.webhook.timeout_seconds,
        )
        self._syslog = SyslogSink(
            enabled=config.syslog.enabled,
            host=config.syslog.host,
            port=config.syslog.port,
            protocol=config.syslog.protocol,
        )
        self._sms = SmsSink(
            enabled=config.sms.enabled,
            account_sid=config.sms.twilio_account_sid,
            auth_token=config.sms.twilio_auth_token,
            from_number=config.sms.from_number,
            to_number=config.sms.to_number,
        )
        self._events_emitted = 0
        self._non_heartbeat_events_emitted = 0
        self._last_non_heartbeat_event_type = ""
        self._last_non_heartbeat_sent_at = ""

    def _resolve_dir(self, d: str) -> str:
        p = Path(d).expanduser()
        if p.is_absolute():
            return str(p)
        return str((Path.home() / p).resolve())

    def _persist_state(self) -> None:
        self.runtime_state["enabled"] = True
        self.runtime_state["monitor_pid"] = __import__("os").getpid()
        self.runtime_state["current_state"] = self.state.state.value
        self.state_store.mark_poll(self.runtime_state)
        self.state_store.save(self.runtime_state)

    def _create_monitor_task(self, awaitable: Awaitable[None], name: str) -> asyncio.Task:
        return asyncio.create_task(self._run_monitor(awaitable), name=name)

    async def _run_monitor(self, awaitable: Awaitable[None]) -> None:
        delay = jittered_seconds(1.0, self.config.metering.loop_jitter_percent)
        if delay > 0:
            await asyncio.sleep(delay)
        await awaitable

    def _disk_allows(self, path: str) -> bool:
        return disk_has_capacity(
            path,
            min_free_mb=self.config.metering.disk_min_free_mb,
            min_free_percent=self.config.metering.disk_min_free_percent,
        )

    async def run(self) -> None:
        if self.state.state == ArgusMode.DISARMED:
            boot = self.state.transition("arm", "daemon_start")
            if boot:
                await self._emit(boot.event)

        # Re-enforce timelock if system was rebooted while timelocked
        # (attacker tried restarting to escape — won't work)
        enforce_timelock(self.runtime_state)
        if is_timelocked(self.runtime_state):
            self.state.state = ArgusMode.LOCKDOWN
            self.state_store.save(self.runtime_state)

        self._persist_state()

        if self.config.windows_events.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    WindowsEventsMonitor(
                        poll_seconds=self.config.windows_events.poll_seconds,
                        watch_event_ids=self.config.windows_events.watch_event_ids,
                    ).start(self.monitor_queue),
                    name="monitor:windows_events",
                )
            )

        if self.config.process_monitor.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    ProcessMonitor(
                        ProcessMonitorConfig(
                            enabled=True,
                            poll_seconds=self.config.process_monitor.poll_seconds,
                            allowlist=self.config.process_monitor.allowlist,
                            denylist=self.config.process_monitor.denylist,
                            alert_on_unknown=self.config.process_monitor.alert_on_unknown,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:process",
                )
            )

        if self.config.file_sentinel.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    FileSentinelMonitor(
                        FileSentinelConfig(
                            enabled=True,
                            poll_seconds=self.config.file_sentinel.poll_seconds,
                            paths=self.config.file_sentinel.paths,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:file_sentinel",
                )
            )

        if self.config.persistence_monitor.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    PersistenceMonitor(
                        PersistenceMonitorConfig(
                            enabled=True,
                            poll_seconds=self.config.persistence_monitor.poll_seconds,
                            watch_paths=self.config.persistence_monitor.watch_paths,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:persistence",
                )
            )

        if self.config.anti_tamper.enabled:
            watch_files = [self.config_path, *self.config.anti_tamper.watch_files]
            self._tasks.append(
                self._create_monitor_task(
                    AntiTamperMonitor(
                        AntiTamperConfig(
                            enabled=True,
                            poll_seconds=self.config.anti_tamper.poll_seconds,
                            watch_files=watch_files,
                            required_tasks=self.config.anti_tamper.required_tasks,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:anti_tamper",
                )
            )

        if self.config.session_monitor.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    SessionMonitor(
                        poll_seconds=self.config.session_monitor.poll_seconds,
                        logon_types=self.config.session_monitor.logon_types,
                    ).start(self.monitor_queue),
                    name="monitor:session",
                )
            )

        if self.config.usb_monitor.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    UsbMonitor(
                        UsbMonitorConfig(
                            enabled=True,
                            poll_seconds=self.config.usb_monitor.poll_seconds,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:usb",
                )
            )

        if self.config.dns_monitor.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    DnsMonitor(
                        DnsMonitorConfig(
                            enabled=True,
                            poll_seconds=self.config.dns_monitor.poll_seconds,
                            suspicious_tlds=self.config.dns_monitor.suspicious_tlds,
                            entropy_threshold=self.config.dns_monitor.entropy_threshold,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:dns",
                )
            )

        if self.config.registry_monitor.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    RegistryMonitor(
                        RegistryMonitorConfig(
                            enabled=True,
                            poll_seconds=self.config.registry_monitor.poll_seconds,
                            watch_keys=self.config.registry_monitor.watch_keys,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:registry",
                )
            )

        if self.config.service_monitor.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    ServiceMonitor(
                        ServiceMonitorConfig(
                            enabled=True,
                            poll_seconds=self.config.service_monitor.poll_seconds,
                            suspicious_paths=self.config.service_monitor.suspicious_paths,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:service",
                )
            )

        if self.config.audit_policy.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    AuditPolicyMonitor(
                        AuditPolicyConfig(
                            enabled=True,
                            poll_seconds=self.config.audit_policy.poll_seconds,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:audit_policy",
                )
            )

        if self.config.firewall_monitor.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    FirewallMonitor(
                        FirewallMonitorConfig(
                            enabled=True,
                            poll_seconds=self.config.firewall_monitor.poll_seconds,
                            suspicious_ports=self.config.firewall_monitor.suspicious_ports,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:firewall",
                )
            )

        if self.config.network_egress.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    NetworkEgressMonitor(
                        NetworkEgressConfig(
                            enabled=True,
                            poll_seconds=self.config.network_egress.poll_seconds,
                            suspicious_ports=self.config.network_egress.suspicious_ports,
                            suspicious_processes=self.config.network_egress.suspicious_processes,
                            process_allowlist=self.config.network_egress.process_allowlist,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:network_egress",
                )
            )

        if self.config.posture_monitor.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    PostureMonitor(
                        PostureMonitorConfig(
                            enabled=True,
                            poll_seconds=self.config.posture_monitor.poll_seconds,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:posture",
                )
            )

        if self.config.browser_extensions.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    BrowserExtensionMonitor(
                        BrowserExtensionConfig(
                            enabled=True,
                            poll_seconds=self.config.browser_extensions.poll_seconds,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:browser_extensions",
                )
            )

        if self.config.wmi_subs.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    WmiSubsMonitor(
                        WmiSubsConfig(
                            enabled=True,
                            poll_seconds=self.config.wmi_subs.poll_seconds,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:wmi_subs",
                )
            )

        if self.config.ads_monitor.enabled:
            self._tasks.append(
                self._create_monitor_task(
                    AdsMonitor(
                        AdsMonitorConfig(
                            enabled=True,
                            poll_seconds=self.config.ads_monitor.poll_seconds,
                            scan_dirs=self.config.ads_monitor.scan_dirs,
                        )
                    ).start(self.monitor_queue),
                    name="monitor:ads",
                )
            )

        # Windows Defender health audit (always on when on Windows)
        import os
        if os.name == "nt":
            from .monitors.defender_health import DefenderHealthMonitor
            self._tasks.append(
                self._create_monitor_task(
                    DefenderHealthMonitor(poll_seconds=300).start(self.monitor_queue),
                    name="monitor:defender_health",
                )
            )

        self._tasks.append(asyncio.create_task(self._consume_signals(), name="consume_signals"))
        self._tasks.append(asyncio.create_task(self._heartbeat_loop(), name="heartbeat"))
        self._tasks.append(asyncio.create_task(self._inactivity_loop(), name="inactivity"))
        if self.config.timelock.enabled:
            self._tasks.append(asyncio.create_task(self._timelock_expiry_loop(), name="timelock_expiry"))

        # Supervise monitors — restart crashed ones instead of dying
        import logging
        log = logging.getLogger("argus.daemon")
        while True:
            done, _pending = await asyncio.wait(self._tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                name = task.get_name()
                exc = task.exception()
                if exc is not None:
                    # Critical tasks that should crash the daemon
                    if name in ("consume_signals", "heartbeat"):
                        raise exc
                    # Monitor crashed — log and remove, don't restart to avoid loops
                    log.error("Monitor %s crashed: %s", name, exc)
                    self._tasks.remove(task)
                else:
                    # Task completed normally (shouldn't happen for monitors)
                    self._tasks.remove(task)
            if not self._tasks:
                break

    async def _consume_signals(self) -> None:
        while True:
            signal = await self.signal_queue.get()
            try:
                await await_with_budget(
                    self._handle_signal(signal),
                    self.config.metering.cycle_time_budget_seconds,
                )
            except TimeoutError:
                await self._emit(ArgusEvent(
                    version=1,
                    source="argus",
                    timestamp=utc_now_iso(),
                    host=self.host,
                    event_type="metering_cycle_timeout",
                    severity="medium",
                    confidence=1.0,
                    state=self.state.state.value,
                    title="Argus signal cycle exceeded time budget",
                    description=f"Processing timed out for signal {signal.event_type!r}",
                    category="agent_health",
                    details={
                        "signal_event_type": signal.event_type,
                        "budget_seconds": self.config.metering.cycle_time_budget_seconds,
                    },
                ))

    async def _handle_signal(self, signal: ThreatSignal) -> None:
        await self._emit(self._event_from_signal(signal))

        if not self._should_trigger_lockdown(signal):
            return

        transition = self.state.transition("threat_detected", signal.event_type)
        if transition:
            await self._emit(transition.event)

            # Lockdown response based on mode
            mode = self.config.timelock.lockdown_mode if self.config.timelock.enabled else "passive"

            if mode == "reactive" and self.config.timelock.enabled:
                # REACTIVE: kill network + lock + timelock timer
                expiry = engage_timelock(
                    self.runtime_state,
                    self.config.timelock.duration_minutes,
                    reason=signal.event_type,
                    isolate=self.config.timelock.network_isolation,
                )
                self._sms.send(
                    f"[Argus] REACTIVE LOCKDOWN: {signal.title}. "
                    f"System isolated for {self.config.timelock.duration_minutes} min. "
                    f"Expires {expiry.strftime('%H:%M:%S UTC')}"
                )
                await self._emit(ArgusEvent(
                    version=1,
                    source="argus",
                    timestamp=utc_now_iso(),
                    host=self.host,
                    event_type="timelock_engaged",
                    severity="critical",
                    confidence=1.0,
                    state=self.state.state.value,
                    title="Reactive lockdown — system isolated",
                    description=(
                        f"All network disabled and firewall blocked for "
                        f"{self.config.timelock.duration_minutes} minutes. "
                        f"Trigger: {signal.title}"
                    ),
                    category="response",
                    details={
                        "lockdown_mode": "reactive",
                        "duration_minutes": self.config.timelock.duration_minutes,
                        "expires_utc": expiry.isoformat(),
                        "trigger": signal.event_type,
                        "network_isolation": self.config.timelock.network_isolation,
                    },
                    actions_taken=["timelock_engaged", "network_isolated", "workstation_locked"],
                ))
            else:
                # PASSIVE: alert + evidence + lock workstation, NO network kill
                if "workstation_locked" in transition.actions:
                    lock_workstation()
                self._sms.send(
                    f"[Argus] PASSIVE LOCKDOWN: {signal.title}. "
                    f"Evidence captured. Network remains active."
                )
                await self._emit(ArgusEvent(
                    version=1,
                    source="argus",
                    timestamp=utc_now_iso(),
                    host=self.host,
                    event_type="passive_lockdown",
                    severity="high",
                    confidence=1.0,
                    state=self.state.state.value,
                    title="Passive lockdown — alert mode",
                    description=(
                        f"Threat detected: {signal.title}. "
                        f"Workstation locked and evidence captured. Network remains active."
                    ),
                    category="response",
                    details={"lockdown_mode": "passive", "trigger": signal.event_type},
                    actions_taken=["workstation_locked", "evidence_capture_queued"],
                ))
            if "evidence_capture_queued" in transition.actions and self.config.evidence.enabled:
                if self._disk_allows(self.config.evidence.output_dir):
                    evidence_path = capture_evidence(
                        output_dir=self.config.evidence.output_dir,
                        recent_file_window_minutes=self.config.evidence.recent_file_window_minutes,
                    )
                    await self._emit(
                        ArgusEvent(
                            version=1,
                            source="argus",
                            timestamp=utc_now_iso(),
                            host=self.host,
                            event_type="evidence_capture",
                            severity="medium",
                            confidence=1.0,
                            state=self.state.state.value,
                            title="Forensic evidence captured",
                            description="Argus collected a forensic snapshot after LOCKDOWN",
                            category="forensics",
                            details={"evidence_path": evidence_path},
                            actions_taken=["evidence_captured"],
                        )
                    )
                else:
                    await self._emit(ArgusEvent(
                        version=1,
                        source="argus",
                        timestamp=utc_now_iso(),
                        host=self.host,
                        event_type="metering_evidence_skipped",
                        severity="medium",
                        confidence=1.0,
                        state=self.state.state.value,
                        title="Evidence capture skipped due to disk safeguard",
                        description="Argus skipped forensic evidence capture because disk free space is below the configured metering threshold",
                        category="agent_health",
                        details={
                            "output_dir": self.config.evidence.output_dir,
                            "disk_min_free_mb": self.config.metering.disk_min_free_mb,
                            "disk_min_free_percent": self.config.metering.disk_min_free_percent,
                        },
                    ))
            self._persist_state()

    def _should_trigger_lockdown(self, signal: ThreatSignal) -> bool:
        # Master kill-switch — when disabled, no auto-LOCKDOWN ever, regardless
        # of severity. Manual `argus on/off` and screen-lock hooks still work.
        if not getattr(self.config.threat_response, "lockdown_enabled", True):
            return False
        order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        min_sev = self.config.threat_response.lockdown_min_severity
        min_conf = min(1.0, max(0.0, float(self.config.threat_response.lockdown_min_confidence)))
        current = order.get(str(signal.severity).lower(), 0)
        required = order.get(str(min_sev).lower(), order["high"])
        return current >= required and float(signal.confidence) >= min_conf

    def _active_monitors(self) -> list[str]:
        """Return names of running monitor tasks."""
        names = []
        for task in self._tasks:
            if task.done():
                continue
            name = task.get_name()
            if name.startswith("monitor:"):
                names.append(name.removeprefix("monitor:"))
        return sorted(names)

    async def _heartbeat_loop(self) -> None:
        self._version = get_current_version()
        while True:
            await asyncio.sleep(
                jittered_seconds(
                    self.config.guard.heartbeat_seconds,
                    self.config.metering.loop_jitter_percent,
                )
            )
            hb = make_heartbeat_event(
                host=self.host,
                state=self.state.state.value,
                active_monitors=self._active_monitors(),
            )
            hb.details["version"] = self._version
            hb.details["telemetry"] = {
                "events_emitted": self._events_emitted,
                "non_heartbeat_events_emitted": self._non_heartbeat_events_emitted,
                "last_non_heartbeat_event_type": self._last_non_heartbeat_event_type,
                "last_non_heartbeat_sent_at": self._last_non_heartbeat_sent_at,
                "webhook_enabled": self._webhook.enabled,
                "webhook_last_ok": self._webhook.last_ok,
                "webhook_last_status": self._webhook.last_status,
                "webhook_last_error": self._webhook.last_error,
            }
            # Include timelock status in heartbeat so dashboard knows
            locked, remaining = check_timelock(self.runtime_state)
            if locked:
                hb.details["timelock_active"] = True
                hb.details["timelock_remaining_seconds"] = remaining
                hb.details["timelock_expires_utc"] = self.runtime_state.get("timelock_expires_utc")
            await self._emit(hb)
            self._persist_state()

            # Check if manager requested an update
            commands = self._webhook.last_response.get("commands", {})
            if commands.get("update"):
                await self._do_self_update()

    async def _do_self_update(self) -> None:
        """Pull latest code and restart if successful."""
        import logging
        log = logging.getLogger("argus.updater")
        log.info("Manager requested update, pulling...")

        success = await asyncio.to_thread(perform_update)
        if success:
            await self._emit(ArgusEvent(
                version=1,
                source="argus",
                timestamp=utc_now_iso(),
                host=self.host,
                event_type="agent_updated",
                severity="low",
                confidence=1.0,
                state=self.state.state.value,
                title=f"Argus self-updated from {self._version}",
                description="Agent pulled latest code and is restarting",
                category="agent_health",
                details={"old_version": self._version},
                actions_taken=["git_pull", "restart"],
            ))
            # Give the event time to send
            await asyncio.sleep(2)
            restart_daemon(self.config_path)
            # Exit current process — the restart will spawn new one
            raise SystemExit(0)
        else:
            log.error("Self-update failed, continuing with current version")

    async def _timelock_expiry_loop(self) -> None:
        """Check if timelock has expired and auto-release."""
        while True:
            await asyncio.sleep(jittered_seconds(10, self.config.metering.loop_jitter_percent))
            if not is_timelocked(self.runtime_state):
                # Check if timelock was active but just expired
                if self.runtime_state.get("timelock_active"):
                    release_timelock(self.runtime_state)
                    self.state_store.save(self.runtime_state)
                    await self._emit(ArgusEvent(
                        version=1,
                        source="argus",
                        timestamp=utc_now_iso(),
                        host=self.host,
                        event_type="timelock_released",
                        severity="medium",
                        confidence=1.0,
                        state=self.state.state.value,
                        title="TimeLock expired — network restored",
                        description="TimeLock duration elapsed. Network adapters re-enabled.",
                        category="response",
                        details={},
                        actions_taken=["timelock_released", "network_restored"],
                    ))
                continue
            # Still locked — re-enforce isolation every check
            # (in case attacker tries to re-enable adapters)
            from .actions.network_isolation import isolate_network
            isolate_network()

    async def _inactivity_loop(self) -> None:
        while True:
            await asyncio.sleep(jittered_seconds(5, self.config.metering.loop_jitter_percent))
            if self.state.state != ArgusMode.ARMED_HOME:
                continue
            idle = get_idle_seconds()
            if idle >= self.config.guard.inactivity_timeout_seconds:
                transition = self.state.transition("away_timeout", f"idle_{idle}s")
                if transition:
                    await self._emit(transition.event)
                    self._persist_state()

    def _event_from_signal(self, signal: ThreatSignal) -> ArgusEvent:
        return ArgusEvent(
            version=1,
            source="argus",
            timestamp=signal.timestamp,
            host=self.host,
            event_type=signal.event_type,
            severity=signal.severity,
            confidence=signal.confidence,
            state=self.state.state.value,
            title=signal.title,
            description=signal.description,
            category=signal.category,
            details=signal.details,
            raw=signal.raw,
        )

    def _record_emit(self, event: ArgusEvent) -> None:
        self._events_emitted += 1
        if event.event_type != "heartbeat":
            self._non_heartbeat_events_emitted += 1
            self._last_non_heartbeat_event_type = event.event_type
            self._last_non_heartbeat_sent_at = event.timestamp

    async def _emit(self, event: ArgusEvent) -> None:
        self._record_emit(event)
        if self.config.jsonl.enabled and self._disk_allows(str(self._jsonl.directory)):
            await self._jsonl.emit(event)
        await self._webhook.emit(event)
        await self._syslog.emit(event)
