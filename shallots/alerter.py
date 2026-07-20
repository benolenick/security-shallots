"""Alert dispatch: webhook, email, syslog forward, SMS."""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import socket
from email.mime.text import MIMEText
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.config import AlertingConfig

log = logging.getLogger(__name__)



def _hdr_safe(value: str) -> str:
    """Collapse CR/LF (header-injection / notification-suppression vectors) to spaces."""
    return str(value or "").replace("\r", " ").replace("\n", " ")

class Alerter:
    """Sends escalated alerts via configured channels.

    Only fires for alerts whose verdict is 'escalate'. Channels:
    - Webhook: HTTP POST JSON payload
    - Email: async SMTP (aiosmtplib preferred, falls back to smtplib in executor)
    - Syslog forward: UDP syslog to remote host
    """

    def __init__(self, cfg: AlertingConfig):
        self._cfg = cfg
        self._session: Any = None  # aiohttp.ClientSession, created lazily

    _SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    async def send(self, alert: dict[str, Any]) -> None:
        """Dispatch an alert dict to all enabled channels.

        Only sends if the alert verdict is 'escalate'. Safe to call for
        any alert - non-escalated alerts are silently dropped.
        """
        if alert.get("verdict", "") != "escalate":
            return

        tasks: list[asyncio.Task] = []

        if self._cfg.webhook_url:
            tasks.append(asyncio.create_task(self._send_webhook(alert)))

        if self._cfg.ntfy.enabled and self._cfg.ntfy.topic:
            tasks.append(asyncio.create_task(self._send_ntfy_alert(alert)))

        if self._cfg.email.enabled and self._meets_severity(alert, self._cfg.email.min_severity):
            tasks.append(asyncio.create_task(self._send_email(alert)))

        if self._cfg.syslog.enabled and self._cfg.syslog.host:
            tasks.append(asyncio.create_task(self._send_syslog(alert)))

        if self._cfg.sms.enabled and self._meets_severity(alert, self._cfg.sms.min_severity):
            tasks.append(asyncio.create_task(self._send_sms(alert)))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, Exception):
                    log.error("Alerter channel error: %s", res)

    def _meets_severity(self, alert: dict[str, Any], min_severity: str) -> bool:
        """Check if alert severity meets or exceeds the minimum."""
        alert_sev = self._SEV_ORDER.get(alert.get("severity", "").lower(), 0)
        min_sev = self._SEV_ORDER.get(min_severity.lower(), 3)
        return alert_sev >= min_sev

    # ------------------------------------------------------------------
    # Webhook
    # ------------------------------------------------------------------

    async def _send_webhook(self, alert: dict[str, Any]) -> None:
        """POST alert JSON to the configured webhook URL."""
        try:
            import aiohttp
        except ImportError:
            log.warning("aiohttp not installed - webhook alerts disabled")
            return

        payload = self._build_webhook_payload(alert)

        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )

        try:
            async with self._session.post(
                self._cfg.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            ) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    log.warning(
                        "Webhook returned %d: %s", resp.status, body[:200]
                    )
                else:
                    log.info("Webhook sent for alert %s", alert.get("id", "?"))
        except aiohttp.ClientError as e:
            log.warning("Webhook delivery failed: %s", e)

    def _build_webhook_payload(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Build the JSON payload for the webhook POST."""
        return {
            "event": "shallots.alert.escalated",
            "alert": {
                "id": alert.get("id", ""),
                "timestamp": alert.get("timestamp", ""),
                "source": alert.get("source", ""),
                "severity": alert.get("severity", ""),
                "title": alert.get("title", ""),
                "description": alert.get("description", ""),
                "src_ip": alert.get("src_ip", ""),
                "dst_ip": alert.get("dst_ip", ""),
                "src_geo": alert.get("src_geo", ""),
                "category": alert.get("category", ""),
                "verdict": alert.get("verdict", ""),
                "confidence": alert.get("confidence", 0),
                "ai_reasoning": alert.get("ai_reasoning", ""),
            },
        }

    # ------------------------------------------------------------------
    # Email
    # ------------------------------------------------------------------

    async def _send_email(self, alert: dict[str, Any]) -> None:
        """Send alert via email, preferring aiosmtplib if available."""
        email_cfg = self._cfg.email
        subject = f"[Security Shallots] ESCALATED: {alert.get('title', 'Alert')}"
        body = self._build_email_body(alert)

        try:
            import aiosmtplib  # type: ignore
            await self._send_email_async(email_cfg, subject, body, aiosmtplib)
        except ImportError:
            # Fallback to synchronous smtplib in thread executor
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                self._send_email_sync,
                email_cfg, subject, body,
            )

    async def _send_email_async(
        self, email_cfg: Any, subject: str, body: str, aiosmtplib: Any
    ) -> None:
        """Send email using aiosmtplib."""
        msg = MIMEText(body, "plain")
        msg["Subject"] = _hdr_safe(subject)  # prevent SMTP header injection via title
        msg["From"] = email_cfg.from_addr
        msg["To"] = email_cfg.to_addr

        kwargs: dict[str, Any] = {
            "hostname": email_cfg.smtp_host,
            "port": email_cfg.smtp_port,
        }
        if email_cfg.smtp_port == 465:
            kwargs["use_tls"] = True
        elif email_cfg.smtp_port == 587:
            kwargs["start_tls"] = True
        if email_cfg.smtp_username and email_cfg.smtp_password:
            kwargs["username"] = email_cfg.smtp_username
            kwargs["password"] = email_cfg.smtp_password
        try:
            await aiosmtplib.send(msg, **kwargs)
            log.info("Email alert sent to %s", email_cfg.to_addr)
        except Exception as e:
            log.warning("aiosmtplib send failed: %s", e)
            raise

    def _send_email_sync(self, email_cfg: Any, subject: str, body: str) -> None:
        """Send email using stdlib smtplib (runs in executor)."""
        msg = MIMEText(body, "plain")
        msg["Subject"] = subject
        msg["From"] = email_cfg.from_addr
        msg["To"] = email_cfg.to_addr

        try:
            if email_cfg.smtp_port == 465:
                smtp_cls = smtplib.SMTP_SSL
            else:
                smtp_cls = smtplib.SMTP
            with smtp_cls(email_cfg.smtp_host, email_cfg.smtp_port, timeout=15) as smtp:
                if email_cfg.smtp_port == 587:
                    smtp.starttls()
                if email_cfg.smtp_username and email_cfg.smtp_password:
                    smtp.login(email_cfg.smtp_username, email_cfg.smtp_password)
                smtp.sendmail(email_cfg.from_addr, [email_cfg.to_addr], msg.as_string())
            log.info("Email alert sent (sync) to %s", email_cfg.to_addr)
        except smtplib.SMTPException as e:
            log.warning("smtplib send failed: %s", e)
            raise

    def _build_email_body(self, alert: dict[str, Any]) -> str:
        """Build plain-text email body from alert dict."""
        lines = [
            "Security Shallots - Escalated Alert",
            "=" * 40,
            f"Title:       {alert.get('title', '')}",
            f"Severity:    {alert.get('severity', '')}",
            f"Source:      {alert.get('source', '')}",
            f"Timestamp:   {alert.get('timestamp', '')}",
            f"Src IP:      {alert.get('src_ip', '')}",
            f"Dst IP:      {alert.get('dst_ip', '')}",
            f"Src Geo:     {alert.get('src_geo', '')}",
            f"Category:    {alert.get('category', '')}",
            "",
            "AI Verdict:",
            f"  Verdict:    {alert.get('verdict', '')}",
            f"  Confidence: {alert.get('confidence', 0):.0%}",
            f"  Reasoning:  {alert.get('ai_reasoning', '')}",
            "",
            "Description:",
            alert.get("description", ""),
            "",
            "Alert ID: " + alert.get("id", ""),
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Syslog forward
    # ------------------------------------------------------------------

    async def _send_syslog(self, alert: dict[str, Any]) -> None:
        """Forward alert as a syslog UDP message to remote host."""
        syslog_cfg = self._cfg.syslog
        host = syslog_cfg.host
        port = syslog_cfg.port

        # RFC 3164 syslog message: <PRI>HEADER MSG
        # Priority: facility=1 (user) severity=2 (critical) → 1*8+2 = 10
        priority = 10  # user.critical
        message = (
            f"<{priority}>shallots: ESCALATED [{alert.get('severity', '').upper()}] "
            f"{alert.get('title', '')} src={alert.get('src_ip', '')} "
            f"dst={alert.get('dst_ip', '')} verdict={alert.get('verdict', '')} "
            f"id={alert.get('id', '')}"
        )

        encoded = message.encode("utf-8", errors="replace")[:1024]

        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                None, self._udp_send, host, port, encoded
            )
            log.debug("Syslog forwarded to %s:%d", host, port)
        except Exception as e:
            log.warning("Syslog forward failed to %s:%d: %s", host, port, e)

    @staticmethod
    def _udp_send(host: str, port: int, data: bytes) -> None:
        """Send a UDP datagram (called in executor)."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(data, (host, port))

    # ------------------------------------------------------------------
    # SMS (Twilio)
    # ------------------------------------------------------------------

    async def _send_sms(self, alert: dict[str, Any]) -> None:
        """Send alert via Twilio SMS."""
        sms_cfg = self._cfg.sms
        body = (
            f"[Shallots] {alert.get('severity', '').upper()}: "
            f"{alert.get('title', 'Alert')}\n"
            f"src={alert.get('src_ip', '')} dst={alert.get('dst_ip', '')}\n"
            f"verdict={alert.get('verdict', '')} "
            f"confidence={alert.get('confidence', 0):.0%}"
        )
        # Twilio SMS max 1600 chars
        body = body[:1600]

        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                None, self._twilio_send, sms_cfg, body
            )
            log.info("SMS alert sent to %s", sms_cfg.to_number)
        except Exception as e:
            log.warning("SMS send failed: %s", e)

    @staticmethod
    def _twilio_send(sms_cfg: Any, body: str) -> None:
        """Send SMS via Twilio REST API (called in executor)."""
        import base64
        from urllib import error, request

        from urllib.parse import urlencode
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sms_cfg.twilio_account_sid}/Messages.json"
        # MUST url-encode: raw '&'/'='/newlines in an alert title otherwise inject
        # Twilio parameters or silently truncate the SMS body.
        data = urlencode({
            "To": sms_cfg.to_number,
            "From": sms_cfg.from_number,
            "Body": body,
        }).encode("utf-8")

        credentials = base64.b64encode(
            f"{sms_cfg.twilio_account_sid}:{sms_cfg.twilio_auth_token}".encode()
        ).decode()

        req = request.Request(url, data=data, method="POST", headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        })
        try:
            with request.urlopen(req, timeout=10) as resp:
                if resp.status >= 400:
                    raise RuntimeError(f"Twilio returned {resp.status}")
        except error.HTTPError as e:
            raise RuntimeError(f"Twilio HTTP {e.code}: {e.read().decode()[:200]}") from e

    # ------------------------------------------------------------------
    # ntfy.sh
    # ------------------------------------------------------------------

    async def _send_ntfy_alert(self, alert: dict[str, Any]) -> None:
        """POST alert to ntfy.sh (or self-hosted ntfy server)."""
        await self._ntfy_push(
            title=f"[Shallots] {alert.get('title', 'Alert')}",
            message=(
                f"Severity: {alert.get('severity', '?').upper()}\n"
                f"Src: {alert.get('src_ip', '?')} → Dst: {alert.get('dst_ip', '?')}\n"
                f"{alert.get('ai_reasoning', '')[:200]}"
            ),
            priority="high" if alert.get("severity", "") in ("high", "critical") else "default",
            tags=["rotating_light", alert.get("category", "security")],
        )

    async def notify_incident(self, incident: dict[str, Any]) -> None:
        """Send notification for a new act_now incident via all enabled channels."""
        tasks: list[asyncio.Task] = []

        title = incident.get("title", "Incident")
        summary = incident.get("summary", "")[:300]
        urgency = incident.get("urgency", "check")

        if self._cfg.ntfy.enabled and self._cfg.ntfy.topic:
            tasks.append(asyncio.create_task(self._ntfy_push(
                title=f"[Shallots ACT NOW] {title}",
                message=summary,
                priority="urgent" if urgency == "act_now" else "high",
                tags=["rotating_light", "skull"],
            )))

        if self._cfg.webhook_url:
            payload = {
                "event": "shallots.incident.act_now",
                "incident": {
                    "id": incident.get("id", ""),
                    "title": title,
                    "urgency": urgency,
                    "summary": summary,
                    "affected_ips": incident.get("affected_ips", []),
                    "alert_count": incident.get("alert_count", 0),
                },
            }
            tasks.append(asyncio.create_task(self._post_json(self._cfg.webhook_url, payload)))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, Exception):
                    log.error("Incident notifier channel error: %s", res)

    async def _ntfy_push(
        self,
        title: str,
        message: str,
        priority: str = "default",
        tags: list[str] | None = None,
    ) -> None:
        """Push a notification to ntfy.sh or a self-hosted ntfy server."""
        ntfy_cfg = self._cfg.ntfy
        url = f"{ntfy_cfg.server.rstrip('/')}/{ntfy_cfg.topic}"

        try:
            import aiohttp
        except ImportError:
            log.warning("aiohttp not installed - ntfy notifications disabled")
            return

        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )

        headers: dict[str, str] = {
            # Strip CR/LF/non-ASCII: attacker-controlled titles otherwise raise
            # ValueError in the HTTP layer and the notification silently fails.
            "Title": _hdr_safe(title)[:250],
            "Priority": priority,
            "Content-Type": "text/plain",
        }
        if tags:
            headers["Tags"] = ",".join(_hdr_safe(t) for t in tags)
        if ntfy_cfg.token:
            headers["Authorization"] = f"Bearer {ntfy_cfg.token}"

        try:
            async with self._session.post(url, data=message.encode(), headers=headers) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    log.warning("ntfy returned %d: %s", resp.status, body[:200])
                else:
                    log.info("ntfy notification sent to %s/%s", ntfy_cfg.server, ntfy_cfg.topic)
        except aiohttp.ClientError as e:
            log.warning("ntfy delivery failed: %s", e)

    async def _post_json(self, url: str, payload: dict[str, Any]) -> None:
        """POST arbitrary JSON payload to a URL."""
        try:
            import aiohttp
        except ImportError:
            return

        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )

        try:
            async with self._session.post(url, json=payload) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    log.warning("Webhook POST returned %d: %s", resp.status, body[:200])
        except aiohttp.ClientError as e:
            log.warning("Webhook POST failed: %s", e)

    async def send_squawk(self, title: str, detail: str, severity: str) -> None:
        """Send a squawk notification via SMS (if configured)."""
        if not self._cfg.sms.enabled:
            return
        body = (
            f"[Shallots SQUAWK] {severity.upper()}: {title}\n"
            f"{detail[:200]}"
        )[:1600]
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._twilio_send, self._cfg.sms, body)
            log.info("Squawk SMS sent to %s", self._cfg.sms.to_number)
        except Exception as e:
            log.warning("Squawk SMS failed: %s", e)

    async def close(self) -> None:
        """Clean up resources (call on shutdown)."""
        if self._session and not self._session.closed:
            await self._session.close()
