"""TLS certificate monitoring worker."""

from __future__ import annotations

import asyncio
import logging
import ssl
import uuid
from datetime import datetime, timezone

from shallots.config import TlsMonitorConfig
from shallots.store.db import AlertDB
from shallots.store.models import now_iso

log = logging.getLogger(__name__)


class TlsCertWorker:
    """Periodically checks TLS certificates on configured targets."""

    def __init__(self, cfg: TlsMonitorConfig, db: AlertDB):
        self.cfg = cfg
        self.db = db

    async def run(self, shutdown: asyncio.Event) -> None:
        """Loop that checks all targets every check_interval_hours."""
        interval = self.cfg.check_interval_hours * 3600
        while not shutdown.is_set():
            for target in self.cfg.targets:
                if shutdown.is_set():
                    break
                try:
                    host, port = self._parse_target(target)
                    cert_data = await self._check_cert(host, port)
                    cert_data["id"] = str(uuid.uuid4())
                    await self.db.upsert_tls_cert(host, port, cert_data)

                    days = cert_data.get("days_remaining", 0)
                    if days <= self.cfg.warn_days:
                        log.warning(
                            "TLS cert for %s:%d expires in %d days (notAfter=%s)",
                            host, port, days, cert_data.get("not_after", ""),
                        )
                except Exception:
                    log.exception("TLS check failed for %s", target)

            # Wait for next interval, but wake on shutdown
            try:
                await asyncio.wait_for(shutdown.wait(), timeout=interval)
                break  # shutdown was set
            except asyncio.TimeoutError:
                pass

    async def _check_cert(self, host: str, port: int) -> dict:
        """Connect via TLS and extract certificate details."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert(binary_form=False)
            if cert is None:
                # binary_form=True fallback for DER parsing
                import ssl as _ssl
                der = ssl_obj.getpeercert(binary_form=True)
                # Use openssl-style parsing if available
                cert_pem = _ssl.DER_cert_to_PEM_cert(der)
                # Reconnect with verify to get parsed cert
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                r2, w2 = await asyncio.open_connection(host, port, ssl=ctx2)
                ssl_obj2 = w2.get_extra_info("ssl_object")
                cert = ssl_obj2.getpeercert(binary_form=False) or {}
                w2.close()
                await w2.wait_closed()
        finally:
            writer.close()
            await writer.wait_closed()

        subject_parts = dict(x[0] for x in cert.get("subject", ()))
        issuer_parts = dict(x[0] for x in cert.get("issuer", ()))

        subject = subject_parts.get("commonName", "")
        issuer = issuer_parts.get("commonName", "")
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        serial = cert.get("serialNumber", "")

        # Calculate days remaining
        days_remaining = -1
        if not_after:
            try:
                # Python ssl module returns dates like "Jan  5 09:33:00 2025 GMT"
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                delta = expiry - datetime.now(timezone.utc)
                days_remaining = delta.days
            except (ValueError, TypeError):
                pass

        status = "ok"
        if days_remaining < 0:
            status = "expired"
        elif days_remaining <= self.cfg.warn_days:
            status = "warning"

        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "serial": serial,
            "days_remaining": days_remaining,
            "status": status,
            "last_checked": now_iso(),
        }

    @staticmethod
    def _parse_target(target: str) -> tuple[str, int]:
        """Parse 'host:port' string. Default port is 443."""
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            return host, int(port_str)
        return target, 443
