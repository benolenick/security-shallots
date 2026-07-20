"""
Argus disarm HTTP listener — LAN-only, zero external dependencies.

Run standalone:
  python -m argus --config ~/.argus/config.toml listener

Endpoints:
  GET  /state         — current argus state (read from state file)
  POST /disarm        — HMAC-signed: transition to DISARMED + stop monitor daemon
  POST /arm           — HMAC-signed: start argus daemon via systemctl --user

HMAC scheme (symmetric, time-bucketed):
  bucket = unix_timestamp // 30        (30-second window)
  msg    = "{action}:{bucket}"
  token  = HMAC-SHA256(secret, msg).hexdigest()

Request body (JSON):
  {"token": "<hex>", "ts": <unix_int>}

Both current and previous buckets are accepted to handle ≤30 s clock skew.
The `ts` field is for logging only; the bucket is derived server-side from
real wall clock.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .config import load_config
from .core.disarm import clear_disarm_state
from .core.persistence import StateStore, stop_pid
from .core.state import ArgusMode

log = logging.getLogger("argus.listener")

_STATE_PATH = Path.home() / ".argus" / "state.json"


def _state_path() -> Path:
    return _STATE_PATH


def _hmac_valid(secret: str, action: str, ts: int, token: str) -> bool:
    """Accept tokens for current and previous 30 s buckets."""
    if not secret:
        return False
    bucket_now = int(time.time()) // 30
    for bucket in (bucket_now, bucket_now - 1):
        msg = f"{action}:{bucket}".encode()
        expected = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, token):
            return True
    return False


class _Handler(BaseHTTPRequestHandler):
    secret: str = ""
    config_path: str = ""

    def log_message(self, fmt: str, *args: object) -> None:
        log.info(fmt, *args)

    def _send_json(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return {}

    def _check_hmac(self, action: str) -> tuple[bool, dict]:
        body = self._read_body()
        token = str(body.get("token", ""))
        ts = int(body.get("ts", 0))
        if not token:
            return False, {"error": "missing token"}
        if not _hmac_valid(self.secret, action, ts, token):
            log.warning("HMAC verification failed for action=%s from %s", action, self.client_address)
            return False, {"error": "invalid token"}
        return True, body

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/state":
            self._send_json(404, {"error": "not found"})
            return
        try:
            ss = StateStore(str(_state_path()))
            st = ss.load()
            self._send_json(200, {
                "current_state": st.get("current_state", "UNKNOWN"),
                "enabled": st.get("enabled", False),
                "monitor_pid": st.get("monitor_pid"),
                "last_poll_utc": st.get("last_poll_utc"),
                "pin_configured": st.get("pin_hash") is not None,
                "online": bool(st.get("enabled", False)),
            })
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/disarm":
            self._handle_disarm()
        elif self.path == "/arm":
            self._handle_arm()
        else:
            self._send_json(404, {"error": "not found"})

    def _handle_disarm(self) -> None:
        ok, payload = self._check_hmac("disarm")
        if not ok:
            self._send_json(401, payload)
            return
        try:
            ss = StateStore(str(_state_path()))
            st = ss.load()
            pid = st.get("monitor_pid")
            current = st.get("current_state", "UNKNOWN")

            st["enabled"] = False
            st["current_state"] = ArgusMode.DISARMED.value
            clear_disarm_state(st)
            ss.save(st)

            if pid:
                stop_pid(pid)
                log.info("Disarmed via listener: was=%s pid=%s", current, pid)

            self._send_json(200, {
                "ok": True,
                "previous_state": current,
                "current_state": ArgusMode.DISARMED.value,
            })
        except Exception as exc:
            log.error("Disarm failed: %s", exc)
            self._send_json(500, {"error": str(exc)})

    def _handle_arm(self) -> None:
        ok, payload = self._check_hmac("arm")
        if not ok:
            self._send_json(401, payload)
            return
        try:
            result = subprocess.run(
                ["systemctl", "--user", "start", "argus.service"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                log.info("Armed via listener: systemctl start argus.service")
                self._send_json(200, {"ok": True, "message": "argus.service started"})
            else:
                log.error("arm via systemctl failed: %s", result.stderr.strip())
                self._send_json(500, {"error": result.stderr.strip() or "systemctl failed"})
        except Exception as exc:
            log.error("Arm failed: %s", exc)
            self._send_json(500, {"error": str(exc)})


def serve(config_path: str) -> None:
    cfg = load_config(config_path)
    if not cfg.listener.enabled:
        raise SystemExit("Listener is disabled in config (argus.listener.enabled = false)")
    if not cfg.listener.secret:
        raise SystemExit("No listener secret configured. Set argus.listener.secret in config.")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [argus.listener] %(levelname)s %(message)s",
    )

    _Handler.secret = cfg.listener.secret
    _Handler.config_path = config_path

    host = cfg.listener.host
    port = cfg.listener.port
    server = ThreadingHTTPServer((host, port), _Handler)
    log.info("Argus listener starting on %s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Listener stopped")
    finally:
        server.server_close()
