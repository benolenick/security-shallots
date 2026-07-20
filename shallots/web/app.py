"""aiohttp application factory for Security Shallots web dashboard."""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import secrets
from typing import TYPE_CHECKING

from aiohttp import web
from aiohttp.web import middleware

if TYPE_CHECKING:
    from shallots.daemon import Daemon

log = logging.getLogger(__name__)


def _make_auth_middleware(username: str, password: str):
    """Create a basic auth middleware for the given credentials."""
    expected = base64.b64encode(f"{username}:{password}".encode()).decode()

    @middleware
    async def auth_middleware(request: web.Request, handler) -> web.Response:
        # Allow health and agent-guide endpoints without auth
        if request.path in ("/api/health", "/api/agent-guide", "/api/heartbeat", "/api/ingest/clove", "/api/ingest/argus"):
            return await handler(request)

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            token = auth_header[6:]
            if secrets.compare_digest(token, expected):
                return await handler(request)

        return web.Response(
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="Security Shallots"'},
            content_type="application/json",
            body=json.dumps({"error": "Authentication required"}),
        )

    return auth_middleware


def _host_only(host: str) -> str:
    """Strip an optional :port from a Host header value (IPv4/IPv6/hostname)."""
    host = (host or "").strip()
    if host.startswith("["):                      # [::1] or [::1]:8844
        return host[1:host.index("]")] if "]" in host else host[1:]
    if host.count(":") == 1:                       # ipv4/hostname:port
        return host.rsplit(":", 1)[0]
    return host                                    # bare ipv6 or no port


def _make_host_guard(allowed_hostnames: set[str]):
    """Reject requests whose Host header is an unexpected DOMAIN NAME.

    This defeats DNS-rebinding: an attacker's page (served from evil.com, rebound
    to 127.0.0.1) sends Host: evil.com, which is not in the allowlist. Direct
    access by IP (loopback or LAN IP) always carries an IP-literal Host, which
    cannot be a rebinding attack, so those pass. Hostnames must be allow-listed
    via web.allowed_hosts (e.g. a reverse-proxy domain)."""
    allowed = {h.lower() for h in allowed_hostnames} | {"localhost"}

    @middleware
    async def host_guard(request: web.Request, handler) -> web.Response:
        raw = request.headers.get("Host", "")
        if not raw:                                # no Host = not a browser rebind
            return await handler(request)
        host = _host_only(raw).lower()
        try:
            ipaddress.ip_address(host)             # any IP-literal Host is safe
            return await handler(request)
        except ValueError:
            pass
        if host in allowed:
            return await handler(request)
        return web.Response(
            status=403, content_type="application/json",
            body=json.dumps({"error": "Host not allowed", "host": host}),
        )

    return host_guard


@middleware
async def cors_middleware(request: web.Request, handler) -> web.Response:
    """Same-origin dashboard: no cross-origin access is granted. Preflight is
    answered without Access-Control-Allow-Origin so browsers block cross-site
    API use (a security dashboard has no cross-origin callers)."""
    if request.method == "OPTIONS":
        return web.Response(status=204,
                            headers={"Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                                     "Access-Control-Allow-Headers": "Content-Type, Authorization"})
    return await handler(request)


@middleware
async def error_middleware(request: web.Request, handler) -> web.Response:
    """Convert unhandled exceptions to JSON error responses."""
    try:
        return await handler(request)
    except web.HTTPException as exc:
        return web.Response(
            status=exc.status,
            content_type="application/json",
            body=json.dumps({"error": exc.reason, "status": exc.status}),
        )
    except Exception as exc:
        log.exception("Unhandled error for %s %s", request.method, request.path)
        # Do not leak internal exception detail (paths, SQL, deps) to clients.
        return web.Response(
            status=500,
            content_type="application/json",
            body=json.dumps({"error": "Internal server error"}),
        )


def create_app(daemon: Daemon) -> web.Application:
    """Create and configure the aiohttp application.

    Args:
        daemon: The running Daemon instance, which holds db and ws_clients.

    Returns:
        Configured aiohttp Application ready to serve.
    """
    from shallots.web.api import setup_api_routes
    from shallots.web.ws import setup_ws_routes
    import pathlib

    middlewares = [cors_middleware, error_middleware]

    # Add basic auth if configured
    web_cfg = daemon.cfg.web
    has_auth = bool(web_cfg.username and web_cfg.password)
    if has_auth:
        middlewares.insert(0, _make_auth_middleware(web_cfg.username, web_cfg.password))
        log.info("Web dashboard: basic auth enabled (user=%s)", web_cfg.username)

    # Fail-safe: never expose an unauthenticated dashboard on a non-loopback
    # interface. Without credentials the API (which includes config writes,
    # firewall actions, and runbook execution) would be open to the whole LAN.
    # Refuse rather than silently exposing it — the operator must either bind to
    # loopback or set web.username/web.password.
    _LOOPBACK = {"127.0.0.1", "::1", "localhost", ""}
    if not has_auth and str(web_cfg.host) not in _LOOPBACK:
        raise RuntimeError(
            f"Refusing to start: web.host is '{web_cfg.host}' (LAN-exposed) but no "
            "web.username/web.password is set. Set credentials (and TLS) before exposing "
            "the dashboard, or bind web.host to 127.0.0.1 for local-only access. "
            "See config.example.yaml."
        )

    # DNS-rebinding guard runs first (outermost). Allow the configured bind host
    # (if it's a hostname) plus any operator-listed hostnames (reverse proxy, etc).
    allowed_hosts: set[str] = set(getattr(web_cfg, "allowed_hosts", []) or [])
    if str(web_cfg.host):
        allowed_hosts.add(str(web_cfg.host))
    middlewares.insert(0, _make_host_guard(allowed_hosts))

    app = web.Application(middlewares=middlewares)

    # Store daemon reference for route handlers
    app["daemon"] = daemon

    # Mount API and WebSocket routes
    setup_api_routes(app)
    setup_ws_routes(app)

    # Serve static files from shallots/web/static/
    static_dir = pathlib.Path(__file__).parent / "static"
    static_dir.mkdir(exist_ok=True)

    # Serve index.html at root
    async def index_handler(request: web.Request) -> web.FileResponse:
        return web.FileResponse(static_dir / "index.html")

    async def topology_handler(request: web.Request) -> web.FileResponse:
        return web.FileResponse(static_dir / "topology.html")

    async def ml_handler(request: web.Request) -> web.FileResponse:
        return web.FileResponse(static_dir / "ml.html")

    app.router.add_get("/", index_handler)
    app.router.add_get("/topology", topology_handler)
    app.router.add_get("/ml", ml_handler)
    app.router.add_static("/static", static_dir, name="static")

    log.info("Web app created, static dir: %s", static_dir)
    return app
