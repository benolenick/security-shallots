"""aiohttp application factory for Security Shallots web dashboard."""

from __future__ import annotations

import base64
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


@middleware
async def cors_middleware(request: web.Request, handler) -> web.Response:
    """Allow all origins for local dev."""
    if request.method == "OPTIONS":
        return web.Response(
            status=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
                "Access-Control-Max-Age": "86400",
            },
        )
    response = await handler(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


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
        return web.Response(
            status=500,
            content_type="application/json",
            body=json.dumps({"error": "Internal server error", "detail": str(exc)}),
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
