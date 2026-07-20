"""WebSocket handler for live alert streaming."""

from __future__ import annotations

import asyncio
import json
import logging

from aiohttp import WSMsgType, web

log = logging.getLogger(__name__)

# Keepalive interval in seconds
_PING_INTERVAL = 20


async def handle_ws_alerts(request: web.Request) -> web.WebSocketResponse:
    """GET /ws/alerts - live alert stream via WebSocket.

    Protocol:
        server → client  {"type": "alert",   "data": <alert dict>}
        server → client  {"type": "ping",    "ts": <unix ms>}
        client → server  {"type": "pong"}   (optional, browser auto-pongs)
        client → server  {"type": "ping"}   (optional client-initiated ping)
        server → client  {"type": "connected", "ws_clients": N}  on open
    """
    daemon = request.app["daemon"]
    ws = web.WebSocketResponse(heartbeat=_PING_INTERVAL, autoping=True)
    await ws.prepare(request)

    # Register this client
    daemon.ws_clients.add(ws)
    client_addr = request.remote
    log.info("WebSocket client connected from %s (total=%d)", client_addr, len(daemon.ws_clients))

    # Send welcome message with current client count
    try:
        await ws.send_str(json.dumps({
            "type": "connected",
            "ws_clients": len(daemon.ws_clients),
        }))
    except Exception:
        pass

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    msg_type = data.get("type", "")
                    if msg_type == "ping":
                        await ws.send_str(json.dumps({"type": "pong"}))
                    # Other client messages are silently ignored
                except json.JSONDecodeError:
                    pass  # Ignore malformed messages
            elif msg.type == WSMsgType.ERROR:
                log.debug(
                    "WebSocket error from %s: %s",
                    client_addr,
                    ws.exception(),
                )
                break
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED):
                break
    except asyncio.CancelledError:
        pass
    except Exception:
        log.exception("WebSocket handler error for %s", client_addr)
    finally:
        daemon.ws_clients.discard(ws)
        log.info(
            "WebSocket client disconnected from %s (remaining=%d)",
            client_addr,
            len(daemon.ws_clients),
        )

    return ws


def setup_ws_routes(app: web.Application) -> None:
    """Register WebSocket routes on the app."""
    app.router.add_get("/ws/alerts", handle_ws_alerts)
