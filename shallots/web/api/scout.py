"""Read-only API for edge scout cards."""

from __future__ import annotations

import json

from aiohttp import web

from . import _db, _json_response


async def handle_scout_cards(request: web.Request) -> web.Response:
    """GET /api/scout/cards — recent non-judgmental scout cards."""
    qs = request.rel_url.query
    try:
        limit = min(int(qs.get("limit", 50)), 200)
    except ValueError:
        raise web.HTTPBadRequest(reason="limit must be an integer")

    status = qs.get("status") or None
    cards = await _db(request).get_scout_cards(limit=limit, status=status)
    for card in cards:
        for key in ("reasons", "extracted_json", "context_facts"):
            try:
                card[key] = json.loads(card.get(key) or "[]")
            except (TypeError, json.JSONDecodeError):
                pass
    return _json_response({"cards": cards, "limit": limit, "total": len(cards)})
