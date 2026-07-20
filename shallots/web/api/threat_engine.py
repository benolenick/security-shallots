"""Baselines, graph, ML, killchain, topology, reputation, IoC, sigma, TLS."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta

from aiohttp import web

from . import _json_response, _db

log = logging.getLogger(__name__)


# ── /api/reputation ─────────────────────────────────────────────────────────

async def handle_reputation(request: web.Request) -> web.Response:
    """GET /api/reputation/{ip} — get IP reputation data."""
    ip = request.match_info["ip"]
    db = _db(request)
    rep = await db.get_ip_reputation(ip)
    if rep is None:
        return _json_response({"ip": ip, "status": "not_checked"})

    # Parse details JSON for the response
    try:
        rep["details"] = json.loads(rep.get("details", "{}"))
    except (json.JSONDecodeError, TypeError):
        rep["details"] = {}

    return _json_response(rep)


async def handle_threat_intel_status(request: web.Request) -> web.Response:
    """GET /api/threat-intel — threat intelligence provider status."""
    daemon = request.app["daemon"]
    cfg = daemon.cfg

    from shallots.pipeline.enricher import (
        _greynoise_daily_count, _greynoise_day_start,
    )

    providers = [
        {
            "name": "VirusTotal",
            "type": "ip_reputation",
            "enabled": cfg.virustotal.enabled and cfg.virustotal.ip_lookup_enabled,
            "has_key": bool(cfg.virustotal.api_key),
            "rate_limit": "4/min (free tier)",
            "cost": "Free (limited) / $730/mo (premium)",
        },
        {
            "name": "AbuseIPDB",
            "type": "ip_reputation",
            "enabled": cfg.abuseipdb.enabled,
            "has_key": bool(cfg.abuseipdb.api_key),
            "rate_limit": "1,000/day (free tier)",
            "cost": "Free (limited)",
        },
        {
            "name": "Shodan InternetDB",
            "type": "port_scan_intel",
            "enabled": cfg.shodan.enabled,
            "has_key": True,  # No key needed
            "rate_limit": "None documented",
            "cost": "Free, no API key",
        },
        {
            "name": "GreyNoise",
            "type": "noise_classification",
            "enabled": cfg.greynoise.enabled,
            "has_key": bool(cfg.greynoise.api_key),
            "rate_limit": "50/day (community)",
            "cost": "Free (community) / paid (enterprise)",
            "daily_usage": _greynoise_daily_count if cfg.greynoise.enabled else 0,
        },
        {
            "name": "MaxMind GeoIP",
            "type": "geolocation",
            "enabled": True,
            "has_key": True,  # Local DB
            "rate_limit": "Unlimited (local DB)",
            "cost": "Free (GeoLite2)",
        },
    ]

    # Count IPs with reputation data
    db = _db(request)
    try:
        rep_count = await db._db.execute_fetchall(
            "SELECT verdict, COUNT(*) as cnt FROM ip_reputation GROUP BY verdict"
        )
        rep_stats = {row[0]: row[1] for row in rep_count}
    except Exception:
        rep_stats = {}

    return _json_response({
        "providers": providers,
        "reputation_stats": rep_stats,
    })


# ── Threat Engine API ──────────────────────────────────────────────────────

async def handle_baselines(request: web.Request) -> web.Response:
    """GET /api/baselines — all device behavioral profiles."""
    daemon = request.app["daemon"]
    baselines = getattr(daemon, '_baselines', None)
    if not baselines:
        try:
            rows = await daemon.db.execute_sql(
                "SELECT ip, asset_name, profile_json, baseline_updated, updated_at FROM device_baselines ORDER BY ip",
                (),
            )
            return _json_response({"baselines": [dict(r) for r in rows]})
        except Exception:
            return _json_response({"baselines": []})
    profiles = baselines.get_all_profiles()
    result = []
    for ip, profile in profiles.items():
        result.append({
            "ip": ip,
            "asset_name": profile.asset_name,
            "first_seen": profile.first_seen,
            "last_seen": profile.last_seen,
            "total_alerts": profile.total_alerts,
            "dst_port_count": len(profile.common_dst_ports),
            "dst_ip_count": len(profile.common_dst_ips),
            "category_count": len(profile.common_categories),
            "protocol_count": len(profile.protocols),
            "domain_count": len(profile.dns_domains),
            "baseline_updated": profile.baseline_updated,
        })
    result.sort(key=lambda x: x["total_alerts"], reverse=True)
    return _json_response(result)


async def handle_baseline_detail(request: web.Request) -> web.Response:
    """GET /api/baselines/{ip} — single device profile with full details."""
    ip = request.match_info["ip"]
    daemon = request.app["daemon"]
    baselines = getattr(daemon, '_baselines', None)
    if not baselines:
        return _json_response({"error": "Baselines not available"}, status=503)
    profile = baselines.get_profile(ip)
    if not profile:
        return _json_response({"error": "No baseline for this IP"}, status=404)
    from dataclasses import asdict
    return _json_response(asdict(profile))


async def handle_baseline_rebuild(request: web.Request) -> web.Response:
    """POST /api/baselines/rebuild — force baseline rebuild."""
    daemon = request.app["daemon"]
    baselines = getattr(daemon, '_baselines', None)
    if not baselines:
        return _json_response({"error": "Baselines not available"}, status=503)
    count = await baselines.rebuild()
    return _json_response({"status": "ok", "profiles_rebuilt": count})


async def handle_topology(request: web.Request) -> web.Response:
    """GET /api/topology — full network topology for visualization."""
    daemon = request.app["daemon"]
    graph = getattr(daemon, '_graph', None)
    if not graph:
        return _json_response({"error": "Graph engine not available"}, status=503)

    max_nodes = min(int(request.rel_url.query.get("max_nodes", 300)), 500)
    topology = graph.get_full_topology(max_nodes=max_nodes)

    # Enrich with agent status
    try:
        heartbeats = await daemon.db.get_agent_heartbeats()
        agents = {}
        for hb in heartbeats:
            ip = hb.get("ip", "")
            if ip:
                agents[ip] = {
                    "name": hb.get("agent_name", ""),
                    "type": hb.get("agent_type", ""),
                    "status": "online" if hb.get("last_seen", "") > (
                        datetime.now(timezone.utc) - timedelta(minutes=10)
                    ).isoformat() else "offline",
                }
        for node in topology["nodes"]:
            if node["id"] in agents:
                node["agent"] = agents[node["id"]]
    except Exception:
        pass

    # Enrich with asset names
    try:
        assets = await daemon.db.get_assets(limit=500)
        asset_map = {}
        for a in assets:
            if a.get("ip"):
                asset_map[a["ip"]] = {
                    "hostname": a.get("hostname", ""),
                    "criticality": a.get("criticality", "medium"),
                    "os": a.get("os", ""),
                }
        for node in topology["nodes"]:
            if node["id"] in asset_map:
                node["asset_info"] = asset_map[node["id"]]
    except Exception:
        pass

    return _json_response(topology)


async def handle_graph_pivot(request: web.Request) -> web.Response:
    """GET /api/graph/pivot?entity=X&depth=2 — entity neighborhood."""
    daemon = request.app["daemon"]
    graph = getattr(daemon, '_graph', None)
    if not graph:
        return _json_response({"error": "Graph not available"}, status=503)
    entity = request.rel_url.query.get("entity", "")
    depth = min(int(request.rel_url.query.get("depth", 2)), 4)
    if not entity:
        return _json_response({"error": "entity parameter required"}, status=400)
    result = graph.pivot(entity, depth=depth)
    return _json_response(result)


async def handle_graph_paths(request: web.Request) -> web.Response:
    """GET /api/graph/paths?src=X&dst=Y — attack paths between entities."""
    daemon = request.app["daemon"]
    graph = getattr(daemon, '_graph', None)
    if not graph:
        return _json_response({"error": "Graph not available"}, status=503)
    src = request.rel_url.query.get("src", "")
    dst = request.rel_url.query.get("dst", "")
    if not src or not dst:
        return _json_response({"error": "src and dst parameters required"}, status=400)
    paths = graph.find_paths(src, dst)
    return _json_response({"paths": paths, "count": len(paths)})


async def handle_graph_communities(request: web.Request) -> web.Response:
    """GET /api/graph/communities — entity clusters."""
    daemon = request.app["daemon"]
    graph = getattr(daemon, '_graph', None)
    if not graph:
        return _json_response({"error": "Graph not available"}, status=503)
    communities = graph.detect_communities()
    return _json_response({"communities": communities, "count": len(communities)})


async def handle_graph_entity_score(request: web.Request) -> web.Response:
    """GET /api/graph/entity-score?entity=X — risk score for entity."""
    daemon = request.app["daemon"]
    graph = getattr(daemon, '_graph', None)
    if not graph:
        return _json_response({"error": "Graph not available"}, status=503)
    entity = request.rel_url.query.get("entity", "")
    if not entity:
        return _json_response({"error": "entity parameter required"}, status=400)
    return _json_response(graph.score_entity(entity))


async def handle_graph_stats(request: web.Request) -> web.Response:
    """GET /api/graph/stats — graph size and health."""
    daemon = request.app["daemon"]
    graph = getattr(daemon, '_graph', None)
    if not graph:
        return _json_response({"error": "Graph not available"}, status=503)
    return _json_response(graph.get_stats())


async def handle_ml_anomalies(request: web.Request) -> web.Response:
    """GET /api/ml/anomalies — recent ML-flagged anomalies."""
    db = _db(request)
    limit = min(int(request.rel_url.query.get("limit", 50)), 200)
    try:
        rows = await db.execute_sql(
            """SELECT p.*, a.title, a.src_ip, a.dst_ip, a.severity, a.timestamp
               FROM ml_predictions p
               LEFT JOIN alerts a ON p.alert_id = a.id
               WHERE p.is_anomaly = 1
               ORDER BY p.created_at DESC
               LIMIT ?""",
            (limit,),
        )
        return _json_response({"anomalies": [dict(r) for r in rows], "total": len(rows)})
    except Exception:
        return _json_response({"anomalies": [], "total": 0})


async def handle_ml_health(request: web.Request) -> web.Response:
    """GET /api/ml/health — model status and stats."""
    daemon = request.app["daemon"]
    ml = getattr(daemon, '_ml_detector', None)
    if not ml:
        return _json_response({
            "active": False,
            "reason": "ML detector not initialized (may need retrain)",
            "sklearn_available": True,
            "isolation_forest": {"trained": False},
            "dbscan": {"trained": False},
        })
    return _json_response(ml.get_health())


async def handle_ml_retrain(request: web.Request) -> web.Response:
    """POST /api/ml/retrain — force model retrain."""
    daemon = request.app["daemon"]
    ml = getattr(daemon, '_ml_detector', None)
    if not ml:
        return _json_response({"error": "ML detector not started — restart shallotd first"}, status=503)
    try:
        stats = await ml.retrain()
        return _json_response({"ok": True, **stats})
    except Exception as exc:
        log.exception("ML retrain failed")
        return _json_response({"ok": False, "error": str(exc)}, status=500)


async def handle_killchain_active(request: web.Request) -> web.Response:
    """GET /api/killchain/active — active multi-stage attack progressions."""
    daemon = request.app["daemon"]
    kc = getattr(daemon, '_killchain', None)
    if not kc:
        return _json_response({"chains": [], "count": 0})
    result = kc.get_active_chains()
    if isinstance(result, list):
        return _json_response({"chains": result, "count": len(result)})
    return _json_response(result)


async def handle_killchain_history(request: web.Request) -> web.Response:
    """GET /api/killchain/history — completed/dismissed chains."""
    daemon = request.app["daemon"]
    kc = getattr(daemon, '_killchain', None)
    if not kc:
        return _json_response({"error": "Kill chain detector not available"}, status=503)
    return _json_response(kc.get_history())


async def handle_killchain_dismiss(request: web.Request) -> web.Response:
    """POST /api/killchain/{entity}/dismiss — dismiss a kill chain."""
    daemon = request.app["daemon"]
    kc = getattr(daemon, '_killchain', None)
    if not kc:
        return _json_response({"error": "Kill chain detector not available"}, status=503)
    entity = request.match_info["entity"]
    if kc.dismiss_chain(entity):
        return _json_response({"status": "ok", "dismissed": entity})
    return _json_response({"error": "Chain not found"}, status=404)


async def handle_threat_engine_status(request: web.Request) -> web.Response:
    """GET /api/threat-engine/status — overall threat engine health."""
    daemon = request.app["daemon"]
    status = {}

    baselines = getattr(daemon, '_baselines', None)
    if baselines:
        profiles = baselines.get_all_profiles()
        status["baselines"] = {
            "active": True,
            "profile_count": len(profiles),
        }
    else:
        status["baselines"] = {"active": False}

    graph = getattr(daemon, '_graph', None)
    if graph:
        status["graph"] = {"active": True, **graph.get_stats()}
    else:
        status["graph"] = {"active": False}

    ml = getattr(daemon, '_ml_detector', None)
    if ml:
        status["ml"] = {"active": True, **ml.get_health()}
    else:
        status["ml"] = {"active": False}

    kc = getattr(daemon, '_killchain', None)
    if kc:
        status["killchain"] = {
            "active": True,
            "active_chains": len(kc.active_chains),
            "history_count": len(kc._chain_history),
        }
    else:
        status["killchain"] = {"active": False}

    return _json_response(status)


# ── /api/tls-certs ────────────────────────────────────────────────────────────

async def handle_tls_certs(request: web.Request) -> web.Response:
    """GET /api/tls-certs — list all monitored TLS certificates."""
    try:
        certs = await _db(request).get_tls_certs()
        return _json_response(certs)
    except Exception as exc:
        log.exception("Failed to fetch TLS certs")
        return _json_response({"error": str(exc)}, 500)


# ── Sigma Rules ──────────────────────────────────────────────────────────────

async def handle_get_sigma_rules(request: web.Request) -> web.Response:
    """GET /api/sigma-rules — list loaded Sigma rules."""
    rules = await _db(request).get_sigma_rules()
    return _json_response({"rules": rules, "count": len(rules)})


async def handle_reload_sigma_rules(request: web.Request) -> web.Response:
    """POST /api/sigma-rules/reload — reload Sigma rules from disk."""
    daemon = request.app["daemon"]
    try:
        from shallots.sigma_engine import SigmaEngine
        sigma_cfg = daemon.cfg.sigma
        if not sigma_cfg.enabled:
            return _json_response({"error": "Sigma engine is not enabled in config"}, 400)
        engine = SigmaEngine(sigma_cfg.rules_dir)
        count = engine.load_rules()
        # Persist rules to DB
        for rule in engine.rules:
            await _db(request).upsert_sigma_rule({
                "id": rule.id,
                "title": rule.title,
                "level": rule.level,
                "category": rule.logsource_category,
                "description": rule.description,
                "tags": rule.tags,
                "filename": rule.filename,
            })
        # Store engine on daemon for matching
        daemon._sigma_engine = engine
        return _json_response({"loaded": count})
    except Exception as exc:
        log.exception("Failed to reload Sigma rules")
        return _json_response({"error": str(exc)}, 500)


# ── /api/ioc — IoC Feed Indicators ──────────────────────────────────────────

async def handle_ioc_list(request: web.Request) -> web.Response:
    """GET /api/ioc — list IoC indicators with optional type filter."""
    db = _db(request)
    indicator_type = request.query.get("type")
    limit = int(request.query.get("limit", "500"))
    indicators = await db.get_ioc_indicators(indicator_type=indicator_type, limit=limit)
    return _json_response({"indicators": indicators, "count": len(indicators)})


async def handle_ioc_stats(request: web.Request) -> web.Response:
    """GET /api/ioc/stats — feed statistics."""
    db = _db(request)
    stats = await db.get_ioc_feed_stats()
    return _json_response({"feeds": stats})


async def handle_ioc_check(request: web.Request) -> web.Response:
    """GET /api/ioc/check/{value} — check a specific IP/domain against feeds."""
    db = _db(request)
    value = request.match_info["value"]
    matches = await db.check_ioc(value)
    return _json_response({"value": value, "matches": matches, "hit": len(matches) > 0})


async def handle_ioc_refresh(request: web.Request) -> web.Response:
    """POST /api/ioc/refresh — trigger manual feed refresh."""
    daemon = request.app["daemon"]
    worker = getattr(daemon, "_ioc_worker", None)
    if worker is None:
        return _json_response({"error": "IoC feed worker not running"}, status=503)
    try:
        results = await worker.refresh_all()
        return _json_response({"status": "ok", "results": results})
    except Exception as exc:
        log.exception("IoC manual refresh failed")
        return _json_response({"error": str(exc)}, status=500)
