"""REST API route handlers for Security Shallots dashboard.

This package splits the monolithic api.py into domain modules.
Import setup_api_routes from here - it registers all routes.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from aiohttp import web

log = logging.getLogger(__name__)


def _json_response(data: Any, status: int = 200) -> web.Response:
    """Return a JSON response."""
    return web.Response(
        status=status,
        content_type="application/json",
        body=json.dumps(data, default=str),
    )


def _db(request: web.Request):
    """Extract AlertDB from the request app."""
    return request.app["daemon"].db


async def _call_ai(daemon, system: str, user: str) -> str:
    """Call AI using the configured tier, reusing the OllamaClient pattern."""
    cfg = daemon.cfg.ai
    if cfg.tier == "none":
        return "AI is not configured. Set an AI tier in settings to use this feature."

    from shallots.ai.ollama_client import OllamaClient
    client = OllamaClient(base_url=cfg.ollama_url or "http://localhost:11434")

    try:
        if cfg.tier in ("remote_micro", "remote_standard", "local") and cfg.ollama_url:
            return await client.generate(
                prompt=user,
                model=cfg.ollama_model or "llama3.2",
                system=system,
            )
        elif cfg.tier == "remote_api" and cfg.openai_api_key:
            return await client.generate_openai(
                prompt=user,
                model="gpt-4o-mini",
                api_key=cfg.openai_api_key,
                system=system,
            )
        elif cfg.anthropic_api_key:
            return await client.generate_anthropic(
                prompt=user,
                model="claude-3-haiku-20240307",
                api_key=cfg.anthropic_api_key,
                system=system,
            )
        elif cfg.ollama_url:
            return await client.generate(
                prompt=user,
                model=cfg.ollama_model or "llama3.2",
                system=system,
            )
        else:
            return "No AI provider configured. Go to Settings to configure Ollama, OpenAI, or Anthropic."
    except Exception as exc:
        log.exception("AI consult call failed")
        return f"AI call failed: {exc}"
    finally:
        await client.close()


def setup_api_routes(app: web.Application) -> None:
    """Register all API routes on the app.

    Routes are organized by domain. On lite/micro profiles, optional
    feature endpoints still exist but return empty/inactive responses
    from their handlers (no 404s - the frontend adapts via /api/health).
    """
    from . import alerts, incidents, ai, agents, rules, scout, threat_engine, system

    r = app.router

    # ── Core: health, stats, version ──────────────────────────────
    r.add_get("/api/health", system.handle_health)
    r.add_get("/api/stats", system.handle_stats)
    r.add_get("/api/security/ops", system.handle_security_ops)
    r.add_get("/api/version", system.handle_version)
    r.add_post("/api/update", system.handle_update)
    r.add_get("/api/agent-guide", system.handle_agent_guide)

    # ── Alerts: list, detail, verdict, search, export ─────────────
    r.add_get("/api/alerts", alerts.handle_alerts)
    r.add_get("/api/alerts/search", alerts.handle_search)
    r.add_get("/api/alerts/export", alerts.handle_export)
    r.add_get("/api/alerts/grouped", alerts.handle_grouped_alerts)
    r.add_get("/api/alerts/stale", alerts.handle_stale_alerts)
    r.add_get("/api/alerts/{id}", alerts.handle_alert_detail)
    r.add_get("/api/alerts/{id}/context", alerts.handle_alert_context)
    r.add_get("/api/alerts/{id}/chat", alerts.handle_alert_chat)
    r.add_get("/api/alerts/{id}/notes", alerts.handle_get_notes)
    r.add_post("/api/alerts/{id}/notes", alerts.handle_add_note)
    r.add_post("/api/alerts/{id}/ai/{action}", ai.handle_ai_consult)
    r.add_patch("/api/alerts/{id}/verdict", alerts.handle_set_verdict)
    r.add_patch("/api/alerts/{id}/acknowledge", alerts.handle_acknowledge)
    r.add_post("/api/alerts/bulk-verdict", alerts.handle_bulk_verdict)
    r.add_post("/api/alerts/suppress-filtered", alerts.handle_suppress_filtered)
    r.add_post("/api/pivot", alerts.handle_pivot)
    r.add_post("/api/query", alerts.handle_nl_query)

    # ── Edge Scout: non-judgmental missed-signal cards ───────────
    r.add_get("/api/scout/cards", scout.handle_scout_cards)

    # ── Incidents ─────────────────────────────────────────────────
    r.add_get("/api/incidents", incidents.handle_incidents)
    r.add_get("/api/incidents/counts", incidents.handle_incident_counts)
    r.add_get("/api/incidents/auto-dismiss", incidents.handle_auto_dismiss_candidates)
    r.add_get("/api/incidents/{id}", incidents.handle_incident_detail)
    r.add_patch("/api/incidents/{id}/status", incidents.handle_incident_status)
    r.add_get("/api/incidents/{id}/notes", incidents.handle_incident_notes)
    r.add_post("/api/incidents/{id}/notes", incidents.handle_add_incident_note)
    r.add_get("/api/incidents/{id}/timeline", incidents.handle_incident_timeline)
    r.add_post("/api/incidents/{id}/runbook/execute", incidents.handle_runbook_execute)
    r.add_post("/api/incidents/{id}/runbook/interpret", incidents.handle_runbook_interpret)
    r.add_post("/api/incidents/{id}/decide", incidents.handle_incident_decision)

    # ── Correlations & clusters ───────────────────────────────────
    r.add_get("/api/correlations", incidents.handle_correlations)
    r.add_get("/api/correlations/{id}/alerts", incidents.handle_correlation_alerts)
    r.add_delete("/api/correlations/{id}", incidents.handle_delete_correlation)
    r.add_post("/api/correlations/clear", incidents.handle_clear_correlations)
    r.add_post("/api/correlations/{id}/ai", incidents.handle_correlation_ai)
    r.add_get("/api/clusters", incidents.handle_clusters)
    r.add_get("/api/clusters/stats", incidents.handle_cluster_stats)
    r.add_get("/api/clusters/{id}", incidents.handle_cluster_detail)
    r.add_patch("/api/clusters/{id}/verdict", incidents.handle_cluster_verdict)

    # ── Rules: silence + custom detection ─────────────────────────
    r.add_get("/api/silence-rules", rules.handle_get_silence_rules)
    r.add_post("/api/silence-rules", rules.handle_add_silence_rule)
    r.add_delete("/api/silence-rules/{id}", rules.handle_delete_silence_rule)
    r.add_post("/api/silence-rules/ai", rules.handle_ai_silence_rule)
    r.add_get("/api/rules", rules.handle_get_custom_rules)
    r.add_post("/api/rules", rules.handle_add_custom_rule)
    r.add_post("/api/rules/test", rules.handle_test_custom_rule)
    r.add_patch("/api/rules/{id}", rules.handle_update_custom_rule)
    r.add_delete("/api/rules/{id}", rules.handle_delete_custom_rule)

    # ── AI: triage, autopilot, suggestions ────────────────────────
    r.add_get("/api/ai/status", ai.handle_ai_status)
    r.add_post("/api/ai/mode", ai.handle_ai_set_mode)
    r.add_get("/api/ai/decisions", ai.handle_ai_decisions)
    r.add_get("/api/ai/suggestions", ai.handle_ai_suggestions)
    r.add_post("/api/ai/suggestions/{id}/approve", ai.handle_ai_suggestion_approve)
    r.add_post("/api/ai/suggestions/{id}/reject", ai.handle_ai_suggestion_reject)
    r.add_get("/api/ai/squawks", ai.handle_ai_squawks)
    r.add_post("/api/ai/squawks/{id}/dismiss", ai.handle_ai_squawk_dismiss)
    r.add_get("/api/ai/reports", ai.handle_ai_reports)
    r.add_get("/api/ai/reports/{id}", ai.handle_ai_report_detail)
    r.add_get("/api/ai/verdicts", ai.handle_ai_verdicts)
    r.add_get("/api/settings/ai", ai.handle_get_ai_settings)
    r.add_patch("/api/settings/ai", ai.handle_patch_ai_settings)
    r.add_post("/api/settings/ai/scan", ai.handle_ai_scan)

    # ── Agents: ingest, heartbeat, health ─────────────────────────
    r.add_post("/api/heartbeat", agents.handle_heartbeat)
    r.add_post("/api/ingest/clove", agents.handle_clove_ingest)
    r.add_post("/api/ingest/argus", agents.handle_argus_ingest)
    r.add_get("/api/agents", agents.handle_agents)
    r.add_get("/api/agents/clove", agents.handle_clove_agents)
    r.add_get("/api/agents/{name}/alerts", agents.handle_clove_agent_alerts)
    r.add_post("/api/agents/{name}/update", agents.handle_clove_agent_update)

    # ── Investigations (JTTW) ─────────────────────────────────────
    r.add_post("/api/investigations/run", ai.handle_run_investigation)
    r.add_get("/api/investigations", ai.handle_list_investigations)
    r.add_get("/api/investigations/{id}", ai.handle_get_investigation)
    r.add_get("/api/agent/briefing", agents.handle_agent_briefing)
    r.add_post("/api/agent/investigate", agents.handle_agent_investigate)
    r.add_get("/api/agent/context/{alert_id}", agents.handle_agent_context)

    # ── Dashboard & analytics ─────────────────────────────────────
    r.add_get("/api/dashboard/top-talkers", system.handle_top_talkers)
    r.add_get("/api/dashboard/timeline", system.handle_timeline)
    r.add_get("/api/dashboard/connections", system.handle_connections)
    r.add_get("/api/network/hosts", system.handle_network_hosts)
    r.add_get("/api/analytics/protocols", system.handle_protocol_analytics)
    r.add_get("/api/analytics/dns", system.handle_dns_analytics)
    r.add_get("/api/mitre", system.handle_mitre_coverage)

    # ── Assets & devices ──────────────────────────────────────────
    r.add_get("/api/assets", system.handle_get_assets)
    r.add_post("/api/assets", system.handle_create_asset)
    r.add_get("/api/assets/{id}", system.handle_get_asset)
    r.add_patch("/api/assets/{id}", system.handle_update_asset)
    r.add_get("/api/devices", system.handle_known_devices)

    # ── Threat intel: reputation, IoC feeds ───────────────────────
    r.add_get("/api/reputation/{ip}", threat_engine.handle_reputation)
    r.add_get("/api/threat-intel", threat_engine.handle_threat_intel_status)
    r.add_get("/api/ioc", threat_engine.handle_ioc_list)
    r.add_get("/api/ioc/stats", threat_engine.handle_ioc_stats)
    r.add_get("/api/ioc/check/{value}", threat_engine.handle_ioc_check)
    r.add_post("/api/ioc/refresh", threat_engine.handle_ioc_refresh)
    r.add_get("/api/vulnerabilities", system.handle_vulnerabilities)
    r.add_get("/api/vulnerabilities/correlation", system.handle_vuln_correlation)

    # ── Threat engine: baselines, graph, ML, kill chain ───────────
    r.add_get("/api/threat-engine/status", threat_engine.handle_threat_engine_status)
    r.add_get("/api/baselines", threat_engine.handle_baselines)
    r.add_post("/api/baselines/rebuild", threat_engine.handle_baseline_rebuild)
    r.add_get("/api/baselines/{ip}", threat_engine.handle_baseline_detail)
    r.add_get("/api/topology", threat_engine.handle_topology)
    r.add_get("/api/graph/pivot", threat_engine.handle_graph_pivot)
    r.add_get("/api/graph/paths", threat_engine.handle_graph_paths)
    r.add_get("/api/graph/communities", threat_engine.handle_graph_communities)
    r.add_get("/api/graph/entity-score", threat_engine.handle_graph_entity_score)
    r.add_get("/api/graph/stats", threat_engine.handle_graph_stats)
    r.add_get("/api/ml/anomalies", threat_engine.handle_ml_anomalies)
    r.add_get("/api/ml/health", threat_engine.handle_ml_health)
    r.add_post("/api/ml/retrain", threat_engine.handle_ml_retrain)
    r.add_get("/api/killchain/active", threat_engine.handle_killchain_active)
    r.add_get("/api/killchain/history", threat_engine.handle_killchain_history)
    r.add_post("/api/killchain/{entity}/dismiss", threat_engine.handle_killchain_dismiss)

    # ── System: backup, reports, wiki, sigma, firewall ────────────
    r.add_get("/api/settings/storage", system.handle_get_storage_settings)
    r.add_patch("/api/settings/storage", system.handle_patch_storage_settings)
    r.add_get("/api/system/db-stats", system.handle_db_stats)
    r.add_post("/api/system/backup", system.handle_backup)
    r.add_get("/api/system/health", system.handle_system_health)
    r.add_get("/api/audit-log", system.handle_audit_log)
    r.add_get("/api/saved-searches", system.handle_get_saved_searches)
    r.add_post("/api/saved-searches", system.handle_save_search)
    r.add_delete("/api/saved-searches/{id}", system.handle_delete_saved_search)
    r.add_get("/api/wiki/stats", ai.handle_wiki_stats)
    r.add_get("/api/wiki/recent", ai.handle_wiki_recent)
    r.add_post("/api/wiki/ai", ai.handle_wiki_ai)
    r.add_get("/api/dhcp", system.handle_dhcp_history)
    r.add_get("/api/dhcp/changes", system.handle_dhcp_changes)
    r.add_get("/api/tls-certs", threat_engine.handle_tls_certs)
    r.add_get("/api/sigma-rules", threat_engine.handle_get_sigma_rules)
    r.add_post("/api/sigma-rules/reload", threat_engine.handle_reload_sigma_rules)
    r.add_get("/api/reports/summary", system.handle_get_report_summary)
    r.add_post("/api/reports/send", system.handle_send_report_email)
    r.add_post("/api/firewall/block", system.handle_block_ip)
    r.add_post("/api/firewall/unblock", system.handle_unblock_ip)
    r.add_post("/api/test-detection", system.handle_test_detection)
