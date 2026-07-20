"""MCP server for Security Shallots — lets Claude Code query the dashboard.

Usage:
    python -m shallots.mcp_server [--config config.yaml]

Register in Claude Code settings:
    {"mcpServers": {"shallots": {"command": "python", "args": ["-m", "shallots.mcp_server"]}}}
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

log = logging.getLogger(__name__)


# ── MCP protocol helpers ─────────────────────────────────────────────────────

def _jsonrpc_response(id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _jsonrpc_error(id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


def _tool_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


# ── Tool definitions ─────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "get_briefing",
        "description": "Get a dashboard overview: alert counts, agent status, top sources/IPs",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_alerts",
        "description": "Query alerts with filters",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max alerts to return", "default": 20},
                "severity": {"type": "string", "description": "Filter by severity: low|medium|high|critical"},
                "verdict": {"type": "string", "description": "Filter by verdict: pending|suppress|investigate|escalate"},
                "since": {"type": "string", "description": "Time window: 1h, 24h, 7d, 30d"},
                "source": {"type": "string", "description": "Filter by source: suricata|wazuh|argus|syslog|pfsense"},
            },
        },
    },
    {
        "name": "get_alert_context",
        "description": "Get full enriched context for one alert: details, triage, IP reputation, related alerts, knowledge base matches",
        "inputSchema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "string", "description": "Alert ID"},
            },
            "required": ["alert_id"],
        },
    },
    {
        "name": "search_alerts",
        "description": "Full-text search across alerts",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "limit": {"type": "integer", "default": 20},
            },
            "required": ["query"],
        },
    },
    {
        "name": "ask_question",
        "description": "Ask a natural language question about alerts (translates to SQL)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "question": {"type": "string", "description": "Natural language question"},
            },
            "required": ["question"],
        },
    },
    {
        "name": "set_verdict",
        "description": "Set the verdict on an alert",
        "inputSchema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "string"},
                "verdict": {"type": "string", "description": "suppress|investigate|escalate"},
                "reasoning": {"type": "string", "description": "Why this verdict"},
            },
            "required": ["alert_id", "verdict"],
        },
    },
    {
        "name": "run_investigation",
        "description": "Trigger a JTTW deep investigation of recent alerts",
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {"type": "string", "default": "24h"},
                "min_severity": {"type": "string", "default": "medium"},
                "auto_verdict": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "get_investigation",
        "description": "Read a past investigation report",
        "inputSchema": {
            "type": "object",
            "properties": {
                "investigation_id": {"type": "string"},
            },
            "required": ["investigation_id"],
        },
    },
]


# ── Server class ─────────────────────────────────────────────────────────────

class ShallotsMCPServer:
    """MCP server that exposes Security Shallots tools over stdin/stdout."""

    def __init__(self, config_path: str | None = None):
        self._config_path = config_path
        self._db = None
        self._cfg = None

    async def _ensure_db(self):
        """Lazy-init database connection."""
        if self._db is not None:
            return
        from shallots.config import load_config
        from shallots.store.db import AlertDB

        cfg_path = self._config_path or "config.yaml"
        self._cfg = load_config(cfg_path)
        self._db = AlertDB(self._cfg.storage.db_path)
        await self._db.connect()

    async def handle_request(self, msg: dict) -> dict:
        """Handle a single JSON-RPC request."""
        method = msg.get("method", "")
        id_ = msg.get("id")
        params = msg.get("params", {})

        if method == "initialize":
            return _jsonrpc_response(id_, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "shallots", "version": "0.2.0"},
            })

        if method == "notifications/initialized":
            return None  # No response for notifications

        if method == "tools/list":
            return _jsonrpc_response(id_, {"tools": TOOLS})

        if method == "tools/call":
            tool_name = params.get("name", "")
            args = params.get("arguments", {})
            try:
                result_text = await self._dispatch_tool(tool_name, args)
                return _jsonrpc_response(id_, _tool_result(result_text))
            except Exception as exc:
                return _jsonrpc_response(id_, _tool_result(f"Error: {exc}"))

        return _jsonrpc_error(id_, -32601, f"Unknown method: {method}")

    async def _dispatch_tool(self, name: str, args: dict) -> str:
        """Dispatch tool call to handler."""
        await self._ensure_db()

        if name == "get_briefing":
            return await self._tool_briefing()
        elif name == "get_alerts":
            return await self._tool_get_alerts(args)
        elif name == "get_alert_context":
            return await self._tool_alert_context(args)
        elif name == "search_alerts":
            return await self._tool_search(args)
        elif name == "ask_question":
            return await self._tool_ask(args)
        elif name == "set_verdict":
            return await self._tool_set_verdict(args)
        elif name == "run_investigation":
            return await self._tool_run_investigation(args)
        elif name == "get_investigation":
            return await self._tool_get_investigation(args)
        else:
            return f"Unknown tool: {name}"

    async def _tool_briefing(self) -> str:
        stats = await self._db.get_stats()
        top = await self._db.get_top_talkers(since="24h", limit=5)
        investigations = await self._db.get_recent_investigations(limit=3)
        briefing = {
            "pending_alerts": stats.get("pending_triage", 0),
            "escalated_alerts": stats.get("escalated", 0),
            "total_alerts": stats.get("total_alerts", 0),
            "investigate_alerts": stats.get("investigate", 0),
            "active_correlations": stats.get("correlations", 0),
            "agents_online": stats.get("agents_online", 0),
            "agents_offline": stats.get("agents_offline", 0),
            "top_sources": stats.get("by_source", {}),
            "top_src_ips": top.get("src_ips", [])[:5],
            "top_dst_ips": top.get("dst_ips", [])[:5],
            "recent_investigations": investigations,
        }
        return json.dumps(briefing, indent=2, default=str)

    async def _tool_get_alerts(self, args: dict) -> str:
        alerts = await self._db.get_alerts(
            limit=min(args.get("limit", 20), 100),
            severity=args.get("severity"),
            verdict=args.get("verdict"),
            since=args.get("since"),
            source=args.get("source"),
        )
        # Slim down for token efficiency
        slim = []
        for a in alerts:
            slim.append({
                "id": a["id"], "timestamp": a["timestamp"],
                "severity": a["severity"], "title": a["title"],
                "src_ip": a.get("src_ip", ""), "dst_ip": a.get("dst_ip", ""),
                "dst_port": a.get("dst_port", 0), "verdict": a["verdict"],
                "source": a["source"], "category": a.get("category", ""),
            })
        return json.dumps(slim, indent=2, default=str)

    async def _tool_alert_context(self, args: dict) -> str:
        alert_id = args["alert_id"]
        alert = await self._db.get_alert(alert_id)
        if not alert:
            return json.dumps({"error": "Alert not found"})

        triage = await self._db.get_triage(alert_id)

        # IP reputation
        rep = {}
        for ip_field in ("src_ip", "dst_ip"):
            ip = alert.get(ip_field, "")
            if ip:
                r = await self._db.get_ip_reputation(ip)
                if r:
                    rep[ip] = r

        # Related alerts (same src_ip, last 24h)
        related = []
        if alert.get("src_ip"):
            related = await self._db.get_alerts(limit=10, since="24h", src_ip=alert["src_ip"])
            related = [r for r in related if r["id"] != alert_id]

        # Knowledge base
        kb = await self._db.search_knowledge(alert.get("title", ""), limit=3)

        # Chat history
        chat = await self._db.get_chat_history(alert_id, limit=10)

        context = {
            "alert": alert,
            "triage": triage,
            "ip_reputation": rep,
            "related_alerts": [{"id": r["id"], "title": r["title"], "severity": r["severity"], "timestamp": r["timestamp"]} for r in related[:5]],
            "knowledge_base": kb,
            "chat_history": chat,
        }
        return json.dumps(context, indent=2, default=str)

    async def _tool_search(self, args: dict) -> str:
        results = await self._db.search_alerts(args["query"], limit=args.get("limit", 20))
        slim = [{"id": a["id"], "title": a["title"], "severity": a["severity"], "src_ip": a.get("src_ip", ""), "timestamp": a["timestamp"]} for a in results]
        return json.dumps(slim, indent=2, default=str)

    async def _tool_ask(self, args: dict) -> str:
        if self._cfg.ai.tier == "none":
            return json.dumps({"error": "AI is not configured"})
        from shallots.ai.query import NLQueryEngine
        engine = NLQueryEngine(self._cfg.ai, self._db)
        result = await engine.query(args["question"])
        return result

    async def _tool_set_verdict(self, args: dict) -> str:
        valid = {"suppress", "investigate", "escalate"}
        verdict = args["verdict"]
        if verdict not in valid:
            return json.dumps({"error": f"Invalid verdict: {verdict}"})
        await self._db.update_verdict(
            alert_id=args["alert_id"],
            verdict=verdict,
            confidence=1.0,
            reasoning=args.get("reasoning", "Set via MCP agent"),
        )
        return json.dumps({"ok": True, "alert_id": args["alert_id"], "verdict": verdict})

    async def _tool_run_investigation(self, args: dict) -> str:
        if self._cfg.ai.tier == "none":
            return json.dumps({"error": "AI is not configured"})
        from shallots.ai.investigator import DeepInvestigator
        investigator = DeepInvestigator(self._cfg.ai, self._db)
        report = await investigator.investigate(
            since=args.get("since", "24h"),
            min_severity=args.get("min_severity", "medium"),
            auto_verdict=args.get("auto_verdict", False),
        )
        return json.dumps(report.to_dict(), indent=2, default=str)

    async def _tool_get_investigation(self, args: dict) -> str:
        inv = await self._db.get_investigation(args["investigation_id"])
        if not inv:
            return json.dumps({"error": "Investigation not found"})
        return json.dumps(inv, indent=2, default=str)

    async def run(self) -> None:
        """Main loop — read JSON-RPC from stdin, write to stdout."""
        loop = asyncio.get_event_loop()

        # Set up async stdin reader
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        # stdout — write synchronously (safe for pipe, avoids private API)
        def _write_stdout(data: bytes) -> None:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

        buf = b""
        while True:
            try:
                chunk = await reader.read(65536)
            except Exception:
                break
            if not chunk:
                break
            buf += chunk

            # Process complete lines
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue

                response = await self.handle_request(msg)
                if response is not None:
                    out = (json.dumps(response) + "\n").encode()
                    await loop.run_in_executor(None, _write_stdout, out)

        if self._db:
            await self._db.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Shallots MCP Server")
    parser.add_argument("-c", "--config", default="config.yaml")
    args = parser.parse_args()

    server = ShallotsMCPServer(config_path=args.config)
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
