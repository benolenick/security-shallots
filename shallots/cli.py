"""CLI entry point for Security Shallots."""

from __future__ import annotations

import argparse
import asyncio
import sys

from shallots import __version__


def _load_config_safe(path: str | None):
    """Load config, printing a clean message on failure instead of a traceback."""
    import yaml
    from shallots.config import load_config

    try:
        return load_config(path)
    except FileNotFoundError as e:
        print(f"Error: config file not found — {e}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error: invalid YAML in config — {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: could not load config — {e}", file=sys.stderr)
        sys.exit(1)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="shallot",
        description="Security Shallots — AI-augmented security monitoring",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-c", "--config", help="Path to config.yaml")

    sub = parser.add_subparsers(dest="command")

    # shallot run
    run_p = sub.add_parser("run", help="Start the shallot daemon (foreground)")
    run_p.add_argument("--debug", action="store_true", help="Enable debug logging")

    # shallot status
    sub.add_parser("status", help="Show component health and alert stats")

    # shallot query
    query_p = sub.add_parser("query", help="AI-powered natural language query")
    query_p.add_argument("question", help="Question to ask")

    # shallot rules
    rules_p = sub.add_parser("rules", help="Manage detection rules")
    rules_sub = rules_p.add_subparsers(dest="rules_action")
    rules_sub.add_parser("update", help="Update Suricata rules")

    # shallot health
    sub.add_parser("health", help="Detailed health check")

    # shallot doctor
    sub.add_parser("doctor", help="Diagnose common issues (DB, Suricata, agents, disk)")

    # shallot jttw / investigate
    jttw_p = sub.add_parser("jttw", help="Jesus Take The Wheel — AI deep investigation",
                            aliases=["investigate"])
    jttw_p.add_argument("--since", default="24h", help="Time window (default: 24h)")
    jttw_p.add_argument("--severity", default="medium", help="Min severity (default: medium)")
    jttw_p.add_argument("--auto-verdict", action="store_true", help="Auto-apply AI verdicts")

    # shallot agent-briefing
    sub.add_parser("agent-briefing", help="Print agent briefing JSON to stdout")

    # shallot agent-context
    actx_p = sub.add_parser("agent-context", help="Print full alert context JSON for an agent")
    actx_p.add_argument("alert_id", help="Alert ID")

    # shallot ladder — tiered AI escalation ladder
    ladder_p = sub.add_parser(
        "ladder", help="Tiered AI escalation ladder (qwen3 → Haiku → Sonnet → Opus)")
    ladder_sub = ladder_p.add_subparsers(dest="ladder_action")
    ladder_sub.add_parser("build", help="Tier-0: qwen3 distills escalate-worthy alerts into cases")
    lr = ladder_sub.add_parser("run", help="Run one Claude tier over its open cases")
    lr.add_argument("--tier", required=True, choices=["haiku", "sonnet", "opus"])
    ladder_sub.add_parser("status", help="Show ladder state (cases per tier, pings)")
    ladder_sub.add_parser("test-auth", help="Verify the OAuth Claude path works")

    # shallot setup
    setup_p = sub.add_parser("setup", help="Auto-detect network and generate config")
    setup_p.add_argument("--port", type=int, default=8844, help="Web dashboard port (default: 8844)")
    setup_p.add_argument("--db-path", default="", help="Database path (default: ./shallots.db)")
    setup_p.add_argument("--retention", type=int, default=30, help="Alert retention in days (default: 30)")
    setup_p.add_argument("--install-service", action="store_true", help="Install systemd service")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "run":
        _cmd_run(args)
    elif args.command == "status":
        _cmd_status(args)
    elif args.command == "query":
        _cmd_query(args)
    elif args.command == "health":
        _cmd_health(args)
    elif args.command == "rules":
        _cmd_rules(args)
    elif args.command in ("jttw", "investigate"):
        _cmd_jttw(args)
    elif args.command == "agent-briefing":
        _cmd_agent_briefing(args)
    elif args.command == "agent-context":
        _cmd_agent_context(args)
    elif args.command == "doctor":
        _cmd_doctor(args)
    elif args.command == "ladder":
        _cmd_ladder(args)
    elif args.command == "setup":
        _cmd_setup(args)


def _cmd_ladder(args) -> None:
    import json
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    from shallots.ai.ladder import Ladder

    cfg = _load_config_safe(args.config)
    ladder = Ladder(cfg)
    action = getattr(args, "ladder_action", None)

    if action == "build":
        print(json.dumps(ladder.build(), indent=2))
    elif action == "run":
        print(json.dumps(ladder.run_tier(args.tier), indent=2))
    elif action == "status":
        print(json.dumps(ladder.status(), indent=2, default=str))
    elif action == "test-auth":
        try:
            res = ladder.brain.self_test()
            print(f"OK — {res.model} replied {res.text!r} in {res.latency_ms}ms")
        except Exception as e:  # noqa: BLE001
            print(f"FAILED — {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("usage: shallot ladder {build|run --tier|status|test-auth}", file=sys.stderr)
        sys.exit(1)


def _cmd_run(args) -> None:

    from shallots.daemon import Daemon

    cfg = _load_config_safe(args.config)

    import logging
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    daemon = Daemon(cfg)
    try:
        asyncio.run(daemon.run())
    except KeyboardInterrupt:
        print("\nShutting down...")


def _cmd_status(args) -> None:


    cfg = _load_config_safe(args.config)
    asyncio.run(_print_status(cfg))


async def _print_status(cfg) -> None:
    from shallots.store.db import AlertDB

    db = AlertDB(cfg.storage.db_path)
    try:
        await db.connect()
        stats = await db.get_stats()
    except Exception as e:
        print(f"Database error: {e}")
        return
    finally:
        await db.close()

    print(f"Security Shallots v{__version__}")
    print(f"Profile: {cfg.profile}")
    print(f"AI tier: {cfg.ai.tier}")
    print()
    print(f"Total alerts:    {stats['total_alerts']}")
    print(f"Pending triage:  {stats['pending_triage']}")
    print(f"Suppressed:      {stats['suppressed']}")
    print(f"Investigate:     {stats['investigate']}")
    print(f"Escalated:       {stats['escalated']}")
    print(f"Correlations:    {stats['correlations']}")
    print()
    if stats["by_source"]:
        print("By source:")
        for src, cnt in stats["by_source"].items():
            print(f"  {src}: {cnt}")
    if stats["by_severity"]:
        print("By severity:")
        for sev, cnt in stats["by_severity"].items():
            print(f"  {sev}: {cnt}")


def _cmd_query(args) -> None:


    cfg = _load_config_safe(args.config)
    if cfg.ai.tier == "none":
        print("AI is not configured. Set ai.tier in config.yaml.")
        sys.exit(1)

    asyncio.run(_run_query(cfg, args.question))


async def _run_query(cfg, question: str) -> None:
    from shallots.store.db import AlertDB
    from shallots.ai.query import NLQueryEngine

    db = AlertDB(cfg.storage.db_path)
    await db.connect()
    try:
        engine = NLQueryEngine(cfg.ai, db)
        result = await engine.query(question)
        print(result)
    finally:
        await db.close()


def _cmd_health(args) -> None:


    cfg = _load_config_safe(args.config)
    asyncio.run(_run_health(cfg))


async def _run_health(cfg) -> None:
    from shallots.health import check_all

    results = await check_all(cfg)
    for name, status, detail in results:
        icon = "OK" if status else "FAIL"
        print(f"  [{icon}] {name}: {detail}")


def _cmd_rules(args) -> None:
    if args.rules_action == "update":
        print("Updating Suricata rules...")
        import subprocess
        try:
            subprocess.run(["suricata-update"], check=True)
            print("Rules updated. Reload Suricata to apply.")
        except FileNotFoundError:
            print("suricata-update not found. Is Suricata installed?")
        except subprocess.CalledProcessError as e:
            print(f"Rule update failed: {e}")
    else:
        print("Usage: shallot rules update")


def _cmd_jttw(args) -> None:


    cfg = _load_config_safe(args.config)
    if cfg.ai.tier == "none":
        print("AI is not configured. Set ai.tier in config.yaml.")
        sys.exit(1)

    asyncio.run(_run_jttw(cfg, args.since, args.severity, args.auto_verdict))


async def _run_jttw(cfg, since: str, severity: str, auto_verdict: bool) -> None:
    import json
    from shallots.store.db import AlertDB
    from shallots.ai.investigator import DeepInvestigator

    db = AlertDB(cfg.storage.db_path)
    await db.connect()
    try:
        investigator = DeepInvestigator(cfg.ai, db)
        report = await investigator.investigate(
            since=since, min_severity=severity, auto_verdict=auto_verdict,
        )

        print(f"\n{'=' * 60}")
        print(f"JTTW Investigation Report — {report.created_at}")
        print(f"Window: {report.since_window} | Alerts: {report.alert_count} | Model: {report.model}")
        print(f"Latency: {report.latency_ms}ms | Verdicts applied: {report.verdicts_applied}")
        print(f"{'=' * 60}\n")

        print("EXECUTIVE SUMMARY")
        print(report.executive_summary)
        print()

        if report.findings:
            print("FINDINGS")
            for i, f in enumerate(report.findings, 1):
                print(f"\n  [{i}] {f.get('title', 'Untitled')} ({f.get('severity', '?')})")
                print(f"      {f.get('narrative', '')[:300]}")
                if f.get("mitre_techniques"):
                    print(f"      MITRE: {', '.join(f['mitre_techniques'])}")
            print()

        if report.verdicts:
            print(f"VERDICTS ({len(report.verdicts)})")
            for v in report.verdicts:
                print(f"  {v.alert_id[:12]}... → {v.verdict} — {v.reasoning[:80]}")
            print()

        if report.recommendations:
            print("RECOMMENDATIONS")
            for r in report.recommendations:
                print(f"  - {r}")
            print()

    finally:
        await db.close()


def _cmd_agent_briefing(args) -> None:
    import json


    cfg = _load_config_safe(args.config)
    asyncio.run(_run_agent_briefing(cfg))


async def _run_agent_briefing(cfg) -> None:
    import json
    from shallots.store.db import AlertDB

    db = AlertDB(cfg.storage.db_path)
    await db.connect()
    try:
        stats = await db.get_stats()
        top = await db.get_top_talkers(since="24h", limit=5)
        investigations = await db.get_recent_investigations(limit=3)
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
        print(json.dumps(briefing, indent=2, default=str))
    finally:
        await db.close()


def _cmd_agent_context(args) -> None:
    import json


    cfg = _load_config_safe(args.config)
    asyncio.run(_run_agent_context(cfg, args.alert_id))


async def _run_agent_context(cfg, alert_id: str) -> None:
    import json
    from shallots.store.db import AlertDB

    db = AlertDB(cfg.storage.db_path)
    await db.connect()
    try:
        alert = await db.get_alert(alert_id)
        if not alert:
            print(json.dumps({"error": "Alert not found"}))
            return

        triage = await db.get_triage(alert_id)
        ip_rep = {}
        for ip_field in ("src_ip", "dst_ip"):
            ip = alert.get(ip_field, "")
            if ip:
                rep = await db.get_ip_reputation(ip)
                if rep:
                    ip_rep[ip] = rep

        related = []
        if alert.get("src_ip"):
            related = await db.get_alerts(limit=10, since="24h", src_ip=alert["src_ip"])
            related = [r for r in related if r["id"] != alert_id]

        kb = await db.search_knowledge(alert.get("title", ""), limit=3)
        chat = await db.get_chat_history(alert_id, limit=10)

        context = {
            "alert": alert,
            "triage": triage,
            "ip_reputation": ip_rep,
            "related_alerts": [
                {"id": r["id"], "title": r["title"], "severity": r["severity"], "timestamp": r["timestamp"]}
                for r in related[:5]
            ],
            "knowledge_base": kb,
            "chat_history": chat,
        }
        print(json.dumps(context, indent=2, default=str))
    finally:
        await db.close()


def _cmd_doctor(args) -> None:
    """Run diagnostics: health checks + DB stats + actionable recommendations."""
    from shallots.config import load_config

    try:
        cfg = load_config(args.config)
    except FileNotFoundError:
        print("No config.yaml found. Run 'shallot setup' first.")
        sys.exit(1)

    asyncio.run(_run_doctor(cfg))


async def _run_doctor(cfg) -> None:
    from shallots.health import check_all, format_health_report
    import os

    checks = await check_all(cfg)
    print(format_health_report(checks))
    print()

    # DB stats
    db_path = cfg.storage.db_path
    if os.path.exists(db_path):
        size_mb = os.path.getsize(db_path) / (1024 * 1024)
        print(f"Database: {db_path}")
        print(f"  Size: {size_mb:.1f} MB")
        print(f"  Retention: {cfg.storage.retention_days} days")
        print(f"  Max backups: {cfg.storage.max_backups}")

        # Check for backup bloat
        from pathlib import Path
        backup_dir = cfg.storage.backup_dir or str(Path(db_path).parent / "backups")
        if os.path.isdir(backup_dir):
            backups = list(Path(backup_dir).glob("shallots-*.db"))
            total_backup_mb = sum(f.stat().st_size for f in backups) / (1024 * 1024)
            print(f"  Backups: {len(backups)} files, {total_backup_mb:.0f} MB total")
            if len(backups) > cfg.storage.max_backups:
                print(f"  WARNING: {len(backups)} backups exceed max_backups={cfg.storage.max_backups}")
    else:
        print(f"Database: not found at {db_path}")

    print()
    print(f"Profile: {cfg.profile}")
    print(f"AI tier: {cfg.ai.tier}")
    print(f"Threat engine: {cfg.threat_engine.tier}")
    print(f"  Baselines: {'on' if cfg.threat_engine.baselines else 'off'}")
    print(f"  Graph: {'on' if cfg.threat_engine.graph else 'off'}")
    print(f"  ML: {'on' if cfg.threat_engine.ml_detector else 'off'}")
    print(f"  Kill chain: {'on' if cfg.threat_engine.killchain else 'off'}")

    # Recommendations
    recs = []
    failed = [name for name, ok, _ in checks if not ok]
    if "suricata_process" in failed:
        recs.append("Suricata is not running. Install and start it: sudo systemctl start suricata")
    if "suricata_eve_file" in failed:
        recs.append(f"Suricata EVE log not found at {cfg.suricata.eve_path}. Check suricata.eve_path in config.yaml")
    if "disk_space" in failed:
        recs.append("Disk usage above 90%. Consider reducing retention_days or cleaning old backups")
    if "database" in failed:
        recs.append("Database inaccessible. Check storage.db_path in config.yaml")
    if cfg.web.username == "" or cfg.web.password == "":
        recs.append("No web auth configured. Set web.username and web.password in config.yaml")
    if cfg.ai.tier == "none":
        recs.append("AI triage is off. Add an API key to config.yaml for automatic alert classification")

    if recs:
        print()
        print("Recommendations:")
        for i, rec in enumerate(recs, 1):
            print(f"  {i}. {rec}")
    else:
        print()
        print("No issues found.")


def _cmd_setup(args) -> None:
    """Auto-detect network and generate a working config.yaml."""
    from pathlib import Path
    import socket

    config_path = Path(args.config) if args.config else Path("config.yaml")
    if config_path.exists():
        print(f"Config already exists at {config_path}")
        print("Delete it first if you want to regenerate.")
        sys.exit(1)

    print("Security Shallots — Quick Setup")
    print("=" * 40)

    # Detect home CIDR
    home_cidr = "192.168.0.0/16"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        my_ip = s.getsockname()[0]
        s.close()
        # Guess /24 from the IP
        parts = my_ip.split(".")
        home_cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        print(f"  Detected LAN: {home_cidr} (server IP: {my_ip})")
    except Exception:
        print(f"  Could not detect LAN, using default: {home_cidr}")

    # Detect Suricata EVE path
    eve_path = "/var/log/suricata/eve.json"
    eve_found = False
    eve_candidates = [
        Path("/var/log/suricata/eve.json"),
        Path("/var/log/suricata/fast.log"),
        Path("/usr/local/var/log/suricata/eve.json"),
    ]
    for p in eve_candidates:
        if p.exists():
            eve_path = str(p)
            eve_found = True
            print(f"  Found Suricata: {eve_path}")
            break

    if not eve_found:
        print(f"  Suricata not found.")
        print(f"  Install it first:")
        import platform as _plat
        if _plat.system() == "Linux":
            # Detect package manager
            import shutil
            if shutil.which("apt"):
                print(f"    sudo apt install suricata")
            elif shutil.which("dnf"):
                print(f"    sudo dnf install suricata")
            elif shutil.which("pacman"):
                print(f"    sudo pacman -S suricata")
            else:
                print(f"    See https://suricata.io/download/")
        else:
            print(f"    See https://suricata.io/download/")
        print(f"  Using default path: {eve_path}")

    # Detect hardware
    from shallots.config import _detect_hardware, detect_profile
    hw = _detect_hardware()
    profile = detect_profile()
    print(f"  Hardware: {hw['ram_gb']}GB RAM, {hw['cpu_cores']} cores → profile={profile}, tier={hw['tier']}")

    # User-configurable options
    db_path = args.db_path or "./shallots.db"
    web_port = args.port
    retention = args.retention

    # Write config
    config_content = f"""# Security Shallots — auto-generated config
# Edit to taste, then run: shallot run

profile: auto

network:
  home_cidr: "{home_cidr}"

suricata:
  eve_path: "{eve_path}"

storage:
  db_path: "{db_path}"
  retention_days: {retention}
  max_backups: 3

web:
  host: "0.0.0.0"
  port: {web_port}
  # Uncomment and set for basic auth (recommended):
  # username: "admin"
  # password: "changeme"

# AI triage (optional — uncomment one):
# ai:
#   tier: remote_api
#   anthropic_api_key: "sk-ant-..."
#   # or: openai_api_key: "sk-..."
"""

    config_path.write_text(config_content)
    server_ip = my_ip if 'my_ip' in dir() else 'localhost'
    print(f"\n  Config written to {config_path}")

    # Optionally install systemd service
    if args.install_service:
        _install_systemd_service(config_path, server_ip, web_port)

    print()
    print("  Next steps:")
    print(f"    1. shallot run")
    print(f"    2. Open http://{server_ip}:{web_port}")
    print(f"    3. Click 'Setup' in the header to deploy agents to your machines")
    print()
    print("  To deploy agents from the command line:")
    print(f"    Linux:   curl -fsSL https://raw.githubusercontent.com/benolenick/security-shallots/main/setup/endpoint/clove | sudo bash -s -- --manager {server_ip}")
    print(f"    Windows: irm https://raw.githubusercontent.com/benolenick/security-shallots/main/setup/endpoint/clove.ps1 | iex")
    print()
    print("  To run as a background service:")
    if not args.install_service:
        print(f"    shallot setup --install-service")
    print(f"    sudo systemctl enable --now shallotd")


def _install_systemd_service(config_path, server_ip, web_port):
    """Install a systemd service file for shallotd."""
    import os
    work_dir = os.path.abspath(os.path.dirname(config_path))
    config_abs = os.path.abspath(config_path)
    python_path = sys.executable

    service_content = f"""[Unit]
Description=Security Shallots SIEM Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart={python_path} -m shallots -c {config_abs} run
WorkingDirectory={work_dir}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
NoNewPrivileges=yes
PrivateTmp=yes
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
    service_path = Path("/etc/systemd/system/shallotd.service")
    try:
        service_path.write_text(service_content)
        print(f"\n  Systemd service installed: {service_path}")
        print(f"  Enable with: sudo systemctl enable --now shallotd")
    except PermissionError:
        # Write to temp and tell user to copy
        tmp_path = Path("/tmp/shallotd.service")
        tmp_path.write_text(service_content)
        print(f"\n  Service file written to {tmp_path} (need sudo to install)")
        print(f"  Run: sudo cp {tmp_path} /etc/systemd/system/ && sudo systemctl daemon-reload")
