#!/usr/bin/env python3
"""Render router syslog setup and verification steps from the expected-source manifest."""

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
from pathlib import Path
from typing import Any

import yaml


DEFAULT_TARGET = "192.168.0.172"
DEFAULT_PORT = 514


def _admin_urls(src_ips: list[str]) -> list[str]:
    urls: list[str] = []
    for ip in src_ips:
        urls.extend([f"http://{ip}/", f"https://{ip}/"])
    return urls


def _ui_hints(name: str, hostnames: list[str]) -> list[str]:
    text = " ".join([name, *hostnames]).lower()
    if "dlink" in text or "covr" in text:
        return [
            "D-Link/COVR UIs commonly place this under Management -> System Log.",
            "Look for Remote Log, Syslog Server, Log Server IP, or Enable Logging.",
        ]
    if "sagemcom" in text:
        return [
            "Sagemcom UIs vary by ISP firmware; check Advanced/Management, Maintenance, Diagnostics, or Event Log.",
            "If no remote syslog option exists, keep this source as an explicit expected gap or replace it with another sensor for that segment.",
        ]
    return [
        "Search the UI for System Log, Event Log, Remote Log, Syslog, Diagnostics, or Maintenance logging.",
    ]


def _fallback_options(name: str, src_ips: list[str], hostnames: list[str]) -> list[dict[str, Any]]:
    text = " ".join([name, *hostnames]).lower()
    segment = ", ".join(src_ips) or name
    options: list[dict[str, Any]] = [
        {
            "name": "keep_expected_gap",
            "when": "Use when no approved alternate sensor is deployed yet.",
            "action": "Keep this manifest entry expected=true so the production gate continues to show the network visibility gap.",
            "verify": ".venv/bin/python tools/shallot_production_gate.py",
        },
        {
            "name": "syslog_capable_gateway_or_firewall",
            "when": "Use when the router firmware cannot forward logs but the segment can be put behind a firewall/gateway that can.",
            "action": f"Place {segment} behind a syslog-capable gateway/firewall and forward logs to 192.168.0.172:514.",
            "verify": ".venv/bin/python tools/shallot_alert_assess.py --hours 1 --summary-json --expected-log-sources docs/NETWORK_LOG_SOURCES.yaml",
        },
        {
            "name": "mirror_or_tap_sensor",
            "when": "Use when switch/AP port mirroring is available and router admin logging is not.",
            "action": "Mirror the gateway/uplink port to a sensor running Suricata or equivalent and add that sensor as an expected source.",
            "verify": ".venv/bin/python tools/shallot_rule_canary.py && .venv/bin/python tools/shallot_production_gate.py",
        },
    ]
    if "sagemcom" in text:
        options.append(
            {
                "name": "segment_endpoint_coverage",
                "when": "Use as partial compensation if ISP firmware exposes neither syslog nor mirroring.",
                "action": "Keep Argus network_egress enabled on Host02-segment endpoints and document that router-management events remain uncovered.",
                "verify": ".venv/bin/python tools/shallot_fleet_top.py --summary-json",
            }
        )
    return options


def _tcp_open(host: str, port: int, *, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _route_to(host: str) -> str:
    try:
        completed = subprocess.run(
            ["ip", "route", "get", host],
            text=True,
            capture_output=True,
            timeout=1,
        )
    except Exception:
        return ""
    if completed.returncode != 0:
        return ""
    return " ".join(completed.stdout.strip().split())


def _curl_probe(url: str) -> str:
    try:
        completed = subprocess.run(
            ["curl", "-k", "-L", "--max-time", "5", "-sS", "-i", url],
            text=True,
            capture_output=True,
            timeout=7,
        )
    except Exception:
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout[:20000]


def _cert_probe(host: str) -> dict[str, str]:
    command = (
        f"timeout 6 openssl s_client -connect {host}:443 -servername {host} </dev/null 2>/dev/null "
        "| openssl x509 -noout -subject -issuer -dates 2>/dev/null"
    )
    try:
        completed = subprocess.run(
            ["bash", "-lc", command],
            text=True,
            capture_output=True,
            timeout=8,
        )
    except Exception:
        return {}
    if completed.returncode != 0:
        return {}
    out: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def _fingerprint(host: str, *, probe: bool) -> dict[str, Any]:
    if not probe:
        return {}
    body = _curl_probe(f"https://{host}/") or _curl_probe(f"http://{host}/")
    title = ""
    template_version = ""
    server = ""
    if body:
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = " ".join(title_match.group(1).split())
        tpl_match = re.search(r"TPL_VER\s*=\s*[\"']([^\"']+)[\"']", body)
        if tpl_match:
            template_version = tpl_match.group(1).strip()
        server_match = re.search(r"^Server:\s*(.+)$", body, re.IGNORECASE | re.MULTILINE)
        if server_match:
            server = server_match.group(1).strip()
    cert = _cert_probe(host)
    return {
        "title": title,
        "template_version": template_version,
        "server": server,
        "cert_subject": cert.get("subject", ""),
        "cert_issuer": cert.get("issuer", ""),
        "cert_not_before": cert.get("notBefore", ""),
        "cert_not_after": cert.get("notAfter", ""),
    }


def _reachability(src_ips: list[str], *, probe: bool) -> list[dict[str, Any]]:
    if not probe:
        return []
    return [
        {
            "ip": ip,
            "tcp80": _tcp_open(ip, 80),
            "tcp443": _tcp_open(ip, 443),
            "route": _route_to(ip),
        }
        for ip in src_ips
    ]


def _ping_ok(host: str) -> bool:
    try:
        completed = subprocess.run(
            ["ping", "-c", "1", "-W", "1", host],
            text=True,
            capture_output=True,
            timeout=2,
        )
    except Exception:
        return False
    return completed.returncode == 0


def _target_preflight(target: str, port: int, *, probe: bool) -> dict[str, Any]:
    if not probe:
        return {
            "status": "not_probed",
            "target": target,
            "port": port,
            "checks": {},
            "next_step": "Run with --probe from the operator network before changing router syslog settings.",
        }
    checks = {
        "route": _route_to(target),
        "ping": _ping_ok(target),
        "tcp_syslog": _tcp_open(target, port),
        "tcp_api_8844": _tcp_open(target, 8844),
    }
    if checks["ping"] or checks["tcp_syslog"] or checks["tcp_api_8844"]:
        status = "reachable"
        next_step = "Confirm the receiver preflight commands pass before saving router syslog settings."
    elif checks["route"]:
        status = "routed_but_unreachable"
        next_step = f"Restore the Shallots receiver host at {target} before pointing routers at it."
    else:
        status = "unreachable"
        next_step = f"Confirm network route to the Shallots receiver host {target} before router changes."
    return {
        "status": status,
        "target": target,
        "port": port,
        "checks": checks,
        "next_step": next_step,
    }


def _diagnosis(reachability: list[dict[str, Any]]) -> dict[str, str]:
    if not reachability:
        return {
            "diagnosis": "not_probed",
            "next_step": "Run with --probe from host01 to verify router UI reachability before logging in.",
        }
    ui_reachable = any(bool(item.get("tcp80") or item.get("tcp443")) for item in reachability)
    routed = any(bool(item.get("route")) for item in reachability)
    if ui_reachable:
        return {
            "diagnosis": "management_ui_reachable_syslog_not_forwarding",
            "next_step": "Log into the reachable router UI and enable remote syslog to 192.168.0.172:514.",
        }
    if routed:
        return {
            "diagnosis": "host_routed_but_management_ui_unconfirmed",
            "next_step": "Verify router UI access or configure logging from another management path.",
        }
    return {
        "diagnosis": "source_unreachable_or_unprobed",
        "next_step": "Confirm the expected source IP/route before configuring syslog forwarding.",
    }


def load_sources(path: str) -> list[dict[str, Any]]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    sources = data.get("sources", []) if isinstance(data, dict) else []
    return [src for src in sources if isinstance(src, dict) and src.get("expected", True)]


def build_plan(
    sources: list[dict[str, Any]],
    *,
    target: str = DEFAULT_TARGET,
    port: int = DEFAULT_PORT,
    probe: bool = False,
) -> dict[str, Any]:
    items = []
    for src in sources:
        name = str(src.get("name") or "unnamed")
        src_ips = [str(ip) for ip in src.get("src_ips") or []]
        hostnames = [str(host) for host in src.get("hostnames") or []]
        admin_urls = _admin_urls(src_ips)
        reachability = _reachability(src_ips, probe=probe)
        fingerprints = {ip: _fingerprint(ip, probe=probe) for ip in src_ips} if probe else {}
        items.append(
            {
                "name": name,
                "type": str(src.get("type") or "syslog"),
                "source_ips": src_ips,
                "hostnames": hostnames,
                "admin_urls": admin_urls,
                "target": target,
                "port": port,
                "note": str(src.get("note") or ""),
                "reachability": reachability,
                "fingerprints": fingerprints,
                **_diagnosis(reachability),
                "ui_hints": _ui_hints(name, hostnames),
                "fallback_options": _fallback_options(name, src_ips, hostnames),
                "router_steps": [
                    f"Open the router admin UI: {', '.join(admin_urls) or name}.",
                    "Find System Log, Event Log, Remote Log, Syslog, or Diagnostics logging.",
                    f"Enable remote syslog/log forwarding to {target} on port {port}.",
                    "Use UDP if the router requires a protocol choice; TCP is also accepted by Shallots.",
                    "Save/apply settings, then trigger a harmless router event such as login/logout or DHCP renew.",
                ],
                "verify_commands": [
                    "cd /home/user/security-shallots",
                    ".venv/bin/python tools/shallot_alert_assess.py --hours 1 --summary-json --expected-log-sources docs/NETWORK_LOG_SOURCES.yaml",
                    ".venv/bin/python tools/shallot_production_gate.py",
                    "tail -n 140 docs/ALERT_ASSESSMENT_LOG.md",
                ],
                "success_criteria": [
                    f"At least one fresh syslog event from {name} appears within the assessment window.",
                    f"production_gate.blockers no longer contains network:expected_syslog_missing:{name}.",
                    "The source row status is ok or stale, not missing; stale means forwarding worked but the router has been quiet.",
                    "shallot_syslog_canary remains ok after the router change.",
                ],
            }
        )
    return {
        "target": target,
        "port": port,
        "target_preflight": _target_preflight(target, port, probe=probe),
        "receiver_preflight_commands": [
            "cd /home/user/security-shallots",
            f"ss -lun '( sport = :{port} )'; ss -ltn '( sport = :{port} )'",
            ".venv/bin/python tools/shallot_syslog_canary.py --timeout 30",
            ".venv/bin/python tools/shallot_ops_sanity.py",
        ],
        "sources": items,
    }


def print_text(plan: dict[str, Any]) -> None:
    print(f"Router syslog target: {plan['target']}:{plan['port']}")
    target_preflight = plan.get("target_preflight") or {}
    if target_preflight:
        print(f"target preflight: {target_preflight.get('status', 'unknown')}")
        checks = target_preflight.get("checks") or {}
        if checks:
            print(
                "  "
                + ", ".join(
                    [
                        f"route={'yes' if checks.get('route') else 'no'}",
                        f"ping={'ok' if checks.get('ping') else 'fail'}",
                        f"tcp{plan['port']}={'open' if checks.get('tcp_syslog') else 'closed'}",
                        f"tcp8844={'open' if checks.get('tcp_api_8844') else 'closed'}",
                    ]
                )
            )
        if target_preflight.get("next_step"):
            print(f"target next: {target_preflight['next_step']}")
    print("receiver preflight:")
    for cmd in plan.get("receiver_preflight_commands") or []:
        print(f"  $ {cmd}")
    for src in plan["sources"]:
        print()
        print(f"{src['name']} ({src['type']})")
        print(f"source IPs: {', '.join(src['source_ips']) or 'unknown'}")
        if src.get("admin_urls"):
            print(f"admin URLs: {', '.join(src['admin_urls'])}")
        if src["hostnames"]:
            print(f"hostnames: {', '.join(src['hostnames'])}")
        if src["note"]:
            print(f"note: {src['note']}")
        if src.get("reachability"):
            print("reachability:")
            for item in src["reachability"]:
                status = []
                status.append(f"tcp80={'open' if item.get('tcp80') else 'closed'}")
                status.append(f"tcp443={'open' if item.get('tcp443') else 'closed'}")
                route = item.get("route") or "no route"
                print(f"  - {item.get('ip')}: {', '.join(status)}; {route}")
        if src.get("fingerprints"):
            print("fingerprints:")
            for ip, item in src["fingerprints"].items():
                details = []
                if item.get("title"):
                    details.append(f"title={item['title']}")
                if item.get("template_version"):
                    details.append(f"tpl={item['template_version']}")
                if item.get("server"):
                    details.append(f"server={item['server']}")
                if item.get("cert_subject"):
                    details.append(f"cert_subject={item['cert_subject']}")
                print(f"  - {ip}: {'; '.join(details) or 'unidentified'}")
        if src.get("diagnosis"):
            print(f"diagnosis: {src['diagnosis']}")
        if src.get("next_step"):
            print(f"next: {src['next_step']}")
        if src.get("ui_hints"):
            print("UI hints:")
            for hint in src["ui_hints"]:
                print(f"  - {hint}")
        if src.get("fallback_options"):
            print("fallback options if router syslog is unavailable:")
            for option in src["fallback_options"]:
                print(f"  - {option['name']}: {option['when']}")
                print(f"    action: {option['action']}")
                print(f"    verify: {option['verify']}")
        print("router steps:")
        for step in src["router_steps"]:
            print(f"  - {step}")
        print("verify:")
        for cmd in src["verify_commands"]:
            print(f"  $ {cmd}")
        if src.get("success_criteria"):
            print("success criteria:")
            for item in src["success_criteria"]:
                print(f"  - {item}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="docs/NETWORK_LOG_SOURCES.yaml")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--probe", action="store_true", help="Probe router routes and TCP 80/443 reachability.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    plan = build_plan(load_sources(args.manifest), target=args.target, port=args.port, probe=args.probe)
    if args.json:
        print(json.dumps(plan, indent=2))
    else:
        print_text(plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
