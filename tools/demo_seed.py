#!/usr/bin/env python3
"""Seed a Security Shallots database with realistic SYNTHETIC data for demos and
screenshots. All hosts/IPs are fictional (RFC-5737 documentation ranges for
"external" IPs, 192.168.1.x for the LAN). Nothing here reflects a real network.

Usage:
    python -m tools.demo_seed --db /path/to/demo.db
"""
from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timedelta, timezone

from shallots.store.db import AlertDB
from shallots.store.models import Alert


def iso(minutes_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


# Fictional LAN inventory
DEVICES = [
    ("aa:bb:cc:00:00:01", "192.168.1.1", "gateway"),
    ("aa:bb:cc:00:00:02", "192.168.1.10", "web-server"),
    ("aa:bb:cc:00:00:03", "192.168.1.20", "nas"),
    ("aa:bb:cc:00:00:04", "192.168.1.30", "workstation"),
    ("aa:bb:cc:00:00:05", "192.168.1.40", "pi-shallots"),
    ("aa:bb:cc:00:00:06", "192.168.1.55", "unknown-device"),
]

# (minutes_ago, source, severity, title, description, src_ip, dst_ip, dst_port,
#  proto, category, sig_id, verdict, confidence, ai_reasoning, src_asset, dst_asset)
ALERTS = [
    (3, "suricata", "critical", "ET MALWARE Cobalt Strike Beacon Observed",
     "Periodic outbound TLS to 203.0.113.66 every 60s with jittered timing consistent with a Cobalt Strike C2 beacon. web-server is not expected to initiate outbound to this host.",
     "192.168.1.10", "203.0.113.66", 443, "TCP", "ET MALWARE", 2027001,
     "escalate", 0.94,
     "Beaconing cadence + destination reputation strongly indicate active C2. Isolate web-server and block 203.0.113.66 now.",
     "web-server", ""),
    (11, "wazuh", "high", "SSH Brute Force from external IP",
     "342 failed SSH password attempts from 198.51.100.23 against web-server in 6 minutes, followed by one success.",
     "198.51.100.23", "192.168.1.10", 22, "TCP", "Authentication Failure", 5710,
     "escalate", 0.88,
     "High-rate failed logins then a success = likely credential compromise. Rotate the account and check for persistence.",
     "", "web-server"),
    (24, "argus", "high", "New device joined the network",
     "Previously-unseen device 192.168.1.55 (unknown vendor) appeared on the LAN and opened port 8080.",
     "192.168.1.55", "", 8080, "TCP", "new-device", 0,
     "investigate", 0.6,
     "Unrecognized MAC with an open service port. Confirm this is a device you added.",
     "unknown-device", ""),
    (33, "suricata", "medium", "Internal port scan detected",
     "198.51.100.12 probed 41 ports on workstation in under 10s (host sweep signature).",
     "198.51.100.12", "192.168.1.30", 0, "TCP", "ET SCAN", 2010935,
     "investigate", 0.55,
     "Reconnaissance sweep. Not yet an exploit, but worth watching this source.",
     "", "workstation"),
    (47, "pihole", "medium", "DNS lookup to newly-registered domain",
     "workstation resolved 'update-service-cdn[.]info', registered 2 days ago — common in malware staging.",
     "192.168.1.30", "", 53, "UDP", "dns", 0,
     "investigate", 0.5,
     "Young domains are a weak signal on their own; correlate with any outbound connections that follow.",
     "workstation", ""),
    (52, "crowdsec", "medium", "IP flagged by community blocklist",
     "185.220.101.45 (in the CrowdSec community blocklist for SSH bruteforce) attempted a connection to the gateway.",
     "185.220.101.45", "192.168.1.1", 22, "TCP", "crowdsec/ban", 0,
     "investigate", 0.6, "Known-bad source, blocked by CrowdSec. Informational.",
     "", "gateway"),
    # --- suppressed noise (shows the pipeline keeping things quiet) ---
    (6, "wazuh", "low", "PAM: Login session opened",
     "Routine PAM session open on pi-shallots.", "192.168.1.40", "", 0, "", "authentication_success", 5501,
     "suppress", 0.9, "native suppression: title matched 'PAM: Login session opened'", "pi-shallots", ""),
    (9, "suricata", "low", "LLMNR query",
     "Standard Windows name-resolution broadcast.", "192.168.1.30", "224.0.0.252", 5355, "UDP", "Not Suspicious", 2000001,
     "suppress", 0.9, "native suppression: benign LAN discovery", "workstation", ""),
    (14, "wazuh", "low", "Package changes detected",
     "apt upgraded 4 packages on nas.", "192.168.1.20", "", 0, "", "package_change", 2902,
     "suppress", 0.85, "native suppression: routine package maintenance", "nas", ""),
    (19, "suricata", "low", "SURICATA STREAM excessive retransmissions",
     "TCP stream noise.", "192.168.1.10", "192.168.1.1", 443, "TCP", "Generic Protocol Command Decode", 2210050,
     "suppress", 0.9, "native suppression: Suricata stream noise", "web-server", "gateway"),
    (28, "argus", "low", "Internal SSH login",
     "workstation -> nas over SSH (known-good admin path).", "192.168.1.30", "192.168.1.20", 22, "TCP", "authentication_success", 0,
     "suppress", 0.8, "rule-based: internal LAN source, low severity", "workstation", "nas"),
]

INCIDENTS = [
    {
        "title": "Possible C2 beacon from web-server",
        "summary": "web-server is beaconing to 203.0.113.66 on a regular 60-second interval — the pattern of malware phoning home. This needs attention now: treat web-server as possibly compromised until you've confirmed otherwise.",
        "severity": "critical", "status": "new", "urgency": "act_now", "category": "c2",
        "affected_ips": ["192.168.1.10", "203.0.113.66"], "affected_hosts": ["web-server"],
        "alert_count": 1,
        "runbook": [
            {"description": "Confirm the connection is live and find the process behind it.",
             "command": "ss -tanp | grep 203.0.113.66",
             "expect": "No output = the connection is gone.",
             "bad_sign": "An ESTABLISHED connection tied to an unexpected process (not your app).",
             "decision": "If a strange process owns it, treat web-server as compromised."},
            {"description": "Block the destination at the gateway/firewall.",
             "command": "sudo ufw deny out to 203.0.113.66",
             "expect": "Rule added.", "bad_sign": "", "decision": "Blocks the beacon while you investigate."},
            {"description": "Isolate web-server from the LAN if the process is confirmed malicious.",
             "command": "sudo ip link set dev eth0 down   # on web-server",
             "expect": "Host drops off the network.", "bad_sign": "",
             "decision": "Contain first, forensics second."},
            {"description": "Review what started the process (cron, systemd, a web upload).",
             "command": "sudo journalctl -S -1h | grep -i web-server",
             "expect": "A clear origin.", "bad_sign": "An unfamiliar unit/cron entry = persistence.",
             "decision": "Remove the persistence mechanism before restoring the host."},
        ],
        "ai_analysis": "Regular-interval outbound TLS to a low-reputation host, initiated by a server that should only receive connections, is a textbook C2 beacon. Confidence is high. Prioritize containment.",
        "created_at": iso(3),
    },
    {
        "title": "SSH brute force against web-server (one success)",
        "summary": "Someone tried hundreds of SSH passwords against web-server from 198.51.100.23 and then got in once. Assume the account may be compromised.",
        "severity": "high", "status": "new", "urgency": "act_now", "category": "brute_force",
        "affected_ips": ["192.168.1.10", "198.51.100.23"], "affected_hosts": ["web-server"],
        "alert_count": 1,
        "runbook": [
            {"description": "See which account the successful login used.",
             "command": "sudo grep 'Accepted password' /var/log/auth.log | tail",
             "expect": "A login you recognize.", "bad_sign": "A service or unfamiliar account.",
             "decision": "Rotate that account's credentials immediately."},
            {"description": "Ban the source and switch SSH to key-only auth.",
             "command": "sudo ufw deny from 198.51.100.23",
             "expect": "Rule added.", "bad_sign": "", "decision": "Stops the ongoing attempts."},
        ],
        "ai_analysis": "Failed-login flood followed by a success is the signature of a successful brute force. Rotate credentials and disable password auth.",
        "created_at": iso(11),
    },
]


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    args = ap.parse_args()

    db = AlertDB(args.db)
    await db.connect()
    try:
        for mac, ip, host in DEVICES:
            await db.upsert_asset(ip=ip, mac=mac, hostname=host, asset_type="host")
            try:
                await db._db.execute(
                    "INSERT OR IGNORE INTO known_devices (mac, ip, hostname, first_seen, last_seen, alert_generated) VALUES (?,?,?,?,?,1)",
                    (mac, ip, host, iso(1440), iso(2)))
            except Exception:
                pass
        await db._db.commit()

        for i, a in enumerate(ALERTS):
            (m, source, sev, title, desc, sip, dip, dport, proto, cat, sig,
             verdict, conf, reason, sasset, dasset) = a
            alert = Alert(
                timestamp=iso(m), source=source, source_ref=f"demo-{i}", severity=sev,
                title=title, description=desc, src_ip=sip, dst_ip=dip, dst_port=dport,
                proto=proto, category=cat, signature_id=sig, src_asset=sasset, dst_asset=dasset,
                raw=json.dumps({"demo": True, "title": title}),
            )
            alert.verdict = verdict
            alert.confidence = conf
            alert.ai_reasoning = reason
            await db.insert_alert(alert)

        for inc in INCIDENTS:
            await db.insert_incident(inc)

        print(f"Seeded {len(ALERTS)} alerts, {len(INCIDENTS)} incidents, {len(DEVICES)} devices into {args.db}")
    finally:
        await db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
