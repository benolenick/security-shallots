# SPAN / full-LAN visibility — readiness & blocker (2026-07-19)

## Why it matters
Suricata on host01 sees ONLY its own link (enp0s31f6), not a mirror of the LAN. So
agent-less gear — the host03 iLO/BMC, IoT boxes, the router, the infected-IPTV class of
device — is invisible on the wire. This is the single biggest remaining gap.

## What is ALREADY ready (software) — zero code work left
- `shallots/ingest/flow_scan.py` FlowScanDetector already consumes Suricata `flow`
  records and detects east-west port-scan / host-sweep fan-out.
- The classifier escalates flow-portscan/flow-sweep directly (classify() step 0).
- The moment SPAN traffic reaches a capture interface that Suricata reads, full-LAN
  east-west detection lights up with NO further code changes.

## What is BLOCKED (needs hands / switch access)
1. Cisco WS-C3560X-48 @ 192.168.0.216 — configure a mirror:
     monitor session 1 source vlan <lan> both
     monitor session 1 destination interface <port-to-host01>
   BLOCKER: no management access. telnet/ssh/web all refused (services off, not ACL);
   USB mini-B console does NOT enumerate on host01 (tried multiple cables, no CP210x /
   /dev/ttyUSB); RJ45 rollover console cable lost. Smart Install (TCP 4786) read-only
   config-pull was the last authorized path but the tooling could not be run.
   NEXT: obtain a USB-serial console cable that actually presents CP210x, OR a known-good
   RJ45 rollover + USB adapter, OR power-cycle into a known cred. Then enable SSH + SPAN.
2. Capture path on host01 — either a SECOND NIC as the SPAN destination (add a second
   Suricata af-packet interface in /etc/suricata/suricata.yaml), or dedicate host01's
   link to the mirror. Cheap USB3-2.5GbE NIC is sufficient for a home LAN.

## Interim mitigations already in place (this session)
- Wazuh agents on all 4 hosts → host-vantage auth + egress coverage (not the wire, but
  most east-west from an AGENTED host is seen from its own side).
- Host-firewall (ufw) drop decode on host02/host04 (flood-safe) — partial peer-scan vantage.
- Device-watch → alerts on any new MAC joining the LAN.
None of these replace a real SPAN; they narrow the gap while it stays blocked.
