# Homelab / Small-Office Readiness

Security Shallots is being framed as a lightweight security scout for a home lab
or small office under about 10 computers.

The product claim should be:

> Shallots gives a small network a cheap scout that collects logs and high-value
> signals, remembers local normal, catches drift/canary/first-seen activity, and
> escalates compact context to a human or stronger AI.

It should not claim full Security Onion parity. Security Onion remains better for
large-scale indexed search, analyst workflow, case management, Zeek depth, file
analysis, and long retention.

## Useful Protection Per Footprint

Highest value for a Pi-class hub:

1. Router/firewall syslog
2. DNS or resolver logs
3. Posture scanner
4. Canary files and honey listener
5. SQLite alert memory
6. Short evidence ring
7. CrowdSec only if stable on the host
8. Suricata only if traffic placement and CPU budget make sense
9. Cloud or remote elder AI, not local LLM

Lower value on a Pi unless the user has the hardware:

- local 8B LLM
- Grafana/VictoriaLogs
- Wazuh manager
- long pcap retention
- full Zeek-style protocol metadata

## Placement Decision

The first install question should be where Shallots will see traffic.

| Answer | Recommended mode |
|---|---|
| Router can send syslog/DNS logs | `pi-core` |
| Managed switch can mirror traffic | `pi-ids` |
| Shallots is the gateway | `pi-ids` or `mini` |
| Normal switch port only | posture/syslog/canary scout; IDS coverage is local-host only |

The UI and installer should warn when Suricata is enabled without a useful vantage
point.

## AI Integration Review

Efficient defaults:

- batch AI work
- send compact alerts/cards, not raw firehose
- keep the scout non-judgmental
- use local rules for obvious suppress/escalate guardrails
- let stronger models review only distilled cases

Required guardrails before broad release:

- redact secrets/tokens before cloud model calls
- treat log text, DNS names, user agents, and process args as untrusted prompt
  content
- never let the scout suppress, page, or change verdicts
- make cloud AI opt-in and disclose what leaves the LAN
- log model inputs/outputs at a bounded size for audit/eval

## Host01 Reference Build

The Host01 build is the reference/full-small-office profile, not the Pi profile.

Enabled live:

- `shallotd.service`
- `suricata.service`
- `crowdsec.service`
- `victorialogs.service`
- `grafana-server.service`
- `wazuh-manager.service`
- `shallot-pcap-ring.service`
- `shallot-posture-scan.timer`
- `shallot-honey-listener.service`
- corpus, inventory, ladder, backup, watchdog, and assessment timers

Measured non-Granite footprint during the July 2026 hardening pass:

- repo + venv + local state: about 375 MB
- `/var/lib/shallots`: about 462-515 MB depending on pcap ring age
- Suricata logs: about 1.1-1.2 GB
- steady non-LLM RAM: about 900 MB
- posture DB: under 1 MB
- honey listener RSS: about 15 MB

## Soak Criteria

Run for at least 24 hours after a clean gate.

Pass conditions:

- `tools/shallot_ops_sanity.py --json` reports `status=ok`
- `tools/shallot_production_gate.py --json` has zero blockers
- posture eval has zero failed checks
- no database lock errors or tracebacks in `shallotd`, posture, or honey logs
- Suricata packet drops remain visible and acceptable
- alert/scout volume stays human-reviewable
- no stale pre-tuning escalations remain open
- GPU temperature stays below the configured ceiling when local AI is enabled

Expected non-blocking warnings:

- documented suppression-volume warnings
- transient synthetic syslog canary failures that self-clear
- visible alerts that are intentionally retained for review

## Near-Term Gaps

Before packaging for a home user:

- add a first-run placement wizard
- add a Pi profile that caps pcap/log retention and disables heavy services
- add cloud-AI redaction tests
- surface Suricata drop counters in the main status
- add one-command backup/restore docs
- make alert delivery obvious, for example ntfy/email setup in the installer
- add a small purple-team/canary eval command for users to prove the system sees
  what they expect
