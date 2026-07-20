# Security Shallots -- Getting Started Guide

## 1. What Is Security Shallots

Security Shallots is an AI-augmented security monitoring stack designed for home labs
and small networks. It fills the gap between bare-bones tools like `fail2ban` and
enterprise platforms like Security Onion that demand 32 GB of RAM.

A central daemon called **shallotd** collects alerts from three sources:

- **Network IDS** (Suricata) -- watches traffic on the wire for known attack signatures.
- **Clove agents** (Wazuh-based) -- lightweight endpoint agents deployed on any machine,
  reporting file changes, authentication events, and system integrity checks.
- **Argus sentinels** -- heavyweight monitors for your most critical machines,
  tracking running processes, credential files, persistence mechanisms, and login sessions.

Every alert passes through an optional **AI triage** layer that classifies it as one of:

| Verdict | Meaning |
|---------|---------|
| **suppress** | Background noise -- safe to ignore |
| **investigate** | Warrants a human review when convenient |
| **escalate** | Act immediately -- potential active threat |

Results are visible in a **web dashboard** on port 8844. For critical threats, shallotd
can fire **email or SMS alerts** so you never miss an escalation.

---

## 2. Architecture Overview

```
                        +---------------------+
                        |      shallotd       |
                        |   (central server)  |
                        +----------+----------+
                                   |
           +-----------+-----------+-----------+-----------+
           |           |           |           |           |
       ingest      normalize    dedup      enrich      AI triage
      (raw logs)  (common fmt)  (merge)   (GeoIP)   (classify)
           |           |           |           |           |
           +-----+-----+-----+-----+-----+-----+-----+---+
                 |                                     |
              store                                 alert
          (SQLite FTS5)                       (email / SMS / webhook)
                 |
          +------+------+
          |             |
     Web Dashboard   Grafana
     (port 8844)    (port 3000)
```

Data flows into shallotd from three directions:

```
  [Suricata]  ---- EVE JSON -----+
                                  |
  [Wazuh Agents] -- alerts.json -+---->  shallotd  ----> Dashboard
                                  |                 \
  [Argus Sentinels] -- webhook --+                   +--> Email/SMS
                                  |
  [pfSense] ----- syslog -------+
  [CrowdSec] ---- LAPI poll ----+
```

Each alert is normalized into a common format, deduplicated, enriched with GeoIP data
when an external IP is involved, passed through AI triage if configured, stored in a
SQLite FTS5 database, and optionally shipped to VictoriaLogs for Grafana dashboards.

---

## 3. The Two Agent Types

Security Shallots uses two distinct agent types. They serve different purposes and
are not interchangeable.

### Clove (Wazuh-based, lightweight)

A general-purpose host intrusion detection agent that runs on **any** machine in your
network. Clove installs the Wazuh agent, which connects back to the Wazuh manager
running on your shallotd server.

**What it monitors:**

- File integrity (detects unauthorized changes to system files)
- Authentication logs (failed logins, privilege escalation)
- System configuration changes
- Rootkit detection
- Vulnerability scanning

**Characteristics:**

- Passive -- collects data and reports to the central manager; does not take action.
- Low resource usage (typically under 100 MB RAM).
- Communicates over port 1514 (events) and 1515 (enrollment).

**Best for:** servers, VMs, NAS boxes, general desktops, Raspberry Pis, containers --
any Linux or Windows machine that should be monitored.

**Optional add-on:** CrowdSec can be installed alongside Clove using the
`--crowdsec` flag. This adds automated IP blocking based on crowd-sourced threat
intelligence (see Section 7).

Think of Clove as the rank-and-file soldier: deploy it everywhere, it is
lightweight and reliable. Each Clove is a single piece of the larger shallot -- small,
potent, and part of the whole.

---

### Argus (the big brother, heavyweight)

A hyper-vigilant guardian designed for your **most critical machines** -- the ones that
hold password vaults, SSH keys, browser sessions, and admin credentials.

**What it monitors:**

- **Running processes** -- detects known hacking tools (mimikatz, netcat, etc.)
- **Credential files** -- watches KeePassXC databases, SSH keys, browser credential stores
- **Persistence mechanisms** -- startup folders, scheduled tasks, registry run keys
- **Login sessions** -- RDP connections, new interactive logins (lateral movement detection)
- **Anti-tamper** -- detects attempts to stop or disable Argus itself

**Characteristics:**

- Active -- operates a state machine with four modes:

  | State | Behavior |
  |-------|----------|
  | `DISARMED` | Monitoring only, no alerts |
  | `ARMED_HOME` | Normal alerting, user is present |
  | `ARMED_AWAY` | Heightened alerting, user is away |
  | `LOCKDOWN` | Maximum sensitivity, can lock the screen |

- Reports to shallotd via webhook (port 8855) or local JSONL files.
- Higher resource usage than the endpoint agent.

**Best for:** your daily-driver PC, admin workstations, machines with password vaults
or SSH keys -- your crown jewels.

Think of Argus as the elite bodyguard: deploy it only where it matters most.

---

### When to Use Which

| Scenario | Agent |
|----------|-------|
| Ubuntu server running Docker | Clove |
| Windows PC you SSH from | Argus |
| Raspberry Pi running Pi-hole | Clove |
| Daily driver laptop with KeePassXC | Argus |
| VirtualBox host with no secrets | Clove |
| VirtualBox host with SSH keys | Clove + Argus |
| NAS / file server | Clove |
| Admin workstation | Argus |

---

## 4. Quick Start

### Step 1: Set Up the Central Server

You need a dedicated Linux box. Ubuntu 22.04+ is recommended. A Raspberry Pi 4 with
4 GB RAM is sufficient for the standard profile.

Run the interactive setup wizard:

```bash
curl -fsSL https://raw.githubusercontent.com/benolenick/security-shallots/main/setup/shallot-setup | sudo bash
```

Or clone the repository and run locally:

```bash
git clone https://github.com/benolenick/security-shallots.git
cd security-shallots
sudo bash setup/shallot-setup
```

**What the wizard does:**

1. Detects your OS, available RAM, and network interfaces.
2. Asks you to choose a deployment profile:

   | Profile | RAM | Components |
   |---------|-----|------------|
   | **Micro** | 2-3 GB | Suricata + CrowdSec + shallotd + SQLite (CLI only) |
   | **Standard** | 4 GB | Full stack + Grafana + VictoriaLogs |
   | **Full** | 8 GB+ | Standard + larger ruleset + local AI model |

3. Configures your home network CIDR and monitoring interface.
4. Asks about AI triage tier and pfSense integration.
5. Installs all packages, generates `/etc/shallots/config.yaml`, creates systemd services.
6. Runs a health check and prints a summary with all service URLs.

After the wizard finishes, note the server IP -- you will need it for agent enrollment.

---

### Step 2: Deploy Clove Agents

Install Clove on every machine you want to monitor.

**Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/benolenick/security-shallots/main/setup/endpoint/clove \
  | sudo bash -s -- --manager YOUR_SERVER_IP
```

Available flags:

| Flag | Purpose |
|------|---------|
| `-m, --manager IP` | Shallotd server IP (required) |
| `-n, --name NAME` | Agent display name (default: hostname) |
| `-g, --group GROUP` | Wazuh agent group (default: "default") |
| `-p, --password PW` | Wazuh authd registration password |
| `--crowdsec` | Also install CrowdSec + firewall bouncer |
| `--skip-healthcheck` | Skip post-install connectivity checks |

**Windows (Clove only, no Argus):**

Download `clove.ps1` and run as Administrator:

```powershell
.\clove.ps1 -Manager YOUR_SERVER_IP -Wazuh
```

The Clove agent will enroll with the Wazuh manager and begin reporting events within a
few minutes.

---

### Step 3: Deploy Argus (Critical Machines Only)

For Windows machines that hold sensitive credentials or serve as admin workstations:

```powershell
.\clove.ps1 -Manager YOUR_SERVER_IP
```

This installs Argus with webhook reporting back to your shallotd server on port 8855.
To install both Argus and the Clove (Wazuh) agent on the same machine:

```powershell
.\clove.ps1 -Manager YOUR_SERVER_IP -Wazuh
```

**Controlling the state machine:**

```bash
# Arm Argus (normal monitoring)
python -m argus --config config.toml on

# Disarm Argus
python -m argus --config config.toml off

# Check current state
python -m argus --config config.toml status

# Disarm with security code (if lock hooks are installed)
python -m argus --config config.toml disarm --code 1234
```

Argus starts in `DISARMED` state. Use `on` to transition to `ARMED_HOME`. The state
machine will automatically escalate to `ARMED_AWAY` and `LOCKDOWN` based on
configured triggers.

---

### Step 4: Open the Dashboard

1. Navigate to `http://YOUR_SERVER_IP:8844` in your browser.
2. If basic auth is configured in `config.yaml`, enter your credentials.
3. You will see:
   - **Stats cards** -- total alerts, alerts by severity, AI triage breakdown.
   - **Alert feed** -- real-time stream via WebSocket, newest alerts at the top.
   - **AI query bar** -- type questions in plain English (e.g., "show SSH attacks today").
   - **Filters** -- narrow by source (suricata, wazuh, argus), severity, or AI verdict.

If the standard or full profile is installed, Grafana is also available at
`http://YOUR_SERVER_IP:3000` (default login: admin / password shown during setup).

---

## 5. Understanding Alerts

### Severity Levels

| Level | Color | Meaning |
|-------|-------|---------|
| **low** | Green | Informational, routine events |
| **medium** | Gold | Suspicious but likely benign |
| **high** | Orange | Probable threat, review promptly |
| **critical** | Red | Active threat, immediate action required |

### AI Verdicts

| Verdict | Action Required |
|---------|-----------------|
| **suppress** | Noise. No action needed. AI determined this is a false positive or routine event. |
| **investigate** | A human should review this when convenient. Not urgent but not noise. |
| **escalate** | Act now. This alert indicates a likely real threat. Email/SMS alerts fire for these. |

### Alert Sources

| Source | What It Covers |
|--------|---------------|
| **suricata** | Network-level detections: port scans, exploit attempts, malware callbacks, protocol anomalies |
| **wazuh** (Clove) | Host-level detections: failed logins, file integrity changes, rootkit checks, vulnerability findings |
| **argus** | Endpoint sentinel detections: suspicious processes, credential access, persistence changes, session anomalies |
| **crowdsec** | Community threat intelligence: known malicious IPs, brute-force sources |
| **pfsense** | Firewall events: blocked connections, filterlog entries |

### Common Alert Examples

- **ET SCAN Nmap** (suricata) -- someone is port-scanning your network.
- **sshd: authentication failure** (wazuh) -- failed SSH login attempt.
- **File integrity changed: /etc/passwd** (wazuh) -- a system file was modified.
- **Suspicious process: mimikatz.exe** (argus) -- credential dumping tool detected.
- **New RDP session from unknown IP** (argus) -- possible lateral movement.

---

## 6. Configuration Reference

> For reducing noise and teaching Shallots your normal, see **[TUNING.md](TUNING.md)**.


The main configuration file lives at `/etc/shallots/config.yaml`. It is generated
by the setup wizard but can be edited at any time. Restart shallotd after changes:

```bash
sudo systemctl restart shallot
```

### Key Sections

**profile** -- Deployment size: `auto`, `micro`, `standard`, or `full`. When set to
`auto`, shallotd detects available RAM and selects a profile.

**network** -- Your home CIDR (e.g., `192.168.0.0/16`) and the network interface to
monitor.

**components** -- Toggle individual components on or off: `suricata`, `crowdsec`,
`wazuh`, `victorialogs`, `grafana`, `syslog_receiver`, `argus`.

**ai** -- AI triage configuration (see below).

**web** -- Dashboard host, port, and optional basic auth credentials.

**alerting** -- Email, webhook, and syslog notification settings.

**storage** -- Database path and retention period (default: 30 days).

**argus** -- Argus webhook receiver settings (port 8855, shared secret).

### Enabling Email Alerts

```yaml
alerting:
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_username: "you@example.com"
    smtp_password: "your-app-password"
    from_addr: "you@example.com"
    to_addr: "you@example.com"
    min_severity: "high"
```

For Gmail, use an [App Password](https://myaccount.google.com/apppasswords) rather
than your account password. The `min_severity` field controls which alerts trigger
emails -- set to `high` to receive only high and critical alerts.

### Enabling Webhook Alerts (SMS via Twilio, Slack, etc.)

```yaml
alerting:
  webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

For SMS, use a service like Twilio with their webhook endpoint, or use a
webhook-to-SMS bridge.

### AI Tier Options

```yaml
ai:
  tier: "remote_standard"
  ollama_url: "http://192.168.0.50:11434"
  ollama_model: "foundation-sec-8b"
```

| Tier | Requirements | Notes |
|------|-------------|-------|
| `none` | Nothing | Rule-based triage only, no AI |
| `remote_micro` | Ollama endpoint, 1.5-3B model | Fast, low accuracy |
| `remote_standard` | Ollama endpoint, 8-14B model | Good balance of speed and accuracy |
| `remote_api` | OpenAI or Anthropic API key | Best accuracy, costs money |
| `local` | 8 GB+ RAM on shallotd host | Runs llama.cpp locally |

For `remote_api`, set one of:

```yaml
ai:
  tier: "remote_api"
  openai_api_key: "sk-..."
  anthropic_api_key: "sk-ant-..."
```

---

## 7. Pairing Clove with CrowdSec

By default, Clove is passive -- it detects and reports but does not block anything.
Adding CrowdSec gives it teeth.

### What CrowdSec Adds

- **Pattern detection** -- identifies brute-force attacks, port scans, and web exploits.
- **Community blocklists** -- shares threat data with the CrowdSec network and receives
  blocklists from thousands of other participants.
- **Firewall bouncer** -- automatically blocks malicious IPs at the firewall level
  (iptables/nftables).

### How to Enable

Add `--crowdsec` when deploying Clove:

```bash
curl -fsSL https://raw.githubusercontent.com/benolenick/security-shallots/main/setup/endpoint/clove \
  | sudo bash -s -- --manager YOUR_SERVER_IP --crowdsec
```

### How It Works

1. CrowdSec parses local logs (auth, web, etc.) for attack patterns.
2. Detected attackers are reported to the CrowdSec community hub.
3. In return, your node receives blocklists compiled from the entire community.
4. The firewall bouncer applies these blocklists as iptables/nftables rules.

This transforms Clove from detection-only into detection **and** response.

---

## 8. Troubleshooting

### Agent Not Connecting to Manager

**Symptoms:** Agent installed but no alerts appear; agent shows as disconnected.

**Check:**
- Ports 1514 (event transport) and 1515 (enrollment) must be open on the shallotd server.
- Verify firewall rules: `sudo ufw status` or `sudo iptables -L -n`.
- Check if fail2ban has banned the agent's IP: `sudo fail2ban-client status sshd`.
- Confirm the manager IP was entered correctly: check `/var/ossec/etc/ossec.conf` on the
  agent for the `<address>` field.

### No Alerts Appearing in Dashboard

**Symptoms:** Dashboard loads but the alert feed is empty.

**Check:**
- Verify shallotd is running: `sudo systemctl status shallot`.
- Check ingestor logs: `journalctl -u shallot -f`.
- Confirm log file permissions -- shallotd must be able to read Suricata's EVE log
  (`/var/log/suricata/eve.json`) and Wazuh alerts (`/var/ossec/logs/alerts/alerts.json`).
- If using Argus webhook mode, verify port 8855 is open and the shared secret matches.

### Dashboard Is Blank or Will Not Load

**Symptoms:** Browser shows a connection error or a blank page at port 8844.

**Check:**
- Service status: `sudo systemctl status shallot`.
- Port binding: `ss -tlnp | grep 8844`.
- Config file: verify `/etc/shallots/config.yaml` has valid YAML syntax.
- Logs: `journalctl -u shallot --since "5 minutes ago"`.

### "AI Triage Pending" on All Alerts

**Symptoms:** Alerts appear but never receive an AI verdict.

**Check:**
- Verify the AI tier is set correctly in `config.yaml`.
- For `remote_micro` or `remote_standard`: confirm the Ollama endpoint is reachable
  from the shallotd host (`curl http://OLLAMA_HOST:11434/api/tags`).
- For `remote_api`: confirm the API key is valid and has available credits.
- For `local`: ensure sufficient RAM (8 GB+) and check llama.cpp logs.

### Argus Not Reporting Events

**Symptoms:** Argus is installed but no argus-source alerts appear in the dashboard.

**Check:**
- Confirm `components.argus: true` is set in the server's `config.yaml`.
- Verify webhook settings match between the Argus endpoint and shallotd:
  port (default 8855), path (`/api/ingest/argus`), and shared secret.
- On the endpoint, check Argus status: `python -m argus --config config.toml status`.
- Check that Argus is armed: events are only generated in `ARMED_HOME`, `ARMED_AWAY`,
  or `LOCKDOWN` states.

### CrowdSec Not Blocking IPs

**Symptoms:** CrowdSec is installed but no IPs are being blocked.

**Check:**
- Service status: `sudo systemctl status crowdsec`.
- Bouncer status: `sudo cscli bouncers list`.
- Decisions: `sudo cscli decisions list` (should show active bans).
- If the list is empty, CrowdSec may not be parsing the correct log files. Check
  `sudo cscli metrics` for acquisition stats.
