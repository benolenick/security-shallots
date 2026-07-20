# Security Policy

## Reporting a vulnerability

Email **security@YOUR-DOMAIN.example** with subject `[shallots-security]`. Please include:

- Affected version / commit SHA
- Reproduction steps or proof of concept
- Impact assessment (what an attacker can do)

Do not open public GitHub issues for security reports. Expect an acknowledgement within
72 hours.

## Supported versions

Security Shallots is pre-1.0. Only the `main` branch receives fixes. Once a 1.0 ships,
this section will list supported minor versions.

## Scope

In scope:
- The `shallots` daemon and its HTTP API
- The `argus` Windows endpoint agent
- The web dashboard
- Default configuration shipped with the project
- Setup scripts under `setup/`

Out of scope:
- Third-party components (Suricata, Wazuh, CrowdSec, Ollama). Report to upstream.
- Configurations the operator has deviated from defaults in unsafe ways
- Self-signed TLS certs (a known operational reality of small-network deploys)

## Hardening checklist

For operators deploying Shallots:
- Replace the default dashboard credentials before exposing the dashboard.
- Restrict the dashboard to LAN or a VPN; do not expose `:8844` to the internet.
- Rotate API tokens (once Phase 3 of the roadmap ships) at least quarterly.
- Keep Suricata, Wazuh, and OS packages updated; subscribe to their advisories.
- Enable email alerting for `critical` so you actually find out.
