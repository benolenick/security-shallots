# Argus

Argus is a lightweight host sentinel agent.

## Phase 1 Status
- State machine implemented: `DISARMED`, `ARMED_HOME`, `ARMED_AWAY`, `LOCKDOWN`
- Event schema v1 implemented in `argus/core/events.py`
- Daily rotated JSONL sink implemented in `argus/sinks/jsonl.py`
- Windows security event monitor implemented in `argus/monitors/windows_events.py`
- Heartbeat + state-change emission wired in daemon

## Phase 2 Status
- `process` monitor implemented: `argus/monitors/process.py`
- `file_sentinel` monitor implemented: `argus/monitors/file_sentinel.py`
- `persistence` monitor implemented: `argus/monitors/persistence.py`
- `anti_tamper` monitor implemented: `argus/monitors/anti_tamper.py`
- `session` monitor implemented: `argus/monitors/session.py`
- forensic snapshot action implemented: `argus/actions/evidence.py`
- All Phase 2 monitors are config-gated and **disabled by default**

## Phase 3 Status (Argus side)
- `webhook` sink implemented: `argus/sinks/webhook.py`
- `syslog` sink implemented: `argus/sinks/syslog.py`
- Both sinks are config-gated and **disabled by default**

## Run
```bash
python -m argus --config config.toml
```

## CLI Commands
```bash
python -m argus --config config.toml on
python -m argus --config config.toml off
python -m argus --config config.toml status
python -m argus --config config.toml disarm --code 1234
python -m argus --config config.toml install-lock-hooks --require-code
python -m argus --config config.toml remove-lock-hooks
```

## Validate config
```bash
python -m argus --config config.toml check-config
```

## Output
Argus writes one JSON event per line to:
- `~/.argus/events/argus_events_YYYY-MM-DD.jsonl` (default)

Schema includes: `version, source, timestamp, host, event_type, severity, confidence, state, title, description, category, details, actions_taken, raw`.
