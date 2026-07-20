# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches 1.0.

## [Unreleased]

### Added
- `GAP_ANALYSIS_AND_ROADMAP.md` - phased plan for small-office productization
- GitHub Actions CI (`ruff` + `pytest` matrix on 3.10/3.11/3.12)
- Weekly `pip-audit` workflow
- `SECURITY.md` - vulnerability disclosure policy
- `setup/systemd/shallotd-home.service` - systemd unit matching the live install layout
- `tools/shallot_backup.py` - online SQLite backup with retention
- `setup/systemd/shallot-backup.{service,timer}` - hourly backup timer
- Agent-offline watchdog in `health.check_agents`
- Ollama circuit breaker with rule-based fallback and backfill

### Changed
- (none yet - see roadmap for upcoming changes)

### Deprecated
- (none yet)

### Removed
- (none yet)

### Fixed
- (none yet)

### Security
- (none yet)
