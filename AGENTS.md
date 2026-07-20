# AGENTS.md — security-shallots

If you are an AI agent working on a deployed instance of security-shallots, look for:
- `SIGIL.md` in the repo root — compact operator card with commands, architecture, known gotchas
- `AI_CONTEXT.md` in the repo root — full operator guide

These files are not committed (they contain deployment-specific details). Generate them with your deployment details using `SIGIL.md.example` as a template, or read the project guide at `docs/GUIDE.md`.

For a cold start on any machine running shallots:
```bash
# Is it running?
curl -sk -u "admin:<password>" https://<host>:8844/api/health

# Tail logs
tail -f /tmp/shallotd.log

# Restart
pkill -f 'python.*shallots'
cd /path/to/security-shallots
nohup .venv/bin/python -m shallots -c config.yaml run > /tmp/shallotd.log 2>&1 &
```
