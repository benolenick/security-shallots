# Disaster Recovery Runbook

## Backup contents

`tools/shallot_backup.py` produces tarballs containing:
- `shallots.db` — online SQLite snapshot via `sqlite3.backup()` (consistent, no
  writer lock)
- `config.yaml` — config at backup time

## Backup tiers and retention

| Tier | Cadence | Retention | Path |
|------|---------|-----------|------|
| Hourly | every hour (systemd timer) | 24 | `/var/lib/shallots/backups/hourly/` |
| Daily | promoted from latest hourly | 14 | `/var/lib/shallots/backups/daily/` |
| Weekly | promoted from latest hourly | 8 | `/var/lib/shallots/backups/weekly/` |

Daily/weekly are hard links by default — they cost no disk relative to hourly.

## RTO / RPO targets

- **RPO:** 1 hour (latest hourly snapshot)
- **RTO:** 5 minutes from clean host

## Restore procedure

```bash
# 1. Stop the daemon
sudo systemctl stop shallotd-home

# 2. Locate the snapshot you want
ls -lt /var/lib/shallots/backups/hourly/

# 3. Extract to a working dir
mkdir -p /tmp/shallot-restore
cd /tmp/shallot-restore
tar -xf /var/lib/shallots/backups/hourly/shallots-2026-05-06T14.tar.zst
# (use `tar -xzf` if the file ends in .gz)

# 4. Move the current db aside (do NOT delete) and put the restored db in place
sudo mv /home/user/security-shallots/shallots.db /home/user/security-shallots/shallots.db.preserved.$(date +%s)
sudo cp shallots.db /home/user/security-shallots/shallots.db
sudo chown om:om /home/user/security-shallots/shallots.db

# 5. (optional) Restore config
sudo cp config.yaml /home/user/security-shallots/config.yaml

# 6. Start the daemon
sudo systemctl start shallotd-home

# 7. Verify
curl -sk -u admin:<password> https://127.0.0.1:8844/api/health
```

## Restore drill

A successful restore drill must be performed quarterly:
1. Pick a recent snapshot.
2. Restore into a *throwaway* directory + sqlite client.
3. Run `PRAGMA integrity_check;` — expect `ok`.
4. Run `SELECT count(*) FROM alerts;` — expect non-zero.
5. Record the result in `docs/DR_DRILL_LOG.md`.

If the drill fails, treat it as a P0 incident.
