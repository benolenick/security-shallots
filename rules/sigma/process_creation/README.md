# Process-creation Sigma rules

Once command-execution capture is on (`execmon.enabled: true` + the auditd rule
in `setup/audit/shallots-exec.rules`), exec alerts carry the command line, and
the built-in Sigma engine can match `process_creation` rules against them.

The lexicon ranker already scores every command cheaply; Sigma rules add named,
community-maintained detections on top. To use the full SigmaHQ set:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma
cp -r sigma/rules/linux/process_creation/*  rules/sigma/process_creation/
# point sigma.rules_dir at rules/sigma/ in config.yaml, restart shallotd
```

`example_reverse_shell.yml` in this directory is a working starter rule.

Field mapping note: Shallots stashes the command line in the alert `description`,
so `CommandLine`, `Image`, and `ParentImage` conditions all resolve there. Use
`|contains` conditions (the community rules mostly do); exact/`endswith` matches
on `Image` will be looser than on a full EDR.
