# Tuning Security Shallots

Shallots does **not** ship pre-tuned to your network - it can't, because it doesn't
know what "normal" looks like for you yet. Out of the box it errs toward *showing*
you things; tuning is the process of teaching it what to stop showing you. Budget a
few evenings over the first week or two. This guide is the map.

The golden rule: **every time you dismiss an alert as noise, ask "should I make a
rule so I never see this again?"** That habit is 90% of tuning.

---

## 1. The mental model

Alerts flow through stages, and you can tune each one:

```
ingest → CLASSIFIER (suppress/severity) → AI TRIAGE (optional) → AUTOPILOT (paging) → you
              │                                  │                      │
        suppression:            ai.tier / batch / obfuscate     autopilot.mode + squawk
        title_patterns, sig_ids,
        source/dest ips+cidrs,
        maintenance_persistence_patterns
```

- The **classifier** is deterministic and runs first. Most noise should be killed
  here - it's free, predictable, and needs no GPU.
- **AI triage** only sees what survives the classifier. If AI is off (`ai.tier: none`),
  rules decide everything and the ambiguous middle defaults to *investigate*.
- **Autopilot** decides what's worth interrupting you for (a "squawk").

Tune from the top down: quiet the classifier first, then AI, then paging.

All keys below live in `config.yaml` (copy from `config.example.yaml`). Restart
`shallotd` after edits, or use the dashboard's per-alert **Silence** button, which
hot-loads a rule without a restart.

---

## 2. The first-week soak loop

1. Install, point your router syslog at it, deploy a couple of agents.
2. Let it run **24-48h untouched.** Real baselines need real time.
3. Open the dashboard and sort by volume. The loudest sources are your tuning list.
4. For each noisy pattern, decide: *is this always benign here?*
   - Yes → add a suppression rule (below) or hit **Silence**.
   - Sometimes → leave it; that's what triage is for.
5. Re-check daily for a week. Noise drops fast once the top offenders are handled.
6. Run the gate (`tools/shallot_production_gate.py --json`) - it tells you when
   coverage and noise are in a healthy place to trust it unattended.

---

## 3. Reducing noise (the classifier)

All under the `suppression:` block. Ships **empty** - you add your own.

```yaml
suppression:
  # Suppress by alert-title substring (case-insensitive). The most common lever.
  title_patterns:
    - "Internal SSH"
    - "heartbeat overdue"
  # Suppress specific Suricata signature IDs outright.
  sig_ids:
    - 2210050        # SURICATA HTTP unable to match response
  # Suppress traffic to/from specific hosts or ranges you trust.
  source_ips:   ["192.168.0.50"]      # e.g. your NAS that scans everything
  source_cidrs: ["192.168.0.0/24"]
  dest_ips:     []
  dest_cidrs:   []
  # Mark YOUR OWN services/scripts as routine maintenance so their persistence-
  # surface changes aren't flagged as an attacker installing persistence.
  maintenance_persistence_patterns:
    - "myapp-worker.service"
    - "/opt/myapp"
```

Guidance:
- Prefer **narrow** rules. `title_patterns: ["ET SCAN"]` is fine; suppressing a whole
  `/16` because one host is chatty is how you go blind.
- `maintenance_persistence_patterns` is the fix for "my own cron job / systemd unit
  keeps getting flagged." List the path or unit name.
- The dashboard **Silence** button writes these for you and applies them live -
  the fastest way to tune day-to-day. Periodically fold them into `config.yaml` so
  they survive a rebuild.

Built-in defaults already suppress common benign chatter (LLMNR/mDNS, internal SSH
logins, package updates, Suricata stream noise) - you're only adding what's specific
to *your* network.

---

## 4. Tuning severity

Also in the classifier. Bump or drop how loud whole categories are:

```yaml
suppression:
  # (severity map lives in code defaults; override per-category here if exposed)
# Behavioral toggles (defaults shown):
#   internal→internal traffic is dampened one severity step (dampen_internal_internal)
#   external→internal traffic is amplified one step (amplify_external_internal)
```

If internal LAN traffic is too loud, the dampening is already on. If you run a flat
network where "internal" isn't trusted, that's when you'd reconsider it.

---

## 5. Tuning the AI layer

```yaml
ai:
  tier: local              # none | local | remote_api
  batch_size: 2            # alerts per LLM call - raise on a fast box, lower on a Pi
  batch_interval_sec: 900  # how often triage runs - longer = calmer, cheaper, slower
  obfuscate_cloud: false   # remote_api only: pseudonymize identifiers before sending
  autopilot:
    mode: copilot          # off | copilot | autopilot
    noise_threshold: 8     # repeats within the window before auto-noise handling
    noise_window_min: 120
    auto_silence_after: 20 # auto-silence a pattern seen this many times
    squawk_sms: false      # page for genuine danger only
```

- **`autopilot.mode`**: `off` = AI advises only; `copilot` = suggests suppressions,
  you approve; `autopilot` = acts on its own. Start at `copilot`.
- **Too many pages?** Lower what squawks - autopilot only pages for genuinely
  dangerous activity (active exploit, C2, exfil, ransomware, priv-esc). If routine
  stuff is paging you, it's usually a *classifier* miss upstream, not an AI setting.
- **Pi / no GPU:** keep `tier: none`. Rules + posture + canaries still work fully.
- **Cloud tier:** set `obfuscate_cloud: true` to strip IPs/hostnames/users before
  anything leaves your box.

---

## 6. Tuning the edge scout

The scout surfaces *candidate* missed signals (it never suppresses or pages). If it's
too eager or too quiet:

```yaml
scout:
  min_score: 2             # raise to surface only stronger candidates
  router_ip: "192.168.0.1" # lets it flag syslog spoofing the router's identity
  router_syslog_hint: "dlink"
  sensor_ips: ["192.168.0.10"]  # hosts running a local Suricata sensor
```

All the hints are optional - set them and the scout gets sharper; leave them blank
and those specific heuristics simply stay off.

---

## 7. Tuning posture (drift, canaries, expected services)

Posture lives in `data/posture_policy.yaml` (copy from `.example`). This is where you
tell Shallots what your machine is *supposed* to look like:

```yaml
expected_services:      # a service bound outside this list = drift alert
  my-server:
    - {proto: tcp, bind: 0.0.0.0, port: 8844, name: "shallots dashboard"}
execution_allow_prefixes:   # executables here are expected (your app venvs)
  - /opt/myapp/.venv/
canaries:               # decoy files - any touch is high-signal
  enabled: true
  files: [fake-prod.env, fake-backup-manifest.txt]
```

If posture is noisy, it's almost always because `expected_services` doesn't yet list
something you run on purpose. Add it.

---

## 8. Tuning what reaches you (alert delivery)

```yaml
alerting:
  ntfy:  {enabled: true, topic: "your-topic"}      # phone push, free
  email: {enabled: true, min_severity: "high"}     # raise to cut inbox noise
  sms:   {enabled: false, min_severity: "critical"}
```

Set `min_severity` per channel so only what you care about interrupts you. A common
setup: ntfy for `high`+, SMS for `critical` only, email off.

---

## 9. Instrumentation - how to know if your tuning is working

These commands are your feedback loop (all take `--json`):

```bash
tools/shallot_ops_sanity.py --json        # is the pipeline healthy?
tools/shallot_production_gate.py --json    # is it noise/coverage-ready to trust?
tools/shallot_full_stack_status.py --json  # end-to-end status
tools/shallot_posture_scan.py scan         # current drift/canary/service state
tools/shallot_posture_eval.py --json       # posture pass/fail
```

The **production gate** is the one that matters: it blocks on both *missing coverage*
(a feed you expect but aren't getting) and *excess noise* (a source drowning you). A
green gate means your tuning has reached "trust it while you sleep."

---

## 10. Hardware / profile tuning

`profile:` and the auto-detected `threat_engine.tier` scale the heavy features to your
box (a Pi runs longer intervals and smaller ML windows; a server runs tighter loops).
You rarely touch these - the defaults follow your CPU/RAM/GPU. Override
`threat_engine.tier` (`pi` | `mid` | `server`) only if auto-detection guesses wrong.

---

## TL;DR

1. Let it soak 48h.
2. Quiet the loudest sources with `suppression.*` rules (or the Silence button).
3. Tell posture what services you run on purpose.
4. Set per-channel `min_severity` so only real things page you.
5. Run `shallot_production_gate.py` until it's green - then trust it.
