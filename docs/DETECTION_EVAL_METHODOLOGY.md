# Security Shallots - Detection Value Proof: Methodology v2
(rebuilt after Codex adversarial review - 23 findings folded in)

## Narrowed claim (Codex #23)
NOT "Shallots beats AV+Snort." The honest claim:
> On a host it monitors, Shallots adds a **host-plane + DNS-lexical + drift + correlation**
> detection layer that flags behaviors a **network signature IDS (Suricata/Snort) and a
> signature AV (ClamAV-style) structurally do not**, AND it does so with a **measured
> precision (negative controls) and a known coverage envelope (evasion controls)** -
> not a cherry-picked demo.

## The test is an ENVELOPE, not a highlight reel
Every capability runs THREE cases:
- **Positive** - malicious-*shaped* behavior (neutral-named, no metadata leakage).
- **Negative control** - benign look-alike that must NOT fire (measures false positives).
- **Evasion** - what a real attacker does to slip past (measures honest false negatives).

A capability only "counts" if: positive fires AND negative stays quiet. Evasion result is
reported honestly as the coverage boundary, never hidden.

## Integrity controls (Codex #19, #21)
- Snapshot + SHA256 `posture.db` before; **run every scan against an isolated COPY** so the
  live system is never polluted and results are reproducible.
- Preflight assert: no test indicator (path/domain) exists in the copied memory tables.
- **Neutral naming**: no "test/canary/dga/beacon/shallots/.x" strings in any injected
  artifact. Findings must cite the OBSERVED behavior (path/entropy), not harness names.
- All raw artifacts (findings JSON, Suricata eve slice) archived per run.

## Baselines done honestly (Codex #15, #16)
- **Suricata**: pull ALL eve.json events (alert + dns + flow + tls) for host01 in the
  scenario window - not an indicator grep - and report what it did/didn't produce.
- **AV**: concrete baseline = ClamAV signature scan of any dropped file. Explicitly note
  that a behavior-based EDR (Defender/CrowdStrike) MIGHT catch some host cases - we do not
  claim to beat EDR, only signature AV.

## Capabilities under test (dropped the circular/weak ones)
- **C1 First-seen execution** (posture scan_execution, real `ps`):
  - pos: copy `/bin/sleep`→ writable-path, run **long-lived** → expect HIGH.
  - neg: identical long-lived process from a NORMAL path (`/bin/sleep`) → must NOT fire.
  - evasion-A: **short-lived** exec from writable path (exits before poll) → expect MISS.
  - evasion-B: exec from an **allow-listed** prefix → expect no fire (honest gap).
- **C2 DNS first-seen/high-entropy** (posture scan_dns, real Pi-hole log):
  - pos: resolve 6 genuinely high-entropy novel domains → expect finding.
  - neg: resolve real benign domains incl. a high-entropy-looking CDN host → measure FP.
  - evasion: resolve **low-entropy pronounceable** DGA-style domains → expect MISS.
  - + capture Suricata eve for the same window (does it flag NXDOMAIN/DGA?).
- **C4 Config/persistence drift** (posture scan_drift + Argus, real files):
  - pos: modify a watched config surface → expect drift finding.
  - neg: modify a NON-watched file → must NOT fire.
- **C-correlation**: already demonstrated live (deterministic FIM escalation → Granite
  incident, verified end-to-end earlier). Referenced, not re-counted here.

## Dropped / demoted (Codex #5, #9, #1-4)
- Live **beacon** (S5): posture egress is snapshot/reconnect-based → not demonstrable in a
  short window. Reported as a COMPONENT unit-test only, explicitly NOT a live-detection win.
- **Canary-read** (S3): posture only hashes canaries; read-detection needs auditd/fanotify
  we have not proven live → dropped rather than overclaim.

## Scorecard (per capability)
positive=TP? | negative=clean? (precision) | evasion=caught/missed (envelope) | Suricata did? 
→ verdict: genuine complementary signal, or not.

## Predeclared expectations (Codex #22 - written BEFORE running)
C1: pos FIRES, neg CLEAN, evasion-A MISS (polling), evasion-B no-fire (allowlist).
C2: pos FIRES, neg CLEAN (or 1 FP acceptable+reported), evasion MISS (lexical limit),
    Suricata SILENT on all (ET Open default has no NXDOMAIN-rate rule here - verify).
C4: pos FIRES, neg CLEAN.
Any deviation from these is reported as-is, including losses.
