# Small-Footprint Security Posture Upgrades

Security Shallots should keep its advantage by adding context and high-signal controls before adding heavy storage or search infrastructure. The goal is not to recreate Security Onion at enterprise scale; it is to give a homelab or small fleet enough awareness to escalate things that would otherwise be missed.

*v2 — 2026-07-18. Reviewed by Codex (GPT-5.6); 30 findings folded in. Major changes from v1: unified alert-memory system, weak-label guardrails on distillation, provenance requirements on fleet memory, sensor-coverage map and time integrity added as foundations, suppression hygiene made first-class, cheap sketches (SimHash/Bloom/Markov) before neural embeddings, revised build order.*

## Design Principle

Prefer tiny, role-aware checks that answer:

- What is this asset supposed to be?
- What behavior is normal for that role?
- What changed?
- Is there nearby evidence that makes this worth escalating?
- **Have we seen this before, and what did we decide last time?**
- **Can we actually see this — or are we blind here and pretending otherwise?**

Avoid unbounded collection by default. Store enough local evidence to explain an escalation, then let a cloud or senior model inspect the compact case when the operator wants that tier.

**Spend bytes on memory, not on storage.** A sketch, a frequency table, a hash ledger, or a distilled classifier is a few KB–MB that *replaces* gigabytes of retained raw logs. The fleet already proved the shape of this with the edge Scout corpus (98–99% review-workload reduction in evals — noting those evals are synthetic streams, not adversarial replay; see §22). Every feature below follows the same rule: compact learned state instead of retention.

**Cheapest technique that works, first.** Exact match → hash/sketch (SimHash, Bloom, count-min) → statistics (rarity, CUSUM, Markov) → neural embeddings → local LLM → cloud LLM. Each tier only sees what the cheaper tier couldn't decide. Embeddings *are* model inference — cheaper than triage, but not free — so they sit above sketches, not below.

---

## Part A — Foundations (see-before-judge)

### 1. Asset Criticality Map

Maintain a small inventory that assigns each device a role and criticality tier: router/gateway, DNS/Pi-hole, NAS/backup, GPU node, workstation, IoT, guest, unknown.

Security value: the same event has different meaning depending on the target. A new outbound connection from an IoT device or DNS server matters more than the same connection from a workstation.

Footprint: tiny YAML or SQLite table. (The Phase-1 MAC-keyed inventory census is already underway — reuse it, don't rebuild.)

### 2. Sensor Coverage Map + Telemetry Health

Track **which host is visible through which sensor**: DNS (Pi-hole), auth (Argus), process, conntrack/egress, Suricata (host01's own link only — NOT a SPAN), syslog. For each (host, sensor) pair: visible / not-visible / stale, with last-seen timestamps.

On top of it, run lightweight change-point detection (CUSUM or Page–Hinkley, ~20 lines, two floats per stream) on every telemetry source's event rate:

- Rate collapses → "source went dark" (attacker killed logging, or breakage — either way, squawk).
- Rate spikes → burst worth a look before dedup hides it.
- Category-mix shift → environment changed; nudge a corpus re-audit.

Security value: attackers disable logging first, and a tiny SIEM that doesn't know its own blind spots produces *fake confidence*. Every escalation card gets a coverage stamp (§23) so no tier over-trusts a verdict formed on partial visibility.

Footprint: one small table + two floats per stream.

### 3. Time Integrity

Monitor NTP sync, clock offsets between fleet hosts, timezone mismatches, and log-delivery delay per source.

Security value: correlation, beacon detection, and sequence baselines all silently break under clock skew. Also a real intrusion signal — timestomping and clock manipulation are anti-forensics staples.

Footprint: near zero (chrony/timedatectl polls + per-source delay stats).

### 4. Service Baselines + Exposure Surface (one subsystem)

Known-good listeners and internet exposure are one surface with one collector — don't build them separately.

Per host: expected listening ports and bind addresses (Shallots hub, Pi-hole, NAS, router management). Alert on: new listener, service binding to LAN instead of localhost, expected service disappearing, service moving ports.

Same collector, lower frequency: public-IP open ports, UPnP mappings, tunnel processes (Cloudflare Tunnel, Tailscale, ngrok, chisel), and anything unexpectedly on `0.0.0.0`.

Security value: catches accidental exposure, compromised services, unexpected admin tools, and hidden tunnels.

Footprint: small periodic socket snapshots + a low-frequency scoped scan.

---

## Part B — Critical State Drift (one typed subsystem)

Identity, network control plane, and config integrity are the same mechanism — snapshot, hash, diff, typed alert — so build them as **one drift engine with typed checks**, not three tools.

### 5. Identity And Auth Drift

New users/groups, new sudoers entries, new SSH authorized keys, new cron jobs or systemd timers, failed-login bursts, successful sudo/root from unusual user, TTY, or source.

Security value: catches persistence and privilege drift with very little data volume.

### 6. Router And DNS Drift

DNS upstream changed, DHCP lease table anomalies, new gateway appears, Pi-hole config changed, unknown device joins the LAN, router syslog stops or changes pattern.

Security value: router/DNS compromise is the highest-impact event in a home network.

### 7. Config Integrity Snapshots

Hash and diff: Shallots config, Argus configs, SSH config, firewall rules, Pi-hole config, systemd unit list, router config export if available.

Security value: makes configuration drift visible and explainable.

Footprint (all of Part B): small hash tables, compact diffs, tiny polling.

### 8. First-Seen Execution Ledger (binaries + ancestry + interpreters)

Three tables, one idea — "the fleet has never seen this run before":

- **Binaries**: path + SHA256 per distinct executable per host. Flag first-ever-seen, execution from `/tmp` / `/dev/shm` / home dirs, and hash changes — **correlated against package-manager provenance** (dpkg/rpm state and upgrade windows) so routine updates don't fire.
- **Process ancestry**: per-host parent→child transition table (Markov-style counts). `nginx → bash` or `cron → curl | sh` is a rare transition worth a card even when both binaries are known. Attacks live off the land more often than they drop binaries.
- **Interpreter command lines**: SimHash of normalized shell/python/perl command lines; first-seen-cluster flag.

Optional sharpener: a handful of **targeted auditd/fanotify watches** on sensitive paths only — SSH keys, sudoers, systemd units, cron dirs, shell profiles, canary files (§13). Not broad endpoint telemetry; a dozen watch rules.

Security value: first-seen tables convert "novel code execution" into a near-zero-cost tripwire, and ancestry catches the fileless majority the binary table misses.

Footprint: a few thousand rows per host; hashing amortized (new inodes only).

---

## Part C — Network Intelligence

Honest scoping first: Suricata sees only host01's own link. LAN-wide egress and beacon detection depend on the sensors that actually exist — Argus host agents, Pi-hole logs, router syslog/conntrack where available. The coverage map (§2) records per-host what's real; features below run **per visible host** and say so.

### 9. DNS Intelligence (rarity + DGA + first-seen)

Pi-hole query logs are the highest-signal / lowest-byte source in the house. Per domain:

- **First-seen eTLD+1** via Bloom filter (fleet-lifetime) + first-seen table for the interesting ones.
- **Lexical DGA score**: character bigram/trigram log-likelihood against a model trained once on the fleet's own historical benign domains — a ~50 KB table, no neural net.
- **NXDOMAIN burst detection** per host (DGA malware's signature footprint).
- **Rare-TLD flag**; **domain-age RDAP lookup only for already-suspicious names** (RDAP is rate-limited — never lookup-first), cached forever.

Security value: nearly every intrusion phase touches DNS. Best posture-per-byte item in this document.

Footprint: one domains table + Bloom filter + 50 KB n-gram model. No packet capture — Pi-hole already logs it.

### 10. Egress Baseline By Host Role

Role-aware outbound expectations, from the sensors each host actually has: Pi-hole should talk to configured upstream DNS only; router should not initiate unusual outbound sessions; GPU nodes may talk to package mirrors, model registries, known APIs; IoT gets a narrow destination set.

Use **Bloom/HyperLogLog first-seen and cardinality tracking** per (host → dst) so "workstation contacted 400 new destinations today" is one number, not 400 rows.

Security value: strong homelab detection for beaconing, tunnels, proxy misuse, and compromised IoT.

Footprint: sketches + compact history per visible host.

### 11. Beacon & Periodicity Detector

From the same egress snapshots: per-(src, dst, port) inter-arrival stats — count, mean, coefficient of variation. Persistent low-jitter periodic connections spanning hours with small payloads = beacon candidate. Cross-check against egress allowlist and IoC feeds before carding. Requires §3 (clock sanity) to be trustworthy.

Security value: C2 beaconing is the classic thing static rules miss and periodicity math catches.

Footprint: three floats per active tuple; tuples expire after silence.

### 12. Behavioral Rarity Sketches

Per (host, event-type), (host, dst-port), (user, login-hour): rolling frequency tables or count-min sketches with weekly decay. Score events by self-information: `-log2 P(event | host)`. High rarity boosts triage priority; high frequency is a suppression *hint* (never an auto-suppress — see §19).

Add per-host **sequence baselines** (Markov transition tables) for auth flows: login → sudo → outbound network within N seconds from a first-seen source is a sequence score, not three unrelated events.

Security value: turns "is this normal for *this* box?" into a number, with zero training and zero labels.

Footprint: a few KB per host. Pure arithmetic.

---

## Part D — Deception & Tripwires

### 13. Canary Secrets And Canary Files

Fake `.env`, fake cloud-credential marker, fake SSH key, fake internal admin URL, fake backup manifest. Alert if read, copied, served, or referenced.

Honest cost note: file-read detection is **not free** — it needs the targeted auditd/fanotify watches from §8 (canary paths are on that watch list) or application-log grep for the served/referenced cases. Still among the highest signal-to-byte ratios available.

Footprint: near zero state; a few watch rules.

### 14. Honey Listener

**One** tiny LAN-only fake service on a port that should receive no legitimate traffic (e.g. fake SSH banner on a non-standard port). Alert on any connection attempt from a non-test source. One listener is signal; a farm of fake banners is maintenance burden and attack surface.

Footprint: one tiny Python service, LAN-bound.

---

## Part E — Memory & Self-Improvement

The escalation ladder produces something almost no SIEM has: continuous verdicts from senior models. But those are **weak labels with correlated blind spots, not ground truth**. Everything in this part treats them accordingly: memory can *route and prioritize* on its own; it can only *suppress* with provenance, TTLs, and audit trails.

### 15. Unified Alert Memory (one substrate, three policies)

One memory system — not separate "dedup" and "RAG" features:

**Tier 1 — SimHash near-duplicate collapse.** Normalized alert text → SimHash → near-dup of an open or recently-resolved case collapses into a counter on that case. Catches the vast majority of repeats for microseconds and ~8 bytes each. Build this before any neural embedding.

**Tier 2 — Embedding neighborhood.** Only alerts that survive Tier 1 get embedded (small local model — `nomic-embed-text` via existing Ollama, or CPU MiniLM; quantize to int8). Store in SQLite (`sqlite-vec`). Provides: novelty score (distance to corpus), nearest-benign-cluster hints, and semantic retrieval.

**Tier 3 — Verdict precedent (case-based reasoning).** Every case reaching a final state (dismissed / resolved / promoted / pinged) becomes a labeled exemplar: embedding + compact brief + verdict + rationale + **provenance (which tier/human decided) + TTL**. Before qwen3 triages a survivor, retrieve k nearest resolved exemplars as few-shot context: *"3 similar past cases, all dismissed as backup-job noise; one promoted because the source host differed."* Tier-0 stops re-deriving the same judgments and inherits elder-tier reasoning at local cost.

Prerequisites (why this isn't step 3 of the build): stable alert normalization, a fixed verdict taxonomy, and entity IDs — without those, fuzzy matching becomes a fuzzy false-suppression engine.

Footprint honestly stated: int8 384-dim ≈ 0.4 KB/vector, float32 768-dim ≈ 3 KB + index overhead — with Tier-1 collapse and pruning, tens of MB in practice, not GB. Embedding is inference: budget it (CPU, milliseconds/alert at post-SimHash volume).

### 16. Suppression Hygiene (first-class, not a footnote)

Bad suppressions are the main failure mode of this whole architecture. Every suppression — native, classifier, memory-derived, or fleet-synced — carries: reason, source/provenance, affected entities, first/last-seen, hit counter, **TTL with review date**, and a canary exception (canary events are never suppressible). Expired suppressions re-surface for one review cycle instead of silently persisting. A weekly suppression audit report lists the top hitters — each is either promoted to a documented rule or allowed to expire.

Footprint: columns on tables that already exist.

### 17. Hyphae Fleet Security Memory (with provenance, not blind trust)

Wire Shallots' durable knowledge into Hyphae (~280k facts) both ways — but treat memory as *evidence*, never *authority*:

- **Write**: operator-confirmed verdicts, suppression rationale, incident postmortems, "benign because X" decisions → Hyphae facts tagged with author, date, confidence. Survives host01 reimage and DB loss; tuning is never lost again.
- **Read**: escalation cards query recall for involved entities ("what does the fleet know about 192.168.0.129?", "is port 9105 sanctioned?"). Today's netwatch squawk on the new :9105 listener would have auto-attached the Warden Lumen-tmux ledger fact — the card ships with the answer instead of paging about it.
- **Trust model**: a Hyphae/ledger match may *downgrade* severity or annotate a card; it may **never silently suppress**. Facts are stamped with age; a 6-month-old "sanctioned" fact about a listener that just changed behavior is itself a finding. Agents can be wrong or compromised — memory written by an agent inherits that agent's trust tier, and conflicts (memory says X, live system says Y) escalate rather than resolve quietly. This is the doc's own source-precedence rule: live state > memory.
- **Cross-check**: nightly diff of Shallots' asset map + service baselines against what Hyphae believes; disagreement = stale memory or unauthorized change — both worth surfacing.

Security value: eliminates the biggest false-squawk class in an agent-run fleet — *sanctioned change Shallots doesn't know about* — without opening a memory-poisoning suppression channel.

Footprint: API calls to an existing service; zero new storage.

### 18. Confidence Calibration + Uncertainty Routing

Two small mechanisms that multiply the value of every tier:

- **Calibration ledger**: for each verdict source (qwen3, Haiku, Sonnet, distilled scorer), bucket predicted severity/confidence vs. eventual outcome. Reliability curves per source; a tier that's overconfident on a category gets its verdicts discounted there. No auto-routing on uncalibrated confidence.
- **Uncertainty sampling**: the scarce resource is senior attention (Opus, Ben). Spend it on **disagreement**, not randomness: Sigma says escalate but memory says benign; novelty high but rarity low; qwen3 low-confidence; coverage map says half-blind. Disagreement cases are also the highest-value training labels for §19.

Footprint: counters and buckets.

### 19. Elder Distillation (shadow-mode ranking, never a suppressor)

Weekly CPU batch: fit a small model (logistic regression or gradient-boosted trees; scikit-learn, seconds to train) on accumulated features → final-verdict pairs. Features: embedding vector, rarity scores, role, criticality, graph degree, coverage stamp.

Deployment ladder, strict:

1. **Shadow mode** — log scores, act on nothing, compare against ladder outcomes for weeks.
2. **Ranking hint** — score orders the triage queue and feeds §18's disagreement detector.
3. **Routing** (skip-to-brief for high scores) — only after calibration (§18) holds on human-confirmed outcomes AND the adversarial harness (§22) shows no recall loss.
4. Never an autonomous suppressor. Sigma/IoC deterministic escalation always bypasses it. Auto-rollback if weekly canary recall drops.

Why the caution: ladder labels are weak labels — distilling them naively compresses the elders' blind spots along with their judgment.

Security value: over months, cloud-spend-derived judgment becomes a free local prioritizer — the system converts its own operating history into permanent capability.

Footprint: model < 1 MB; weekly CPU training.

### 20. Federated Baseline Sync (guarded)

Extend `sync_clusters.py` so learned artifacts — corpus invariants, benign clusters, DNS n-gram model, distilled scorer — replicate fleet-wide. **Guarded**, because federating baselines across heterogeneous nodes is a classic way to spread one node's bad suppression to every node:

- Role overlays (a GPU-node baseline never applies to IoT).
- Synced suppressions arrive as **candidates** with TTLs — they annotate, and only promote to active after local confirmation (N local hits with no contradicting signal).
- Full provenance + one-command rollback of any synced artifact.
- Canary exceptions are never synced away.

Security value: herd immunity done safely; a new node bootstraps with mature baselines instead of weeks of noisy learning.

Footprint: synced artifacts are all < a few MB by construction.

---

## Part F — Escalation Contract & Verification

### 21. Explainable Escalation Cards — define the schema FIRST

The card schema is the product contract: every collector above exists to fill card fields, so the schema is designed **early** (right after Part A), not last. Each card includes:

- Asset role and criticality (§1)
- **Sensor coverage stamp** — what was visible/blind/stale for this verdict (§2)
- Expected behavior vs. observed deviation
- **Novelty + k nearest prior cases with their verdicts and provenance** (§15)
- **Rarity scores** ("first time in 90 days this host did X") (§12)
- 1-hop entity neighborhood, last 48 h (§ graph below)
- **Fleet memory check** — matching Hyphae/ledger facts with age stamps, or "no sanctioned change found" (§17)
- Relevant IoCs, packet/log evidence path
- Confidence, uncertainty, disagreement flags (§18)
- Why rules alone might have missed this

The **entity graph** feeding the neighborhood section is a small SQLite edge table — (host↔user), (host↔dst), (alert↔entity) — with hard TTLs, per-entity edge caps, and event-type filtering. Bounded aggressively or it quietly becomes a second SIEM.

Security value: a senior model (or Ben at 3 a.m.) can say yes/no in ten seconds, and every yes/no becomes a calibrated label.

Footprint: small text artifacts + a bounded edge table.

### 22. Adversarial Eval Harness

The existing eval scores (Scout F1 1.0 on synthetic streams) prove the machinery works on cooperative data. Posture claims require **adversarial replay**: scripted scenarios injected end-to-end — benign-burst floods, sanctioned-change lookalikes, DNS weirdness, synthetic low-jitter beacons, credential-persistence drops, canary touches, and **logging disablement** (the sensor-dark case). Run on a schedule; every release of a suppression, scorer, or synced baseline must keep scenario recall at 100%. Extends the existing canary-harness tooling (`shallot_rule_canary.py`, argus scout canary) from single-scenario to a scenario library.

Security value: this is what makes every other claim in this doc falsifiable.

Footprint: test code, not runtime state.

---

## Suggested Build Order

(Codex-revised: see-before-judge, cheap-before-neural, contract-before-collectors, distill-last.)

1. **Asset criticality map** (§1) — everything keys off role
2. **Sensor coverage map + telemetry health + time integrity** (§2, §3) — know your blind spots before trusting any verdict
3. **Escalation card schema** (§21) — the contract every later collector fills
4. **Service baselines + exposure surface** (§4)
5. **Critical state drift engine** (§5–7) + **suppression hygiene** (§16) — hygiene lands before any new suppression source exists
6. **DNS intelligence** (§9) — best standalone signal
7. **Rarity sketches + sequence baselines** (§12)
8. **First-seen execution ledger + targeted auditd watches** (§8)
9. **Egress baselines** (§10) → **beacon detector** (§11)
10. **Unified alert memory** — SimHash tier first, then embeddings, then verdict precedent (§15)
11. **Hyphae integration** (§17) — after provenance/trust rules exist
12. **Canary files** (§13) + **honey listener** (§14) — cheap wins once auditd watches exist
13. **Entity graph + upgraded cards** (§21 completion)
14. **Calibration + uncertainty routing** (§18)
15. **Adversarial eval harness** (§22) — before anything below gets write access to routing
16. **Elder distillation, shadow mode** (§19) — needs months of verdicts
17. **Federated sync** (§20) — last, once artifacts exist and are proven under §22

## Why This Preserves The Tiny Footprint

Compact **learned state**, not indexing:

- YAML/SQLite inventory, hashes, diffs, first-seen tables
- Bloom filters, HyperLogLog, count-min sketches (KB per host)
- Change-point detectors (two floats per stream)
- SimHash before embeddings; int8 embeddings, pruned, tens of MB bounded
- Markov transition tables (KB per host)
- A distilled classifier < 1 MB
- Short text cards, bounded edge tables, bounded evidence

Still optional / explicitly out of scope: long-term full-text search, long retention, full packet capture, per-event LLM inference (SimHash + sketches gate what embeddings see; embeddings gate what qwen3 sees; the distilled scorer eventually thins Tier-0 further), enterprise dashboards.

Hardware constraints honored: nothing runs on host01's GPU at event rate. Embedding + n-gram + sketch math is CPU at post-SimHash volume; weekly distillation is CPU; the 130 W power cap and 70 °C ceiling stay untouched.

With cloud AI enabled, the hub stays small while the **memory layer compounds**: every verdict the ladder produces makes the edge permanently smarter — routed by disagreement, guarded by provenance and TTLs, verified by adversarial replay — and Hyphae makes that knowledge survive any single machine.
