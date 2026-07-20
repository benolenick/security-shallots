#!/usr/bin/env python3
"""Security Shallots - detection-value evaluation harness.

Runs REAL behavior against the REAL detectors and scores an honest envelope:
positive (must fire) + negative control (must stay quiet = precision) +
evasion (reported as coverage boundary). Scans run against an isolated COPY of
posture.db so the live system is not polluted (DNS digs are real and cleaned up
from live state at the end). Neutral artifact names - findings must cite behavior.

Run on host01:  ./.venv/bin/python detection_eval.py
"""
from __future__ import annotations
import hashlib, json, os, shutil, subprocess, sys, time, tempfile, sqlite3
from pathlib import Path

ROOT = Path("/home/user/security-shallots")
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
from shallots.posture import engine as E  # real detectors

LIVE_DB = ROOT / "data" / "posture.db"
ART = Path(tempfile.mkdtemp(prefix="deval_"))
RESULTS = {"cases": [], "integrity": {}, "suricata": {}}

def sh(cmd, timeout=20):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)

def sha256(p):
    h = hashlib.sha256()
    h.update(Path(p).read_bytes())
    return h.hexdigest()[:16]

def fresh_copy():
    """Isolated copy of live posture.db (real baseline/first-seen history)."""
    dst = ART / f"copy_{time.time_ns()}.db"
    # copy main + wal so recent state is included
    con = sqlite3.connect(LIVE_DB); con.execute("PRAGMA wal_checkpoint(FULL)"); con.close()
    shutil.copy(LIVE_DB, dst)
    return dst

def open_copy():
    """Isolated copy opened with the Row factory the engine's helpers require."""
    c = sqlite3.connect(fresh_copy())
    c.row_factory = sqlite3.Row
    return c

def new_findings(con, before_ids):
    rows = con.execute("SELECT id,category,severity,title,detail FROM posture_findings").fetchall()
    return [dict(zip(("id","category","severity","title","detail"), r)) for r in rows if r[0] not in before_ids]

def finding_ids(con):
    return {r[0] for r in con.execute("SELECT id FROM posture_findings")}

def record(cap, case, kind, expected, fired, detail, cites_behavior=None):
    ok = (fired == expected)
    RESULTS["cases"].append({
        "capability": cap, "case": case, "kind": kind,
        "expected_fire": expected, "did_fire": fired, "as_expected": ok,
        "cites_behavior_not_harness": cites_behavior, "detail": detail,
    })
    tag = "OK " if ok else "!! "
    print(f"  {tag}[{cap}/{kind}] expected_fire={expected} got={fired} - {detail}")

# ── preflight integrity ───────────────────────────────────────────────
print("=== PREFLIGHT ===")
RESULTS["integrity"]["live_posture_db_sha256_16"] = sha256(LIVE_DB)
print("  live posture.db sha256:", RESULTS["integrity"]["live_posture_db_sha256_16"])
policy = E.load_policy()

# neutral names (no test/harness/shallots/dga strings)
NONCE = f"{int(time.time())%100000:05d}"
DROP_DIR = Path(f"/tmp/.font-cache-{NONCE}")
DROP_BIN = DROP_DIR / "gvfsd-metadata"          # neutral, plausible daemon name
SHORT_BIN = DROP_DIR / "gvfsd-burst"
ALLOW_DIR = ROOT / ".venv" / "tmpx"             # inside allow-listed prefix
ALLOW_BIN = ALLOW_DIR / "helper"
HI_DOMAINS = [f"{os.urandom(7).hex()}.com" for _ in range(6)]      # high-entropy, neutral
LO_DOMAINS = ["salmonbridgeriver.com","copperlanternhouse.net","greenvalleyorchard.com"]  # pronounceable evasion
BENIGN_DOMAINS = ["google.com","github.com","cloudflare.com","wikipedia.org"]

# assert no test indicator pre-exists in a copy (baseline not poisoned)
_c = sqlite3.connect(fresh_copy())
pre_exec = _c.execute("SELECT COUNT(*) FROM execution_ledger WHERE path LIKE ?", (str(DROP_DIR)+"%",)).fetchone()[0]
pre_dns = _c.execute("SELECT COUNT(*) FROM dns_memory WHERE domain IN (%s)" % ",".join("?"*len(HI_DOMAINS)), HI_DOMAINS).fetchone()[0]
_c.close()
RESULTS["integrity"]["preexisting_exec_indicator"] = pre_exec
RESULTS["integrity"]["preexisting_dns_indicator"] = pre_dns
print(f"  pre-existing test indicators: exec={pre_exec} dns={pre_dns} (must be 0)")

procs = []
try:
    # ══ C1: FIRST-SEEN EXECUTION ══════════════════════════════════════
    print("\n=== C1: first-seen execution (posture scan_execution, real ps) ===")
    DROP_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy("/bin/sleep", DROP_BIN); shutil.copy("/bin/sleep", SHORT_BIN)
    ALLOW_DIR.mkdir(parents=True, exist_ok=True); shutil.copy("/bin/sleep", ALLOW_BIN)

    # positive: long-lived exec from writable /tmp path
    procs.append(subprocess.Popen([str(DROP_BIN), "600"]))
    time.sleep(1)
    con = open_copy(); before = finding_ids(con)
    E.scan_execution(con, policy)
    nf = new_findings(con, before)
    hit = [f for f in nf if str(DROP_DIR) in (f["detail"] or "") and f["category"]=="execution"]
    record("C1-exec","positive","positive", True, bool(hit),
           (hit[0]["severity"]+": "+hit[0]["title"]+" "+hit[0]["detail"]) if hit else "no finding",
           cites_behavior=bool(hit and "font-cache" not in hit[0]["title"]))
    con.close()

    # negative control: identical long-lived process from NORMAL path
    procs.append(subprocess.Popen(["/bin/sleep","600"]))
    time.sleep(1)
    con = open_copy(); before = finding_ids(con)
    E.scan_execution(con, policy)
    nf = new_findings(con, before)
    fp = [f for f in nf if f["category"]=="execution" and "/bin/sleep" in (f["detail"] or "")]
    record("C1-exec","negative_control","negative", False, bool(fp),
           "FALSE POSITIVE on /bin/sleep" if fp else "correctly quiet on normal-path process")
    con.close()

    # evasion-A: short-lived exec (exits before poll)
    subprocess.run([str(SHORT_BIN), "0.2"]); time.sleep(0.5)
    con = open_copy(); before = finding_ids(con)
    E.scan_execution(con, policy)
    nf = new_findings(con, before)
    caught = [f for f in nf if str(SHORT_BIN) in (f["detail"] or "")]
    record("C1-exec","evasion_shortlived","evasion", False, bool(caught),
           "caught short-lived (unexpected)" if caught else "MISSED short-lived exec (honest ps-polling gap)")
    con.close()

    # evasion-B: exec from allow-listed prefix
    procs.append(subprocess.Popen([str(ALLOW_BIN), "600"]))
    time.sleep(1)
    con = open_copy(); before = finding_ids(con)
    E.scan_execution(con, policy)
    nf = new_findings(con, before)
    caught = [f for f in nf if str(ALLOW_DIR) in (f["detail"] or "")]
    record("C1-exec","evasion_allowlisted","evasion", False, bool(caught),
           "fired on allowlisted (unexpected)" if caught else "no fire on allow-listed prefix (known gap)")
    con.close()

    # ══ C2: DNS FIRST-SEEN / HIGH-ENTROPY ════════════════════════════
    print("\n=== C2: DNS high-entropy first-seen (posture scan_dns, real Pi-hole) + Suricata baseline ===")
    eve = Path("/var/log/suricata/eve.json")
    eve_off = eve.stat().st_size if eve.exists() else 0
    pihole = Path("/var/log/pihole/pihole.log")
    pihole_pre = pihole.stat().st_size if pihole.exists() else 0   # where a prior scan's offset would sit
    t0 = time.time()
    for d in HI_DOMAINS + LO_DOMAINS + BENIGN_DOMAINS:
        sh(f"dig +tries=1 +time=2 +short {d}")
    time.sleep(3)

    con = open_copy(); before = finding_ids(con)
    # steady-state: previous scan left the offset just before these digs (real cadence
    # is 10 min; the digs fall inside the new window). This is production behavior.
    E.set_kv(con, "dns_log_offset", str(pihole_pre)); con.commit()
    E.scan_dns(con)
    nf = new_findings(con, before)
    dns_hits = {f["detail"] for f in nf if f["category"]=="dns"}
    # positive
    pos_hit = [d for d in HI_DOMAINS if d in dns_hits]
    record("C2-dns","positive","positive", True, len(pos_hit)>0,
           f"flagged {len(pos_hit)}/{len(HI_DOMAINS)} high-entropy domains: {pos_hit[:3]}")
    # negative control
    neg_fp = [d for d in BENIGN_DOMAINS if d in dns_hits]
    record("C2-dns","negative_control","negative", False, len(neg_fp)>0,
           f"FALSE POSITIVE on benign {neg_fp}" if neg_fp else "correctly quiet on benign common domains")
    # evasion
    ev_caught = [d for d in LO_DOMAINS if d in dns_hits]
    record("C2-dns","evasion_pronounceable","evasion", False, len(ev_caught)>0,
           f"caught pronounceable {ev_caught}" if ev_caught else "MISSED pronounceable low-entropy DGA (honest lexical gap)")
    con.close()

    # Suricata baseline for the SAME window (full event types, not indicator grep)
    sur = {"alert":0,"dns":0,"anomaly":0,"total_lines":0,"dga_or_nxdomain_alerts":0}
    if eve.exists():
        with eve.open() as fh:
            fh.seek(eve_off)
            for line in fh:
                sur["total_lines"] += 1
                try: ev = json.loads(line)
                except Exception: continue
                et = ev.get("event_type","")
                if et in sur: sur[et]+=1
                if et=="alert":
                    sig = (ev.get("alert",{}).get("signature","") or "").lower()
                    if any(k in sig for k in ("dga","nxdomain","dns tunnel","entropy","suspicious dns")):
                        sur["dga_or_nxdomain_alerts"]+=1
    RESULTS["suricata"] = sur
    print(f"  Suricata in window: {sur['alert']} alerts, {sur['dns']} dns records, "
          f"{sur['dga_or_nxdomain_alerts']} DGA/NXDOMAIN-type alerts")

finally:
    # ── cleanup: procs, dropped files, and LIVE dns_memory pollution ──
    print("\n=== CLEANUP ===")
    for p in procs:
        try: p.terminate()
        except Exception: pass
    for d in (DROP_DIR, ALLOW_DIR):
        shutil.rmtree(d, ignore_errors=True)
    # purge test domains from LIVE posture.db (digs were real -> would poison baseline)
    try:
        lc = sqlite3.connect(LIVE_DB)
        q = ",".join("?"*len(HI_DOMAINS+LO_DOMAINS))
        n1 = lc.execute(f"DELETE FROM dns_memory WHERE domain IN ({q})", HI_DOMAINS+LO_DOMAINS).rowcount
        n2 = lc.execute("DELETE FROM posture_findings WHERE category='dns' AND detail IN (%s)" % q, HI_DOMAINS+LO_DOMAINS).rowcount
        lc.commit(); lc.close()
        print(f"  purged {n1} dns_memory + {n2} findings rows from LIVE db")
    except Exception as e:
        print("  live-db cleanup warning:", e)
    RESULTS["integrity"]["live_db_unchanged_sha_after_exec_tests"] = sha256(LIVE_DB)
    (Path.cwd()/"docs"/"DETECTION_EVAL_RESULTS.json").write_text(json.dumps(RESULTS, indent=2))
    print("  results -> docs/DETECTION_EVAL_RESULTS.json")
    shutil.rmtree(ART, ignore_errors=True)

# ── verdict ───────────────────────────────────────────────────────────
print("\n=== ENVELOPE ===")
byc = {}
for c in RESULTS["cases"]:
    byc.setdefault(c["capability"], []).append(c)
for cap, cs in byc.items():
    pos = [c for c in cs if c["kind"]=="positive"]
    neg = [c for c in cs if c["kind"]=="negative"]
    ev  = [c for c in cs if c["kind"]=="evasion"]
    pos_ok = all(c["as_expected"] for c in pos)
    neg_ok = all(c["as_expected"] for c in neg)
    print(f"  {cap}: detects={pos_ok} precision(neg quiet)={neg_ok} "
          f"evasions_missed={sum(1 for c in ev if not c['did_fire'])}/{len(ev)}")
print("\nDONE.")
