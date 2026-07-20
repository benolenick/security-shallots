#!/usr/bin/env python3
"""Edge-8b escalation gate - SHADOW MODE.
Reads real shallots alerts (READ-ONLY), runs the qwen3:8b escalation-gate
prompt on each, and logs the decision to its OWN table `edge_gate_shadow`.
Changes NOTHING in shallotd's behavior. Resumable: skips alerts already scored.

Run:   python3 edge_gate_shadow.py [--limit N] [--all] [--report]
"""
import sqlite3, json, re, time, urllib.request, sys, argparse

DB="/home/user/security-shallots/shallots.db"
URL="http://127.0.0.1:11434/api/generate"
MODEL="qwen3:8b"

TAXONOMY=("reverse-shell, C2/beacon, cryptominer, malicious-persistence "
  "(cron/systemd pulling remote code), credential-theft, data-exfiltration "
  "(large or covert/DNS egress), unauthorized-root-access, lateral-movement/scan")
FLEET_NORMAL=("KNOWN-BENIGN fleet behavior - SUPPRESS these: web scrapers via Webshare/residential "
  "proxy pools + job boards; ollama/vLLM GPU load + local :11434/:8001 + registry.ollama.ai pulls; "
  "SSH between fleet hosts on 192.168.0.0/24 (host02 .212, host03 .224, host04 .129, host01 .172); "
  "apt/unattended-upgrade; mDNS/avahi udp 5353; Umami/TLA deploy egress; host01's own Suricata "
  "self-traffic (it monitors its own NIC, so OUTBOUND scans from .172 to LAN are usually its own polling); "
  "Pi-hole DNS queries for CDN/update/telemetry domains of known services.")

def gate_prompt(d):
    return ("You are the escalation gate of an always-on edge security sentinel. For this alert you "
      "decide: ESCALATE to the on-call human, or SUPPRESS as fleet-normal noise.\n"
      f"Threat taxonomy (any genuinely present => escalate): {TAXONOMY}.\n"
      f"{FLEET_NORMAL}\n"
      "POLICIES:\n"
      "- A multi-STEP chain (remote script fetch + new persistence + unusual egress) is a real attack.\n"
      "- A fixed-size payload at near-CONSTANT interval to an external host is C2 BEACONING even if the "
      "domain mimics a CDN/telemetry vendor.\n"
      "- Covert exfil (DNS-tunnelling, many TXT queries, reads of credential/key files) is a real attack.\n"
      "- A scan/connection whose SOURCE is the monitoring host itself (host01 .172) to a LAN host is "
      "usually self-generated noise unless paired with another real indicator.\n"
      "- ASYMMETRIC COST: missing a real attack is worse than a false alarm. If a genuine external or "
      "cross-host threat indicator is present, ESCALATE. Only SUPPRESS when confident it is fleet-normal.\n\n"
      f"ALERT:\n{d}\n\n"
      'Output ONLY compact JSON: {"escalate":true|false,"severity":1-5,'
      '"threat":"<taxonomy label or none>","confidence":0.0-1.0,"why":"<=14 words"}')

def alert_digest(r):
    L=[f"source={r['source']} severity={r['severity']} category={r['category']}",
       f"title: {r['title']}"]
    if r['description']: L.append(f"desc: {str(r['description'])[:200]}")
    net=[]
    for k in ("src_ip","src_port","dst_ip","dst_port","proto"):
        if r[k] not in (None,"","0",":0"): net.append(f"{k}={r[k]}")
    if net: L.append("net: "+" ".join(net))
    for k in ("src_dns","dst_dns","src_geo","dst_geo","src_asset","dst_asset"):
        if r[k]: L.append(f"{k}={str(r[k])[:60]}")
    if r['raw']:
        raw=str(r['raw'])[:220]
        L.append(f"raw: {raw}")
    return "\n".join(L)

def call(prompt, num_predict=700, timeout=90):
    body={"model":MODEL,"prompt":prompt,"stream":False,"think":False,
          "options":{"num_ctx":4096,"temperature":0.1,"num_predict":num_predict}}
    t=time.time()
    try:
        req=urllib.request.Request(URL,data=json.dumps(body).encode(),headers={"Content-Type":"application/json"})
        r=json.load(urllib.request.urlopen(req,timeout=timeout))
        return r.get("response",""), r.get("prompt_eval_count",0)+r.get("eval_count",0), time.time()-t, None
    except Exception as e:
        return "", 0, time.time()-t, str(e)[:80]

def field(txt,key,d=None):
    m=re.search(rf'"{key}"\s*:\s*("?)([^",}}]+)\1', txt)
    return m.group(2).strip() if m else d

def ensure_table(c):
    c.execute("""CREATE TABLE IF NOT EXISTS edge_gate_shadow(
      alert_id TEXT PRIMARY KEY, created_at TEXT, model TEXT,
      escalate INTEGER, severity TEXT, threat TEXT, confidence TEXT, why TEXT,
      system_verdict TEXT, latency_ms INTEGER, tokens INTEGER, raw TEXT)""")
    c.commit()

def run(limit=None, do_all=False):
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    ensure_table(c)
    done=set(r[0] for r in c.execute("SELECT alert_id FROM edge_gate_shadow"))
    q="SELECT * FROM alerts ORDER BY id DESC"
    rows=[r for r in c.execute(q) if r['id'] not in done]
    if not do_all and limit: rows=rows[:limit]
    print(f"scoring {len(rows)} alerts ({len(done)} already done)",flush=True)
    for i,r in enumerate(rows):
        txt,tok,dt,err=call(gate_prompt(alert_digest(r)))
        esc = 1 if "true" in (field(txt,"escalate") or "").lower() else 0
        c.execute("INSERT OR REPLACE INTO edge_gate_shadow VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
          (r['id'], time.strftime("%Y-%m-%dT%H:%M:%S"), MODEL, esc,
           field(txt,"severity"), field(txt,"threat"), field(txt,"confidence"),
           (field(txt,"why") or "")[:120], r['verdict'], int(dt*1000), tok, txt[:200]))
        if i%15==0: c.commit()
        if err: print(f"  ERR {r['id'][:8]} {err}",flush=True)
    c.commit()
    report(c)

def report(c):
    c.row_factory=sqlite3.Row
    rows=list(c.execute("""SELECT g.*, a.title,a.severity AS asev,a.category,a.source
                           FROM edge_gate_shadow g JOIN alerts a ON a.id=g.alert_id"""))
    n=len(rows); esc=[r for r in rows if r['escalate']]
    sysup=[r for r in rows if r['system_verdict']=='suppress']
    sysinv=[r for r in rows if r['system_verdict']=='investigate']
    # agreement: gate should ESCALATE what system investigated, SUPPRESS what system suppressed
    gate_esc_on_sysinv=[r for r in sysinv if r['escalate']]
    gate_esc_on_sysup =[r for r in sysup if r['escalate']]      # over-escalations vs system
    gate_sup_on_sysinv=[r for r in sysinv if not r['escalate']] # candidate misses vs system
    lat=[r['latency_ms'] for r in rows if r['latency_ms']]
    print("\n===== SHADOW GATE REPORT (vs shallotd native verdict as silver reference) =====")
    print(f"alerts scored           : {n}")
    print(f"gate ESCALATE / SUPPRESS: {len(esc)} / {n-len(esc)}")
    print(f"system investigate/suppr: {len(sysinv)} / {len(sysup)}")
    print(f"agree-escalate (sys=investigate & gate=escalate): {len(gate_esc_on_sysinv)}/{len(sysinv)}")
    print(f"agree-suppress (sys=suppress & gate=suppress)   : {len(sysup)-len(gate_esc_on_sysup)}/{len(sysup)}")
    print(f"gate escalated a system-SUPPRESSED alert (review): {len(gate_esc_on_sysup)}/{len(sysup)}  = over-escalation-vs-system")
    print(f"gate suppressed a system-INVESTIGATE alert (review): {len(gate_sup_on_sysinv)}/{len(sysinv)}  = candidate MISS")
    if lat: print(f"mean latency            : {sum(lat)/len(lat)/1000:.1f}s/alert")
    print("\n--- DISAGREEMENTS: gate escalated what system suppressed (top 12) ---")
    for r in gate_esc_on_sysup[:12]:
        print(f"  [{r['category']}/{r['source']}] sev{r['severity']} {str(r['title'])[:58]} :: {r['threat']} - {r['why']}")
    print("\n--- DISAGREEMENTS: gate suppressed what system flagged investigate ---")
    for r in gate_sup_on_sysinv[:12]:
        print(f"  [{r['category']}/{r['source']}] {str(r['title'])[:58]} - {r['why']}")

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--limit",type=int,default=60)
    ap.add_argument("--all",action="store_true")
    ap.add_argument("--report",action="store_true")
    a=ap.parse_args()
    if a.report:
        c=sqlite3.connect(DB); ensure_table(c); report(c)
    else:
        run(limit=a.limit, do_all=a.all)
