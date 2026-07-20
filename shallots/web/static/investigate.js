/* ============================================================================
   Investigate View - Security Shallots  (loads after app.js)
   Click a review item -> a plain-language investigation panel.
   Design decisions live in docs/INVESTIGATE_VIEW_SIGIL.md. Verdict-first,
   plain language, color+shape+word, progressive disclosure, graceful degrade.
   ============================================================================ */
(function () {
  "use strict";

  // ---- small self-contained helpers (don't depend on app.js internals) ----
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function relTime(iso) {
    if (!iso) return "";
    const t = Date.parse(iso);
    if (isNaN(t)) return "";
    const s = Math.round((Date.now() - t) / 1000);
    if (s < 60) return s <= 2 ? "just now" : s + "s ago";
    const m = Math.round(s / 60); if (m < 60) return m + "m ago";
    const h = Math.round(m / 60); if (h < 24) return h + "h ago";
    const d = Math.round(h / 24); if (d < 7) return d + "d ago";
    return new Date(t).toLocaleDateString();
  }

  const SEV = {
    critical: { cls: "chip--crit", shape: "⬣", word: "CRITICAL" },   // hexagon
    high:     { cls: "chip--high", shape: "▲", word: "HIGH" },        // triangle
    medium:   { cls: "chip--medium", shape: "◆", word: "MEDIUM" },    // diamond
    low:      { cls: "chip--low", shape: "●", word: "LOW" },          // circle
    benign:   { cls: "chip--benign", shape: "✓", word: "HANDLED" },
  };
  function sevChip(sev) {
    const s = SEV[(sev || "").toLowerCase()] || SEV.medium;
    return `<span class="chip ${s.cls}"><span class="shape">${s.shape}</span>${s.word}</span>`;
  }

  // assessment band -> accent color (what the user cares about: is it bad?)
  const BAND_COLOR = { danger: "#ff6b6b", bad: "#ff9f45", unsure: "#a9b2c3", normal: "#3ecf8e", routine: "#3ecf8e" };

  const CAT_ICON = {
    persistence: "⏰", lateral_movement: "↔️", session: "🔑",
    network_egress: "🌐", anti_tamper: "🛡️", file_sentinel: "📄",
  };
  const catIcon = (c) => CAT_ICON[(c || "").toLowerCase()] || "●";

  // ---------------------------------------------------------------- render --
  window.openInvestigate = async function (clusterId) {
    document.querySelector(".inv-overlay")?.remove();
    const ov = document.createElement("div");
    ov.className = "inv-overlay";
    ov.onclick = (e) => { if (e.target === ov) ov.remove(); };
    ov.innerHTML = `<div class="inv-panel"><button class="inv-close" title="Close">&times;</button>
      <div class="inv-scroll"><div style="padding:40px 0;color:#6b7488">Loading investigation…</div></div></div>`;
    ov.querySelector(".inv-close").onclick = () => ov.remove();
    document.body.appendChild(ov);
    document.addEventListener("keydown", function onEsc(e) {
      if (e.key === "Escape") { ov.remove(); document.removeEventListener("keydown", onEsc); }
    });

    let d;
    try {
      const res = await fetch(`/api/clusters/${encodeURIComponent(clusterId)}/investigate`);
      if (!res.ok) throw new Error("HTTP " + res.status);
      d = await res.json();
    } catch (err) {
      ov.querySelector(".inv-scroll").innerHTML =
        `<div class="state-degraded" style="margin:24px">Couldn't load this investigation - ${esc(err.message)}</div>`;
      return;
    }
    renderPanel(ov, clusterId, d);
  };

  function renderPanel(ov, clusterId, d) {
    const panel = ov.querySelector(".inv-panel");
    const primary = d.primary || {};
    const a = d.assessment || { key: "unsure", label: "Not sure", lead: "Here's what we found", seg: 2 };
    const host = primary.src_asset || primary.src_ip || "a machine";
    panel.style.setProperty("--sev", BAND_COLOR[a.key] || "#a9b2c3");

    const seg = (n) => `<div class="seg">${[0, 1, 2].map(i =>
      `<i class="${i < n ? "on" : ""}"></i>`).join("")}</div>`;

    // ── header ──
    const header = `
      <div class="inv-header">
        <div class="inv-chip-row">
          ${sevChip(primary.severity)}
          <span style="color:#6b7488;font-size:12px">${esc((primary.category || "").replace(/_/g, " "))}</span>
        </div>
        <h2 class="inv-headline">${esc(a.lead)}.</h2>
        <p class="inv-oneliner">${esc(d.explain || "")}</p>
        ${d.ai_reasoning ? `<p class="inv-why"><b>Why we think this:</b> ${esc(d.ai_reasoning)}</p>` : ""}
        <div class="inv-meta">
          <span>${esc(host)}</span><span class="dot">&middot;</span>
          <span>${esc(relTime(primary.ingested_at))}</span>
          ${primary.source ? `<span class="dot">&middot;</span><span>${esc(primary.source)}</span>` : ""}
        </div>
        <div class="inv-conf">
          <span class="lbl">${esc(a.label)}</span>${seg(a.seg)}
        </div>
      </div>`;

    // ── evidence ──
    const ev = d.evidence || {};
    let evidence = "";
    if (ev.kind === "diff" && (ev.added?.length || ev.removed?.length)) {
      const rows = []
        .concat((ev.removed || []).map(l => ({ g: "-", c: "diff-del", t: l })))
        .concat((ev.added || []).map(l => ({ g: "+", c: "diff-add", t: l })));
      evidence = `<div class="inv-sec"><h4>What actually changed</h4>
        <div class="diff">${rows.map(r =>
          `<div class="diff-row ${r.c}"><span class="gutter">${r.g}</span><span class="code">${esc(r.t)}</span></div>`).join("")}</div>
        ${ev.snapshot_hash ? `<div class="evidence-hash">snapshot ${esc(String(ev.snapshot_hash).slice(0, 24))}…</div>` : ""}
        ${ev.mitre_blurb ? `<div class="mitre-tag" title="${esc(ev.mitre || "")}">Technique: ${esc(ev.mitre_blurb)}</div>` : ""}
      </div>`;
    } else if (ev.raw_pretty) {
      evidence = `<div class="inv-sec"><h4>What happened</h4>
        <details class="inv-more"><summary><span class="chev">&rsaquo;</span> Show the raw event</summary>
        <div class="body"><pre class="inv-raw">${esc(ev.raw_pretty)}</pre></div></details></div>`;
    }

    // ── entities ──
    const ents = d.entities || {};
    const hostChips = (ents.hosts || []).map(h =>
      `<span class="ent"><span class="ico">🖥️</span><span class="lab">${esc(h)}</span></span>`).join("");
    const ipChips = (ents.ips || []).map(x => {
      const rep = x.reputation, v = (rep && (rep.verdict || "")).toLowerCase();
      let badge = "";
      if (rep) {
        const cls = v === "malicious" ? "rep--bad" : (v === "clean" ? "rep--ok" : "rep--unk");
        badge = `<span class="rep ${cls}">${esc(rep.verdict || "unknown")}</span>`;
      }
      return `<span class="ent"><span class="ico">🌐</span><span class="lab">${esc(x.ip)}</span>${badge}</span>`;
    }).join("");
    const entities = (hostChips || ipChips) ? `<div class="inv-sec"><h4>Machines &amp; addresses involved</h4>
      <div class="ent-grid">${hostChips}${ipChips}</div></div>` : "";

    // ── related-events timeline ──
    const rel = d.related || {};
    const roll = rel.rollup || {};
    const items = buildTimeline(rel, primary);
    let timeline = "";
    if (items.length) {
      const shown = items.slice(0, 7), extra = items.length - shown.length;
      timeline = `<div class="inv-sec"><h4>What else happened around this</h4>
        <div class="tl-rollup">In this group: <b>${roll.open || 0}</b> still open, <b>${roll.suppressed || 0}</b> already handled${roll.total ? ` of <b>${roll.total}</b>` : ""}.</div>
        <div class="tl">${shown.map(rowHtml).join("")}</div>
        ${extra > 0 ? `<button class="tl-more">View all ${items.length} related events</button>` : ""}</div>`;
    } else {
      timeline = `<div class="inv-sec"><h4>What else happened around this</h4>
        <div class="state-empty">Nothing else happened on ${esc(host)} around this time - this looks like a one-off.</div></div>`;
    }

    // ── AI chain (expandable) ──
    let chain = "";
    const ch = d.ai_chain;
    if (ch && Array.isArray(ch.chain) && ch.chain.length) {
      chain = `<div class="inv-sec"><h4>How the AI decided</h4>
        <details class="inv-more"><summary><span class="chev">&rsaquo;</span> Show how the AI decided (${ch.chain.length} step${ch.chain.length > 1 ? "s" : ""})</summary>
        <div class="body">${ch.chain.map(s => `
          <div class="inv-chain-step"><span class="tier">${esc(s.model || ("tier " + s.tier))}</span>
          <div><span class="dec" style="color:${(s.decision === "escalate" || s.decision === "malicious") ? "#ff9f45" : "#3ecf8e"}">${esc(s.decision || "")}</span>
          <div class="rat">${esc(s.rationale || s.summary || "")}</div></div></div>`).join("")}
        </div></details></div>`;
    }

    // ── Dig deeper analysis slot ──
    const analysis = `<div class="inv-sec" id="inv-analysis-sec" style="display:none">
      <h4>Deeper look</h4><div class="inv-analysis" id="inv-analysis"></div></div>`;

    // ── disposition bar ──
    const dispo = `<div class="inv-dispo">
      <button class="dispo-btn dispo-btn--primary" data-act="looks_fine">
        <span class="b-lab">✅ Looks fine</span>
        <span class="b-help">Not a threat this time - clear it, keep watching.</span></button>
      <button class="dispo-btn" data-act="its_me">
        <span class="b-lab">🏠 It's me</span>
        <span class="b-help">My own activity - stop flagging me doing exactly this.</span></button>
      <button class="dispo-btn" data-act="suppress_kind">
        <span class="b-lab">🔇 Suppress this kind</span>
        <span class="b-help">Too noisy - mute this category (reversible).</span></button>
      <button class="dispo-btn dispo-btn--deeper" data-act="dig">
        <span class="b-lab">🔬 Dig deeper</span>
        <span class="b-help">Ask the AI to explain it in more detail.</span></button>
    </div>`;

    panel.querySelector(".inv-scroll").innerHTML = header + evidence + entities + timeline + chain + analysis;
    panel.insertAdjacentHTML("beforeend", dispo);

    // timeline row clicks -> open that alert's cluster (v1: same cluster)
    panel.querySelectorAll(".tl-row[data-cluster]").forEach(r =>
      r.onclick = () => { const c = r.getAttribute("data-cluster"); if (c && c !== clusterId) window.openInvestigate(c); });

    // disposition
    panel.querySelectorAll(".dispo-btn").forEach(b =>
      b.onclick = () => disposition(ov, clusterId, d, b.getAttribute("data-act")));
  }

  function buildTimeline(rel, primary) {
    const seen = new Set();
    const rows = [];
    const push = (a, isCurrent) => {
      if (!a || !a.id || seen.has(a.id)) return;
      seen.add(a.id);
      rows.push({
        id: a.id, cluster_id: a.cluster_id, ts: a.ingested_at || a.timestamp,
        category: a.category, severity: a.severity, title: a.title, verdict: a.verdict, current: !!isCurrent,
      });
    };
    push(primary, true);
    (rel.window || []).forEach(a => push(a));
    (rel.siblings || []).forEach(a => push(a));
    rows.sort((x, y) => String(x.ts || "").localeCompare(String(y.ts || "")));
    return rows;
  }

  function rowHtml(r) {
    const cur = r.current ? " tl-row--current" : "";
    const clickable = r.cluster_id ? ` data-cluster="${esc(r.cluster_id)}"` : "";
    return `<div class="tl-row${cur}"${clickable}>
      <div class="tl-time">${esc(relTime(r.ts))}</div>
      <div class="tl-rail"><div class="tl-dot">${r.current ? "" : catIcon(r.category)}</div></div>
      <div class="tl-label">
        <span class="tl-title">${esc(r.title || r.category || "event")}</span>
        ${r.current ? `<span class="tl-current-tag">this alert</span>` : ""}
        <div class="tl-sub">${esc((r.category || "").replace(/_/g, " "))}${r.verdict ? " &middot; " + esc(r.verdict) : ""}</div>
      </div>${r.cluster_id ? `<span class="chev">&rsaquo;</span>` : ""}</div>`;
  }

  // ------------------------------------------------------------ disposition --
  async function disposition(ov, clusterId, d, act) {
    const primary = d.primary || {};
    if (act === "dig") return digDeeper(ov, clusterId);

    let verdict = "suppress", rule = null, confirmMsg = null;
    if (act === "looks_fine") {
      confirmMsg = "Mark this as fine and clear it? Shallots keeps watching for it.";
    } else if (act === "its_me") {
      if (primary.src_ip) rule = { match_type: "src_ip+title", pattern: primary.src_ip, pattern2: primary.title || "" };
      else rule = { match_type: "title", pattern: primary.title || "" };
      confirmMsg = `Stop flagging this exact activity again?\n\nRule: ${rule.match_type} = "${rule.pattern}${rule.pattern2 ? " / " + rule.pattern2 : ""}"\n(You can remove it later in Rules.)`;
    } else if (act === "suppress_kind") {
      rule = { match_type: "category", pattern: (primary.category || "").toLowerCase() };
      if (!rule.pattern) return;
      confirmMsg = `Mute the whole "${rule.pattern}" category?\n\nYou'll stop seeing these until you turn it back on in Rules.`;
    }
    if (confirmMsg && !window.confirm(confirmMsg)) return;

    const btns = ov.querySelectorAll(".dispo-btn");
    btns.forEach(b => b.disabled = true);
    try {
      await fetch(`/api/clusters/${encodeURIComponent(clusterId)}/verdict`, {
        method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verdict, reasoning: "Investigate view: " + act }),
      });
      if (rule) {
        await fetch(`/api/silence-rules`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(Object.assign({ reason: "Investigate view: " + act }, rule)),
        });
      }
      ov.remove();
      // refresh dashboard stats/lists if app.js exposes them
      if (typeof window.fetchStats === "function") window.fetchStats();
      if (typeof window.fetchAlerts === "function") window.fetchAlerts();
      document.querySelector(".pivot-overlay")?.remove();
    } catch (err) {
      btns.forEach(b => b.disabled = false);
      alert("Couldn't save that: " + err.message);
    }
  }

  async function digDeeper(ov, clusterId) {
    const sec = ov.querySelector("#inv-analysis-sec");
    const box = ov.querySelector("#inv-analysis");
    sec.style.display = "";
    box.className = "inv-analysis loading";
    box.textContent = "Asking the AI to take a closer look…";
    sec.scrollIntoView({ behavior: "smooth", block: "center" });
    try {
      const res = await fetch(`/api/clusters/${encodeURIComponent(clusterId)}/analyze`, { method: "POST" });
      const j = await res.json();
      box.className = "inv-analysis";
      box.textContent = j.analysis || j.error || "No analysis returned.";
    } catch (err) {
      box.className = "inv-analysis";
      box.textContent = "Couldn't run the analysis: " + err.message;
    }
  }
})();
