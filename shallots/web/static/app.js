/**
 * Security Shallots - Dashboard SPA
 * Vanilla JS, no frameworks, no build tools.
 */

'use strict';

// ── State ──────────────────────────────────────────────────────────────────

const state = {
  alerts: [],
  page: 0,
  pageSize: 50,
  totalLoaded: 0,
  totalFiltered: 0,
  filters: { source: "", severity: "", verdict: "!suppress", timerange: "" },
  searchMode: false,     // true when showing FTS results
  ws: null,
  wsStatus: 'disconnected', // connecting | connected | disconnected
  statsInterval: null,
  queryPending: false,
  selected: new Set(),   // selected alert IDs for bulk actions
  lastStats: null,       // cached stats for tips
  focusedCard: -1,       // index of keyboard-focused card
  groupedView: true,     // default to grouped view
};

// ── DOM refs ───────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

const dom = {
  // Stats
  statReview:      $('stat-review'),
  statReviewSub:   $('stat-review-sub'),
  statThreats:     $('stat-threats'),
  statThreatsSub:  $('stat-threats-sub'),
  statAutohandled: $('stat-autohandled'),
  statYourActivity:$('stat-youractivity'),
  statAgents:      $('stat-agents'),
  statAgentsSub:   $('stat-agents-sub'),
  statAgentsCard:  $('stat-agents-card'),
  statSla:         $('stat-sla'),
  statSlaSub:      $('stat-sla-sub'),
  statSlaCard:     $('card-sla'),
  bySource:        $('by-source'),
  bySeverity:      $('by-severity'),
  // WS
  wsDot:           $('ws-dot'),
  wsLabel:         $('ws-label'),
  // Query
  queryInput:      $('query-input'),
  queryBtn:        $('query-btn'),
  queryResult:     $('query-result'),
  queryResultSum:  $('query-result-summary'),
  queryResultSql:  $('query-result-sql'),
  queryResultCnt:  $('query-result-count'),
  // Filters
  filterTimerange: $('filter-timerange'),
  filterSource:    $('filter-source'),
  filterSeverity:  $('filter-severity'),
  filterVerdict:   $('filter-verdict'),
  searchBox:       $('search-box'),
  // Correlations
  corrSection:     $('correlations-section'),
  corrList:        $('correlations-list'),
  // Alert list
  alertList:       $('alert-list'),
  alertCount:      $('alert-count'),
  btnPrev:         $('btn-prev'),
  btnNext:         $('btn-next'),
  pageInfo:        $('page-info'),
  // Bulk actions
  selectAllWrap:   $('select-all-wrap'),
  selectAllCb:     $('select-all-cb'),
  bulkToolbar:     $('bulk-toolbar'),
  bulkCount:       $('bulk-count'),
  bulkSuppress:    $('bulk-suppress'),
  bulkInvestigate: $('bulk-investigate'),
  bulkEscalate:    $('bulk-escalate'),
  bulkDeselect:    $('bulk-deselect'),
  btnSuppressAll:  $('btn-suppress-all'),
  // Tips
  tipsContainer:   $('tips-container'),
  // Toast
  toastContainer:  $('toast-container'),
  // Version / Update
  updateBadge:     $('update-badge'),
  versionText:     $('version-text'),
  updateOverlay:   $('update-overlay'),
  updateModal:     $('update-modal'),
  updateInfo:      $('update-info'),
  updateOutput:    $('update-output'),
  updateCancel:    $('update-cancel'),
  updateConfirm:   $('update-confirm'),
  // New panels
  statConnections: $('stat-connections'),
  timelineChart:   $('timeline-chart'),
  topSrcIps:       $('top-src-ips'),
  topDstIps:       $('top-dst-ips'),
  topSigs:         $('top-sigs'),
  hostsSection:    $('hosts-section'),
  hostCount:       $('host-count'),
  hostsTableWrap:  $('hosts-table-wrap'),
  vulnSection:     $('vuln-section'),
  vulnCount:       $('vuln-count'),
  vulnList:        $('vuln-list'),
  // Agents
  agentPill:       $('agent-status-pill'),
  agentPillDot:    $('agent-pill-dot'),
  agentPillLabel:  $('agent-pill-label'),
  agentsSection:   $('agents-section'),
  agentSummary:    $('agent-summary'),
  agentsGrid:      $('agents-grid'),
  aiHistorySection:$('ai-history-section'),
  aiHistoryList:   $('ai-history-list'),
  savedSearches:   $('saved-searches'),
  btnSaveSearch:   $('btn-save-search'),
  btnExport:       $('btn-export'),
  filterCount:     $('filter-count'),
  btnTheme:        $('btn-theme'),
  kbdOverlay:      $('kbd-overlay'),
  kbdClose:        $('kbd-close'),
  btnViewToggle:   $('btn-view-toggle'),
  // Incidents
  incidentsList:   $('incidents-list'),
  incidentFilter:  $('incident-filter'),
  incidentCounts:  $('incident-counts'),
  scoutCards:      $('scout-cards'),
  scoutCount:      $('scout-count'),
  scoutRefresh:    $('btn-scout-refresh'),
  securityOpsUpdated: $('security-ops-updated'),
  securityGateStatus: $('security-gate-status'),
  securityGateSub:    $('security-gate-sub'),
  securitySelfStatus: $('security-self-status'),
  securitySelfSub:    $('security-self-sub'),
  securityAgentStatus:$('security-agent-status'),
  securityAgentSub:   $('security-agent-sub'),
  securityEgressStatus:$('security-egress-status'),
  securityEgressSub:   $('security-egress-sub'),
  securityCentralStatus: $('security-central-status'),
  securityCentralSub:    $('security-central-sub'),
  securityNoiseStatus:   $('security-noise-status'),
  securityNoiseSub:      $('security-noise-sub'),
  securityQualityStatus: $('security-quality-status'),
  securityQualitySub:    $('security-quality-sub'),
  securitySuppressionStatus: $('security-suppression-status'),
  securitySuppressionSub:    $('security-suppression-sub'),
  securityLoopStatus:    $('security-loop-status'),
  securityLoopSub:       $('security-loop-sub'),
  securityNetworkStatus: $('security-network-status'),
  securityNetworkSub:    $('security-network-sub'),
  securityPublicStatus:  $('security-public-status'),
  securityPublicSub:     $('security-public-sub'),
  securitySyslogStatus:  $('security-syslog-status'),
  securitySyslogSub:     $('security-syslog-sub'),
  securityRuleStatus:    $('security-rule-status'),
  securityRuleSub:       $('security-rule-sub'),
  securityIncidentStatus:$('security-incident-status'),
  securityIncidentSub:   $('security-incident-sub'),
  securityOpsActions:    $('security-ops-actions'),
  securitySelfTableWrap: $('security-self-table-wrap'),
  securityRiskTableWrap: $('security-risk-table-wrap'),
  securityBlockerTableWrap:$('security-blocker-table-wrap'),
  securityActionTableWrap:$('security-action-table-wrap'),
  securityCommandTableWrap:$('security-command-table-wrap'),
  securityIncidentTableWrap:$('security-incident-table-wrap'),
  securityPublicTableWrap:$('security-public-table-wrap'),
  securitySuppressionTableWrap:$('security-suppression-table-wrap'),
  securityHostHealthWrap:$('security-host-health-wrap'),
  securityFleetTableWrap:$('security-fleet-table-wrap'),
  securityVolumeTableWrap:$('security-volume-table-wrap'),
  securitySourceTableWrap:$('security-source-table-wrap'),
  securityRuleTableWrap:  $('security-rule-table-wrap'),
  securityMaintTableWrap: $('security-maint-table-wrap'),
  securityBaselineTableWrap: $('security-baseline-table-wrap'),
  fleetCorner: $('fleet-corner'),
};

// ── Utilities ──────────────────────────────────────────────────────────────

function fmtTime(iso) {
  if (!iso) return '-';
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    });
  } catch { return iso; }
}

function fmtRelative(iso) {
  if (!iso) return '';
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60)  return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

function escHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function severityBadge(sev) {
  const s = (sev || 'unknown').toLowerCase();
  return `<span class="badge badge-sev-${s}">${escHtml(s)}</span>`;
}

function verdictBadge(v) {
  const verdict = (v || 'pending').toLowerCase();
  return `<span class="badge badge-v-${verdict}">${escHtml(verdict)}</span>`;
}

function sourceBadge(src) {
  const s = (src || 'unknown').toLowerCase();
  return `<span class="badge badge-src-${s}">${escHtml(s)}</span>`;
}

function toast(msg, type = 'info', duration = 4000) {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  dom.toastContainer.appendChild(el);
  setTimeout(() => el.remove(), duration);
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(
    () => toast('Copied to clipboard', 'success'),
    () => toast('Copy failed', 'error')
  );
}

function setWsStatus(status) {
  state.wsStatus = status;
  dom.wsDot.className = `ws-dot ${status}`;
  const labels = {
    connected: 'Live',
    connecting: 'Connecting…',
    disconnected: 'Offline',
  };
  dom.wsLabel.textContent = labels[status] || status;
}

function setSecurityDial(valueEl, subEl, value, sub, status) {
  if (!valueEl || !subEl) return;
  valueEl.textContent = value ?? '-';
  valueEl.className = `security-ops-value ${status || ''}`.trim();
  subEl.textContent = sub || '';
}

function firstNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function clampPercent(value) {
  const n = firstNumber(value);
  return Math.max(0, Math.min(100, n));
}

function fmtPercent(value) {
  if (value === undefined || value === null || value === '') return '-';
  return `${firstNumber(value).toFixed(firstNumber(value) % 1 ? 1 : 0)}%`;
}

function fmtMb(value) {
  if (value === undefined || value === null || value === '') return '-';
  const mb = firstNumber(value);
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)}GB`;
  return `${Math.round(mb)}MB`;
}

function fmtDuration(seconds) {
  const n = Number(seconds);
  if (!Number.isFinite(n) || n < 0) return '-';
  const days = Math.floor(n / 86400);
  const hours = Math.floor((n % 86400) / 3600);
  const minutes = Math.floor((n % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function fmtGbFromMb(value) {
  if (value === undefined || value === null || value === '') return '-';
  return `${(firstNumber(value) / 1024).toFixed(1)}GB`;
}

function healthDial(label, value, detail, status = '', displayValue = null) {
  const pct = clampPercent(value);
  const shown = displayValue !== null
    ? displayValue
    : value === undefined || value === null || value === '' ? '-' : `${Math.round(pct)}%`;
  return `
    <div class="security-health-dial ${status}" style="--dial-value:${pct}%">
      <div class="security-health-dial-ring">
        <div class="security-health-dial-value">${escHtml(shown)}</div>
      </div>
      <div class="security-health-dial-label">${escHtml(label)}</div>
      <div class="security-health-dial-detail">${escHtml(detail || '')}</div>
    </div>
  `;
}

function agentHealthCard(agent) {
  const warnings = agent.warnings || [];
  const statusClass = warnings.length ? 'warn' : String(agent.state || '').startsWith('OFFLINE') ? 'fail' : 'ok';
  const loadPct = clampPercent(firstNumber(agent.load_per_core) * 100);
  const cpuTemp = agent.cpu_temp_c === undefined || agent.cpu_temp_c === '' ? null : firstNumber(agent.cpu_temp_c);
  const cpuTempLabel = agent.cpu_temp_label ? String(agent.cpu_temp_label) : 'sensor';
  const memDetail = agent.mem_available_mb !== undefined && agent.mem_available_mb !== ''
    ? `${fmtMb(agent.mem_available_mb)} free`
    : '';
  const diskDetail = agent.disk_free_gb !== undefined && agent.disk_free_gb !== ''
    ? `${agent.disk_free_gb}GB free`
    : '';
  const gpus = Array.isArray(agent.gpus) ? agent.gpus : [];
  const gpuUtil = gpus.length ? Math.max(...gpus.map(gpu => clampPercent(gpu.util_pct))) : '';
  const gpuDetail = gpus.length
    ? gpus.map(gpu => `GPU${gpu.index}: ${fmtPercent(gpu.util_pct)} / ${fmtPercent(gpu.mem_used_pct)} vram / ${gpu.temp_c ?? '-'}C`).join(' | ')
    : 'CPU-only or no NVIDIA telemetry';
  const gpuRows = gpus.map(gpu => {
    const power = gpu.power_w !== undefined && gpu.power_limit_w !== undefined
      ? `${gpu.power_w}/${gpu.power_limit_w}W`
      : gpu.power_w !== undefined ? `${gpu.power_w}W` : '-';
    return `GPU${gpu.index} ${gpu.name || ''}: ${fmtPercent(gpu.util_pct)} util, ${fmtPercent(gpu.mem_used_pct)} vram, ${gpu.temp_c ?? '-'}C, ${power}`;
  });
  const monitors = String(agent.monitors || '').split(',').filter(Boolean);
  const loadTuple = [agent.load1, agent.load5, agent.load15]
    .filter(value => value !== undefined && value !== '')
    .map(value => firstNumber(value).toFixed(2))
    .join(' / ');
  return `
    <section class="security-host-health-card ${statusClass}">
      <div class="security-host-health-head">
        <div>
          <div class="security-host-health-name">${escHtml(agent.agent || '-')}</div>
          <div class="security-host-health-meta">${escHtml(agent.ip || '-')} · ${escHtml(agent.state || '-')} · ${fmtSecurityAge(agent.age_sec)}</div>
        </div>
        <div class="security-host-health-webhook ${agent.webhook_ok === true ? 'ok' : agent.webhook_ok === false ? 'fail' : ''}">
          ${agent.webhook_ok === true ? 'webhook ok' : agent.webhook_ok === false ? 'webhook fail' : 'webhook -'}
        </div>
      </div>
      <div class="security-host-health-dials">
        ${healthDial('CPU', agent.cpu_util_pct, `${agent.cpu_count || '-'} cores`, firstNumber(agent.cpu_util_pct) >= 85 ? 'warn' : '')}
        ${healthDial('Load', loadPct, `core ${agent.load_per_core ?? '-'}`, loadPct >= 80 ? 'warn' : '')}
        ${healthDial('Temp', cpuTemp === null ? '' : cpuTemp, cpuTempLabel, cpuTemp !== null && cpuTemp >= 80 ? 'warn' : cpuTemp === null ? 'muted' : '', cpuTemp === null ? '-' : `${Math.round(cpuTemp)}C`)}
        ${healthDial('Memory', agent.mem_used_pct, memDetail, firstNumber(agent.mem_used_pct) >= 85 ? 'warn' : '')}
        ${healthDial('Disk', agent.disk_used_pct, diskDetail, firstNumber(agent.disk_used_pct) >= 80 ? 'warn' : '')}
        ${healthDial('GPU', gpuUtil, gpuDetail, gpus.length ? '' : 'muted')}
      </div>
      <div class="security-host-health-details">
        <div><span>Uptime</span><strong>${escHtml(fmtDuration(agent.uptime_seconds))}</strong></div>
        <div><span>Load 1/5/15</span><strong>${escHtml(loadTuple || '-')}</strong></div>
        <div><span>RAM</span><strong>${escHtml(fmtMb(agent.mem_available_mb))} free / ${escHtml(fmtMb(agent.mem_total_mb))}</strong></div>
        <div><span>Disk</span><strong>${escHtml(agent.disk_free_gb !== undefined && agent.disk_free_gb !== '' ? `${agent.disk_free_gb}GB free` : '-')}</strong></div>
        <div class="wide"><span>GPU detail</span><strong>${escHtml(gpuRows.join(' | ') || 'CPU-only or no NVIDIA telemetry')}</strong></div>
      </div>
      <div class="security-host-health-foot">
        <span>${escHtml(monitors.join(', ') || 'no monitor list')}</span>
        <span>${warnings.length ? escHtml(warnings.join(', ')) : 'clean'}</span>
      </div>
    </section>
  `;
}

function fleetCornerMetric(label, value, status = '') {
  return `<span class="${status}"><b>${escHtml(label)}</b> ${escHtml(value)}</span>`;
}

function fleetCornerRow(agent) {
  const warnings = agent.warnings || [];
  const offline = String(agent.state || '').startsWith('OFFLINE');
  const statusClass = offline ? 'fail' : warnings.length ? 'warn' : 'ok';
  const gpus = Array.isArray(agent.gpus) ? agent.gpus : [];
  const gpuMax = gpus.length ? Math.max(...gpus.map(gpu => clampPercent(gpu.util_pct))) : null;
  const gpuMemMax = gpus.length ? Math.max(...gpus.map(gpu => clampPercent(gpu.mem_used_pct))) : null;
  const temp = agent.cpu_temp_c !== undefined && agent.cpu_temp_c !== '' ? `${Math.round(firstNumber(agent.cpu_temp_c))}C` : '-';
  const disk = agent.disk_used_pct !== undefined && agent.disk_used_pct !== '' ? fmtPercent(agent.disk_used_pct) : '-';
  const ram = agent.mem_used_pct !== undefined && agent.mem_used_pct !== '' ? fmtPercent(agent.mem_used_pct) : '-';
  const gpu = gpus.length ? `${Math.round(gpuMax)}%/${Math.round(gpuMemMax)}%` : 'CPU';
  return `
    <div class="fleet-corner-row ${statusClass}">
      <div class="fleet-corner-host">
        <span class="fleet-corner-dot"></span>
        <strong>${escHtml(agent.agent || '-')}</strong>
        <em>${fmtSecurityAge(agent.age_sec)}</em>
      </div>
      <div class="fleet-corner-metrics">
        ${fleetCornerMetric('CPU', fmtPercent(agent.cpu_util_pct), firstNumber(agent.cpu_util_pct) >= 85 ? 'warn' : '')}
        ${fleetCornerMetric('T', temp, firstNumber(agent.cpu_temp_c) >= 80 ? 'warn' : '')}
        ${fleetCornerMetric('RAM', ram, firstNumber(agent.mem_used_pct) >= 85 ? 'warn' : '')}
        ${fleetCornerMetric('DSK', disk, firstNumber(agent.disk_used_pct) >= 80 ? 'warn' : '')}
        ${fleetCornerMetric('GPU', gpu, gpuMax !== null && (gpuMax >= 90 || gpuMemMax >= 90) ? 'warn' : '')}
      </div>
    </div>
  `;
}

function renderFleetCorner(fleet) {
  if (!dom.fleetCorner) return;
  const agents = fleet.agents || [];
  if (!agents.length) {
    dom.fleetCorner.innerHTML = '';
    return;
  }
  const online = firstNumber(fleet.online);
  const expected = firstNumber(fleet.expected);
  const warnings = agents.reduce((count, agent) => count + ((agent.warnings || []).length ? 1 : 0), 0);
  dom.fleetCorner.innerHTML = `
    <div class="fleet-corner-head">
      <span>Fleet</span>
      <strong>${online}/${expected || agents.length}</strong>
    </div>
    ${agents.map(fleetCornerRow).join('')}
    <div class="fleet-corner-foot">${warnings ? `${warnings} warning${warnings === 1 ? '' : 's'}` : 'all clean'}</div>
  `;
}

function fmtSecurityAge(seconds) {
  const n = Number(seconds);
  if (!Number.isFinite(n)) return '-';
  if (n < 60) return `${Math.max(0, Math.round(n))}s`;
  if (n < 3600) return `${Math.round(n / 60)}m`;
  return `${Math.floor(n / 3600)}h${String(Math.round((n % 3600) / 60)).padStart(2, '0')}m`;
}

async function fetchSecurityOps() {
  if (!dom.securityGateStatus) return;
  try {
    const res = await fetch('/api/security/ops');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderSecurityOps(data);
  } catch (err) {
    setSecurityDial(dom.securityGateStatus, dom.securityGateSub, 'Error', err.message, 'fail');
    if (dom.securityOpsUpdated) dom.securityOpsUpdated.textContent = 'Snapshot unavailable';
  }
}

function renderSecurityOps(data) {
  const gate = data.production_gate || {};
  const selfAssessment = data.self_assessment || {};
  const fleet = data.fleet || {};
  const rollout = data.agent_rollout || {};
  const central = data.central_health || {};
  const noise = data.noise_housekeep || {};
  const assessment = data.assessment_loop || {};
  const network = data.network || {};
  const publicListeners = data.public_listeners || {};
  const syslogCanary = data.syslog_canary || {};
  const ruleCanary = data.rule_canary || {};
  const alerts = data.alerts || {};
  const blockers = gate.blockers || [];
  const warnings = gate.warnings || [];
  const gateStatus = gate.status || data.status || 'unknown';
  const gateClass = blockers.length ? 'blocked' : warnings.length ? 'warn' : 'ok';

  renderFleetCorner(fleet);

  setSecurityDial(
    dom.securityGateStatus,
    dom.securityGateSub,
    gateStatus,
    `${blockers.length} blockers, ${warnings.length} warnings`,
    gateClass
  );

  const readinessScore = firstNumber(selfAssessment.readiness_score);
  const selfStatus = selfAssessment.status || gateStatus;
  const selfRisks = selfAssessment.risks || [];
  setSecurityDial(
    dom.securitySelfStatus,
    dom.securitySelfSub,
    selfAssessment.readiness_score !== undefined ? `${readinessScore}/100` : '-',
    `${selfStatus}; ${selfRisks.length} risk(s)`,
    selfStatus === 'ready' ? 'ok' : selfStatus === 'blocked' ? 'blocked' : 'warn'
  );

  const online = firstNumber(fleet.online);
  const expected = firstNumber(fleet.expected);
  const warningAgents = fleet.warning_agents || [];
  const agentWarnings = warningAgents.length;
  const firstAgentWarning = warningAgents[0] || {};
  const agentWarningSub = firstAgentWarning.agent
    ? `${firstAgentWarning.agent}: disk ${firstAgentWarning.disk_used_pct ?? '-'}%`
    : `${agentWarnings} agent warning(s)`;
  setSecurityDial(
    dom.securityAgentStatus,
    dom.securityAgentSub,
    expected ? `${online}/${expected}` : '-',
    agentWarnings ? agentWarningSub : 'heartbeats current',
    agentWarnings || online < expected ? 'warn' : 'ok'
  );

  const covered = (rollout.covered_agents || []).length;
  const rolloutExpected = (rollout.expected_agents || []).length;
  const rolloutBlockers = rollout.blockers || [];
  const remaining = rollout.remaining_agents || [];
  let rolloutSub = rollout.canary_ready ? 'canary ready' : 'canary warming';
  if (rolloutBlockers.length) {
    rolloutSub = rolloutBlockers.join(', ');
  } else if (remaining.length) {
    rolloutSub = `remaining: ${remaining.join(', ')}`;
  }
  setSecurityDial(
    dom.securityEgressStatus,
    dom.securityEgressSub,
    rolloutExpected ? `${covered}/${rolloutExpected}` : '-',
    rolloutSub,
    rolloutBlockers.length ? 'blocked' : rollout.canary_ready ? 'ok' : 'warn'
  );

  setSecurityDial(
    dom.securityCentralStatus,
    dom.securityCentralSub,
    central.status || '-',
    ((central.checks || []).find(c => c.name === 'central_api_health') || {}).detail || 'service/API',
    central.status === 'ok' ? 'ok' : 'fail'
  );

  const prune = ((noise.synthetic_prune || {}).status) || {};
  const nextEligible = prune.next_eligible_in_hours;
  setSecurityDial(
    dom.securityNoiseStatus,
    dom.securityNoiseSub,
    noise.status || '-',
    nextEligible !== undefined ? `next prune ~${nextEligible}h` : `${noise.suppression_applied || 0} suppressed`,
    noise.status === 'ok' ? 'ok' : 'warn'
  );

  const residue = alerts.synthetic_residue || {};
  const qualityWarnings = alerts.guardrail_warnings || [];
  const visible24h = firstNumber(alerts.last_24h_visible);
  const syntheticCount = firstNumber(residue.count);
  const syntheticPct = firstNumber(residue.percent_raw);
  const realRawRate = firstNumber(alerts.real_raw_per_hour_24h);
  const syntheticRate = firstNumber(alerts.synthetic_per_hour_24h);
  const qualityNextEligible = residue.next_eligible_in_hours;
  const qualityValue = visible24h === 0 ? 'quiet' : String(visible24h);
  const qualitySub = syntheticCount
    ? `${syntheticCount} synthetic (${syntheticPct}%), real/h ${realRawRate}, synth/h ${syntheticRate}, prune ~${qualityNextEligible ?? '-'}h`
    : `${alerts.last_24h_raw || 0} raw / 24h, real/h ${realRawRate}`;
  setSecurityDial(
    dom.securityQualityStatus,
    dom.securityQualitySub,
    qualityValue,
    qualitySub,
    qualityWarnings.length ? 'warn' : 'ok'
  );

  const suppression = alerts.suppression_quality || {};
  const suppressionWarnings = alerts.suppression_warnings || suppression.warnings || [];
  const suppressedHigh = firstNumber(suppression.suppressed_high_or_critical);
  const suppressedCritical = firstNumber(suppression.suppressed_critical);
  const suppressionStatus = suppression.status || (suppressionWarnings.length ? 'warn' : 'ok');
  const suppressionSub = `${suppressedHigh} high/critical suppressed${suppressedCritical ? `, ${suppressedCritical} critical` : ''}`;
  setSecurityDial(
    dom.securitySuppressionStatus,
    dom.securitySuppressionSub,
    suppressionStatus,
    suppressionSub,
    suppressionWarnings.length ? 'warn' : suppressionStatus === 'ok' ? 'ok' : 'warn'
  );

  const loopAge = assessment.latest_log_age_sec;
  const loopSub = loopAge !== undefined && loopAge !== null
    ? `log ${Math.round(Number(loopAge) / 60)}m ago`
    : 'log age unknown';
  setSecurityDial(
    dom.securityLoopStatus,
    dom.securityLoopSub,
    assessment.status || '-',
    loopSub,
    assessment.status === 'ok' ? 'ok' : 'warn'
  );

  const networkBlockers = (network.blocking_gaps || []).length;
  const networkActive = (network.active_sources_window_24h || []).join(', ') || 'none';
  setSecurityDial(
    dom.securityNetworkStatus,
    dom.securityNetworkSub,
    network.status || '-',
    networkBlockers ? `${networkBlockers} expected source gap(s)` : `active: ${networkActive}`,
    networkBlockers ? 'blocked' : 'ok'
  );

  const publicUnexpected = publicListeners.unexpected || [];
  const publicWarnings = publicListeners.warnings || [];
  const publicCount = firstNumber(publicListeners.unexpected_count !== undefined
    ? publicListeners.unexpected_count
    : publicUnexpected.length);
  const publicFirst = publicUnexpected[0] || {};
  const publicSub = publicCount
    ? `${publicFirst.process || 'unknown'}:${publicFirst.port || '?'}`
    : publicListeners.status || 'ok';
  setSecurityDial(
    dom.securityPublicStatus,
    dom.securityPublicSub,
    String(publicCount),
    publicWarnings.length ? publicWarnings[0] : publicSub,
    publicCount ? 'blocked' : publicListeners.status === 'warn' ? 'warn' : 'ok'
  );

  const syslogAge = syslogCanary.age_sec;
  const syslogSub = syslogAge !== undefined && syslogAge !== null
    ? `${syslogCanary.matched || 0} matched, ${Math.round(Number(syslogAge) / 60)}m ago`
    : `${syslogCanary.matched || 0} matched`;
  setSecurityDial(
    dom.securitySyslogStatus,
    dom.securitySyslogSub,
    syslogCanary.status || '-',
    syslogSub,
    syslogCanary.status === 'ok' ? 'ok' : syslogCanary.status === 'warn' ? 'warn' : 'fail'
  );

  const ruleCoverage = ruleCanary.coverage || {};
  const ruleGuardrails = ruleCanary.coverage_guardrails || {};
  const quietHeadroom = ((ruleGuardrails.quiet || {}).headroom_cases);
  const sourceHeadroom = (((ruleGuardrails.sources || {}).headroom_cases) || {});
  const sourceHeadroomText = Object.keys(sourceHeadroom).length
    ? Object.keys(sourceHeadroom).sort().map(source => `${source}:${sourceHeadroom[source]}`).join(' ')
    : 'source headroom unknown';
  const ruleSub = quietHeadroom !== undefined
    ? `${firstNumber(ruleCanary.passed)}/${firstNumber(ruleCanary.passed) + firstNumber(ruleCanary.failed)} passing; qh=${quietHeadroom}; ${sourceHeadroomText}`
    : `${firstNumber(ruleCanary.passed)}/${firstNumber(ruleCanary.passed) + firstNumber(ruleCanary.failed)} cases passing; ${Object.keys((ruleCoverage.sources) || {}).join(', ') || 'coverage unknown'}`;
  setSecurityDial(
    dom.securityRuleStatus,
    dom.securityRuleSub,
    ruleCanary.status || '-',
    ruleSub,
    ruleCanary.status === 'ok' ? 'ok' : 'fail'
  );

  const incidents = (alerts.incident_candidates || []).length;
  setSecurityDial(
    dom.securityIncidentStatus,
    dom.securityIncidentSub,
    String(incidents),
    `${alerts.last_24h_visible || 0} visible alerts / 24h`,
    incidents ? 'blocked' : 'ok'
  );

  if (dom.securityOpsUpdated) {
    const age = noise.age_sec !== undefined ? `cleanup ${Math.round(noise.age_sec)}s ago` : 'snapshot current';
    dom.securityOpsUpdated.textContent = age;
  }

  if (dom.securityOpsActions) {
    const actions = (gate.next_actions || []).slice(0, 6);
    dom.securityOpsActions.innerHTML = actions.length
      ? actions.map(action => `<div class="security-ops-action">${escHtml(action)}</div>`).join('')
      : '<div class="security-ops-action">No production gate actions.</div>';
  }

  if (dom.securitySelfTableWrap) {
    const sections = selfAssessment.sections || [];
    dom.securitySelfTableWrap.innerHTML = sections.length ? `
      <table class="security-self-table">
        <thead>
          <tr>
            <th>Assessment Section</th>
            <th>Status</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          ${sections.map(section => {
            const status = section.status || '-';
            const statusClass = status === 'ok' ? 'ok' : status === 'blocked' ? 'fail' : 'warn';
            return `
              <tr class="${statusClass}">
                <td>${escHtml(section.name || '-')}</td>
                <td>${escHtml(status)}</td>
                <td>${escHtml(section.detail || '-')}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    ` : '<div class="security-ops-action">Self-assessment sections unavailable.</div>';
  }

  if (dom.securityRiskTableWrap) {
    const risks = selfAssessment.risks || [];
    const strengths = selfAssessment.strengths || [];
    dom.securityRiskTableWrap.innerHTML = risks.length || strengths.length ? `
      <table class="security-risk-table">
        <thead>
          <tr>
            <th>Finding</th>
            <th>Severity</th>
            <th>Domain</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          ${risks.slice(0, 8).map(risk => {
            const severity = risk.severity || 'normal';
            const statusClass = severity === 'high' ? 'fail' : severity === 'normal' ? 'warn' : 'ok';
            return `
              <tr class="${statusClass}">
                <td>Risk</td>
                <td>${escHtml(severity)}</td>
                <td>${escHtml(risk.domain || '-')}</td>
                <td>${escHtml(risk.risk || '-')}</td>
              </tr>
            `;
          }).join('')}
          ${strengths.slice(0, 6).map(strength => `
            <tr class="ok">
              <td>Strength</td>
              <td>ok</td>
              <td>-</td>
              <td>${escHtml(strength || '-')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : '<div class="security-ops-action">No self-assessment risks or strengths.</div>';
  }

  if (dom.securityBlockerTableWrap) {
    const blockerReview = selfAssessment.blocker_review || [];
    dom.securityBlockerTableWrap.innerHTML = blockerReview.length ? `
      <table class="security-blocker-table">
        <thead>
          <tr>
            <th>Gate Item</th>
            <th>Kind</th>
            <th>Tier</th>
            <th>Age</th>
            <th>Owner</th>
            <th>Urgency</th>
            <th>Action</th>
            <th>Verify</th>
          </tr>
        </thead>
        <tbody>
          ${blockerReview.slice(0, 12).map(item => {
            const tier = item.tier || '-';
            const statusClass = tier === 'overdue' || tier === 'stale' ? 'fail' : tier === 'aging' || item.needs_operator ? 'warn' : 'ok';
            const commands = item.commands || [];
            return `
              <tr class="${statusClass}">
                <td>${escHtml(item.name || '-')}</td>
                <td>${escHtml(item.kind || '-')}</td>
                <td>${escHtml(tier)}</td>
                <td>${escHtml(item.age || fmtSecurityAge(item.age_sec))}</td>
                <td>${escHtml(item.owner || '-')}</td>
                <td>${escHtml(item.urgency || '-')}</td>
                <td>${escHtml(item.action || '-')}</td>
                <td>${commands.length ? `<code>${escHtml(commands[0])}</code>` : '-'}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    ` : '<div class="security-ops-action">No active gate items in blocker review.</div>';
  }

  if (dom.securityActionTableWrap) {
    const actionItems = gate.action_items || [];
    dom.securityActionTableWrap.innerHTML = actionItems.length ? `
      <table class="security-action-table">
        <thead>
          <tr>
            <th>Action Domain</th>
            <th>Owner</th>
            <th>Urgency</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${actionItems.slice(0, 8).map(item => `
            <tr class="${item.urgency === 'high' ? 'fail' : 'warn'}">
              <td>${escHtml(item.domain || '-')}</td>
              <td>${escHtml(item.owner || '-')}</td>
              <td>${escHtml(item.urgency || '-')}</td>
              <td>${escHtml(item.action || '-')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : '<div class="security-ops-action">No categorized gate actions.</div>';
  }

  if (dom.securityCommandTableWrap) {
    const commands = gate.remediation_commands || [];
    dom.securityCommandTableWrap.innerHTML = commands.length ? `
      <table class="security-command-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Verification / Planning Command</th>
          </tr>
        </thead>
        <tbody>
          ${commands.slice(0, 10).map((command, index) => `
            <tr class="ok">
              <td>${index + 1}</td>
              <td><code>${escHtml(command || '-')}</code></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : '<div class="security-ops-action">No remediation commands.</div>';
  }

  if (dom.securityIncidentTableWrap) {
    const candidates = alerts.incident_candidates || [];
    dom.securityIncidentTableWrap.innerHTML = candidates.length ? `
      <table class="security-incident-table">
        <thead>
          <tr>
            <th>Incident Candidate</th>
            <th>Severity</th>
            <th>Source</th>
            <th>Rule Hits</th>
            <th>Verdict</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          ${candidates.slice(0, 12).map(item => {
            const severity = String(item.severity || '').toLowerCase();
            const statusClass = severity === 'critical' ? 'fail' : severity === 'high' ? 'warn' : 'ok';
            const rules = (item.rule_hits || []).map(hit => hit.rule_id || hit.reason || '').filter(Boolean).join(', ');
            return `
              <tr class="${statusClass}">
                <td>${escHtml(item.asset || item.title || '-')}</td>
                <td>${escHtml(item.severity || '-')}</td>
                <td>${escHtml(item.source || '-')}</td>
                <td>${escHtml(rules || 'legacy')}</td>
                <td>${escHtml(item.verdict || '-')}</td>
                <td>${item.timestamp ? escHtml(fmtTime(item.timestamp)) : '-'}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    ` : '<div class="security-ops-action">No incident candidates in the current assessment window.</div>';
  }

  if (dom.securityPublicTableWrap) {
    const rows = publicUnexpected;
    dom.securityPublicTableWrap.innerHTML = rows.length || publicWarnings.length ? `
      <table class="security-public-table">
        <thead>
          <tr>
            <th>Bind</th>
            <th>Port</th>
            <th>Process</th>
            <th>PID</th>
            <th>Reason</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${rows.slice(0, 12).map(item => `
            <tr class="fail">
              <td>${escHtml(item.bind || item.proto || '-')}</td>
              <td>${escHtml(item.port || '-')}</td>
              <td>${escHtml(item.process || '-')}</td>
              <td>${escHtml(item.pid || '-')}</td>
              <td>${escHtml(item.reason || '-')}</td>
              <td>${escHtml(item.action || 'review bind/firewall/allowlist')}</td>
            </tr>
          `).join('')}
          ${!rows.length && publicWarnings.length ? publicWarnings.slice(0, 6).map(warning => `
            <tr class="warn">
              <td>-</td>
              <td>-</td>
              <td>-</td>
              <td>-</td>
              <td>${escHtml(warning || '-')}</td>
              <td>review</td>
            </tr>
          `).join('') : ''}
        </tbody>
      </table>
    ` : '<div class="security-ops-action">No unexpected public listeners.</div>';
  }

  if (dom.securitySuppressionTableWrap) {
    const examples = alerts.suppression_review_examples || [];
    dom.securitySuppressionTableWrap.innerHTML = examples.length ? `
      <table class="security-suppression-table">
        <thead>
          <tr>
            <th>Suppression Review</th>
            <th>Severity</th>
            <th>Category</th>
            <th>Count</th>
            <th>Latest</th>
            <th>Title</th>
          </tr>
        </thead>
        <tbody>
          ${examples.slice(0, 6).map(item => {
            const severity = String(item.severity || '').toLowerCase();
            const statusClass = severity === 'critical' ? 'fail' : severity === 'high' ? 'warn' : 'ok';
            const latest = item.latest_age_hours !== undefined
              ? `${firstNumber(item.latest_age_hours)}h ago`
              : item.latest_seen ? fmtTime(item.latest_seen) : '-';
            return `
              <tr class="${statusClass}">
                <td>${escHtml(item.asset || '-')}</td>
                <td>${escHtml(item.severity || '-')}</td>
                <td>${escHtml(item.category || item.source_ref || '-')}</td>
                <td>${firstNumber(item.count)}</td>
                <td>${escHtml(latest)}</td>
                <td>${escHtml(item.title || '-')}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    ` : '<div class="security-ops-action">No real suppressed-alert review examples.</div>';
  }

  if (dom.securityHostHealthWrap) {
    const agents = fleet.agents || [];
    dom.securityHostHealthWrap.innerHTML = agents.length ? `
      <div class="security-host-health-grid">
        ${agents.map(agentHealthCard).join('')}
      </div>
    ` : '<div class="security-ops-action">Host health rows unavailable.</div>';
  }

  if (dom.securityFleetTableWrap) {
    const agents = fleet.agents || [];
    dom.securityFleetTableWrap.innerHTML = agents.length ? `
      <table class="security-fleet-table">
        <thead>
          <tr>
            <th>Box</th>
            <th>State</th>
            <th>Age</th>
            <th>Load/Core</th>
            <th>Mem</th>
            <th>Disk</th>
            <th>Events</th>
            <th>Webhook</th>
            <th>Warnings</th>
          </tr>
        </thead>
        <tbody>
          ${agents.map(agent => {
            const warnings = agent.warnings || [];
            const statusClass = warnings.length ? 'warn' : String(agent.state || '').startsWith('OFFLINE') ? 'fail' : 'ok';
            const events = `${firstNumber(agent.events_emitted)}/${firstNumber(agent.non_heartbeat_events)}`;
            const disk = agent.disk_used_pct !== undefined && agent.disk_used_pct !== ''
              ? `${agent.disk_used_pct}%${agent.disk_free_gb !== undefined && agent.disk_free_gb !== '' ? ` / ${agent.disk_free_gb}GB` : ''}`
              : '-';
            return `
              <tr class="${statusClass}">
                <td>${escHtml(agent.agent || '-')}</td>
                <td>${escHtml(agent.state || '-')}</td>
                <td>${fmtSecurityAge(agent.age_sec)}</td>
                <td>${agent.load_per_core ?? '-'}</td>
                <td>${agent.mem_used_pct !== undefined && agent.mem_used_pct !== '' ? `${agent.mem_used_pct}%` : '-'}</td>
                <td>${disk}</td>
                <td>${events}</td>
                <td>${agent.webhook_ok === true ? 'ok' : agent.webhook_ok === false ? 'fail' : '-'}</td>
                <td>${warnings.length ? escHtml(warnings.join(', ')) : '-'}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    ` : '<div class="security-ops-action">Fleet resource rows unavailable.</div>';
  }

  if (dom.securityVolumeTableWrap) {
    const volumeRows = alerts.volume_by_host_24h || [];
    dom.securityVolumeTableWrap.innerHTML = volumeRows.length ? `
      <table class="security-volume-table">
        <thead>
          <tr>
            <th>Source</th>
            <th>Raw/Day</th>
            <th>Real Raw</th>
            <th>Visible</th>
            <th>Suppressed</th>
            <th>Synthetic</th>
          </tr>
        </thead>
        <tbody>
          ${volumeRows.map(row => {
            const visible = firstNumber(row.visible);
            const realRaw = firstNumber(row.real_raw);
            const synthetic = firstNumber(row.synthetic_or_experiment);
            const raw = firstNumber(row.raw);
            const statusClass = visible ? 'fail' : realRaw ? 'warn' : synthetic ? 'synthetic' : 'ok';
            return `
              <tr class="${statusClass}">
                <td>${escHtml(row.host || '-')}</td>
                <td>${firstNumber(row.raw_per_day || raw)}</td>
                <td>${realRaw}</td>
                <td>${visible}</td>
                <td>${firstNumber(row.suppressed)}</td>
                <td>${synthetic}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    ` : '<div class="security-ops-action">No alert volume rows in the last 24h.</div>';
  }

  if (dom.securitySourceTableWrap) {
    const sources = data.external_sources || [];
    dom.securitySourceTableWrap.innerHTML = sources.length ? `
      <table class="security-source-table">
        <thead>
          <tr>
            <th>Network Source</th>
            <th>Status</th>
            <th>Expected IPs</th>
            <th>UI</th>
            <th>Identity</th>
            <th>Latest</th>
            <th>Diagnosis</th>
          </tr>
        </thead>
        <tbody>
          ${sources.map(source => {
            const reach = source.reachability || [];
            const uiReachable = reach.some(item => item.tcp80 || item.tcp443);
            const status = source.status || '-';
            const statusClass = status === 'ok' ? 'ok' : status === 'missing' ? 'fail' : 'warn';
            const ui = reach.length
              ? reach.map(item => `${item.ip || '-'}:${item.tcp80 ? '80' : ''}${item.tcp80 && item.tcp443 ? '/' : ''}${item.tcp443 ? '443' : ''}`).join(', ')
              : '-';
            const fingerprints = source.fingerprints || {};
            const identity = Object.entries(fingerprints).map(([ip, fp]) => {
              const parts = [];
              if (fp.title) parts.push(fp.title);
              if (fp.template_version) parts.push(`tpl ${fp.template_version}`);
              if (fp.server) parts.push(fp.server);
              if (!parts.length && fp.cert_subject) parts.push(fp.cert_subject);
              return parts.length ? `${ip}: ${parts.join(' / ')}` : '';
            }).filter(Boolean).join(', ') || '-';
            return `
              <tr class="${statusClass}">
                <td>${escHtml(source.name || '-')}</td>
                <td>${escHtml(status)}</td>
                <td>${escHtml((source.src_ips || []).join(', ') || '-')}</td>
                <td>${uiReachable ? escHtml(ui) : '-'}</td>
                <td>${escHtml(identity)}</td>
                <td>${source.latest ? escHtml(fmtTime(source.latest)) : '-'}</td>
                <td>${escHtml(source.diagnosis || source.next_step || '-')}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    ` : '<div class="security-ops-action">No expected network sources configured.</div>';
  }

  if (dom.securityRuleTableWrap) {
    const cases = ruleCanary.cases || [];
    dom.securityRuleTableWrap.innerHTML = cases.length ? `
      <table class="security-rule-table">
        <thead>
          <tr>
            <th>Rule Case</th>
            <th>Source</th>
            <th>Status</th>
            <th>Expected</th>
            <th>Actual</th>
          </tr>
        </thead>
        <tbody>
          ${cases.map(item => `
            <tr class="${item.ok ? 'ok' : 'fail'}">
              <td>${escHtml(item.name || '-')}</td>
              <td>${escHtml(item.source || '-')}</td>
              <td>${item.ok ? 'ok' : 'fail'}</td>
              <td>${escHtml((item.expected || []).join(', ') || '-')}</td>
              <td>${escHtml((item.actual || []).join(', ') || '-')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : '<div class="security-ops-action">Rule canary cases unavailable.</div>';
  }

  if (dom.securityMaintTableWrap) {
    const pruneStatus = ((noise.synthetic_prune || {}).status) || {};
    const trim = noise.assessment_log_trim || {};
    const gateWatch = data.gate_watch || {};
    const blockerReview = selfAssessment.blocker_review || [];
    const operatorReview = blockerReview.filter(item => item.needs_operator);
    const oldestReview = blockerReview[0] || {};
    const blockerAges = gateWatch.blocker_age_sec || {};
    const oldestBlockerAge = Object.values(blockerAges).reduce((max, value) => {
      const age = Number(value);
      return Number.isFinite(age) && age > max ? age : max;
    }, 0);
    const rows = [
      {
        name: 'Assessment Timer',
        status: assessment.status || '-',
        detail: `${assessment.timer_active ? 'active' : 'inactive'}; log ${fmtSecurityAge(assessment.latest_log_age_sec)} ago`,
        warn: (assessment.warnings || []).join(', '),
      },
      {
        name: 'Gate Drift Watch',
        status: gateWatch.status || '-',
        detail: `${(gateWatch.stable_blockers || []).length} stable blockers; ${(gateWatch.new_blockers || []).length} new; ${operatorReview.length} need operator; oldest ${oldestReview.name || '-'} ${oldestReview.age || fmtSecurityAge(oldestBlockerAge)} ${oldestReview.tier || ''}; ${oldestReview.action || 'review gate item'}`,
        warn: (gateWatch.warnings || []).join(', '),
      },
      {
        name: 'Noise Housekeeping',
        status: noise.status || '-',
        detail: `${firstNumber(noise.suppression_applied)} suppressions; ${firstNumber(pruneStatus.prune_eligible)} prune eligible`,
        warn: (noise.warnings || []).join(', '),
      },
      {
        name: 'Assessment Log',
        status: trim.trimmed ? 'trimmed' : 'ok',
        detail: `${firstNumber(trim.sections_after)} sections; ${firstNumber(trim.bytes_after)} bytes`,
        warn: trim.exists === false ? 'missing' : '',
      },
    ];
    dom.securityMaintTableWrap.innerHTML = `
      <table class="security-maint-table">
        <thead>
          <tr>
            <th>Maintenance Loop</th>
            <th>Status</th>
            <th>Detail</th>
            <th>Warnings</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(row => {
            const statusClass = row.warn ? 'warn' : row.status === 'ok' || row.status === 'stable' ? 'ok' : row.status === '-' ? 'warn' : 'warn';
            return `
              <tr class="${statusClass}">
                <td>${escHtml(row.name)}</td>
                <td>${escHtml(row.status)}</td>
                <td>${escHtml(row.detail)}</td>
                <td>${escHtml(row.warn || '-')}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;
  }

  if (dom.securityBaselineTableWrap) {
    const baseline = alerts.rate_baseline || {};
    const current = baseline.current || {};
    const previous = baseline.previous_hourly_avg || {};
    const quiet = baseline.quiet_streak_hours || {};
    const adaptive = baseline.adaptive_thresholds || {};
    const perHost = baseline.per_host || [];
    const baselineWarnings = baseline.warnings || [];
    const rows = [
      ['Raw', 'raw'],
      ['Real Raw', 'real_raw'],
      ['Actionable', 'actionable'],
      ['Visible', 'visible'],
    ];
    dom.securityBaselineTableWrap.innerHTML = `
      <table class="security-baseline-table">
        <thead>
          <tr>
            <th>Alert Baseline</th>
            <th>Current Hour</th>
            <th>Prev Hour Avg</th>
            <th>Adaptive Limit</th>
            <th>Quiet Streak</th>
            <th>Warnings</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(([label, key]) => {
            const warn = baselineWarnings.filter(item => String(item).includes(key));
            const statusClass = warn.length ? 'warn' : 'ok';
            return `
              <tr class="${statusClass}">
                <td>${label}</td>
                <td>${firstNumber(current[key])}</td>
                <td>${firstNumber(previous[key])}</td>
                <td>${firstNumber((adaptive[key] || {}).threshold)}</td>
                <td>${firstNumber(quiet[key])}h</td>
                <td>${escHtml(warn.join(', ') || '-')}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
      <table class="security-baseline-table security-host-baseline-table">
        <thead>
          <tr>
            <th>Host Baseline</th>
            <th>Current Real</th>
            <th>Current Actionable</th>
            <th>Current Visible</th>
            <th>Prev Real Avg</th>
            <th>Prev Actionable Avg</th>
            <th>Quiet Actionable</th>
            <th>Warnings</th>
          </tr>
        </thead>
        <tbody>
          ${perHost.length ? perHost.slice(0, 12).map(item => {
            const currentHost = item.current || {};
            const previousHost = item.previous_hourly_avg || {};
            const quietHost = item.quiet_streak_hours || {};
            const warnings = item.warnings || [];
            const statusClass = warnings.length ? 'warn' : 'ok';
            return `
              <tr class="${statusClass}">
                <td>${escHtml(item.host || '-')}</td>
                <td>${firstNumber(currentHost.real_raw)}</td>
                <td>${firstNumber(currentHost.actionable)}</td>
                <td>${firstNumber(currentHost.visible)}</td>
                <td>${firstNumber(previousHost.real_raw)}</td>
                <td>${firstNumber(previousHost.actionable)}</td>
                <td>${firstNumber(quietHost.actionable)}h</td>
                <td>${escHtml(warnings.join(', ') || '-')}</td>
              </tr>
            `;
          }).join('') : '<tr class="warn"><td colspan="8">No host baseline rows yet</td></tr>'}
        </tbody>
      </table>
    `;
  }
}

// ── Stats ──────────────────────────────────────────────────────────────────

async function fetchStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.lastStats = data;

    // Overview cards
    const review  = data.needs_review     ?? 0;
    const threats = data.threats_external  ?? 0;
    animateCount(dom.statReview,       review);
    animateCount(dom.statThreats,      threats);
    animateCount(dom.statAutohandled,  data.auto_handled   ?? 0);
    animateCount(dom.statYourActivity, data.your_activity   ?? 0);

    // Color threats card: green when 0, red when > 0
    const threatsCard = $('card-threats');
    if (threatsCard) {
      threatsCard.className = threats > 0 ? 'stat-card critical stat-clickable' : 'stat-card low stat-clickable';
      if (dom.statThreatsSub) dom.statThreatsSub.textContent = threats > 0 ? 'from outside your network' : 'all clear';
    }
    // Color review card: green when 0
    const reviewCard = $('card-review');
    if (reviewCard) {
      reviewCard.className = review > 0 ? 'stat-card medium stat-clickable' : 'stat-card low stat-clickable';
    }

    // Agents stat card
    if (data.agents_total !== undefined && dom.statAgents) {
      const aOnline = data.agents_online ?? 0;
      const aTotal = data.agents_total ?? 0;
      const aOffline = data.agents_offline ?? 0;
      dom.statAgents.textContent = `${aOnline}/${aTotal}`;
      if (aOffline > 0) {
        dom.statAgentsSub.textContent = `${aOffline} offline`;
        dom.statAgentsSub.style.color = 'var(--sev-critical)';
        if (dom.statAgentsCard) dom.statAgentsCard.className = 'stat-card critical';
      } else if (aTotal > 0) {
        dom.statAgentsSub.textContent = 'all online';
        dom.statAgentsSub.style.color = 'var(--sev-low)';
        if (dom.statAgentsCard) dom.statAgentsCard.className = 'stat-card low';
      } else {
        dom.statAgentsSub.textContent = 'endpoint monitors';
        dom.statAgentsSub.style.color = '';
        if (dom.statAgentsCard) dom.statAgentsCard.className = 'stat-card';
      }
    }

    // SLA stats
    if (dom.statSla) {
      const stale = data.sla_stale_count || 0;
      const oldestMin = data.sla_oldest_pending_min || 0;
      const mttr = data.sla_mttr_min || 0;
      dom.statSla.textContent = stale;
      if (stale > 0) {
        const ageStr = oldestMin > 1440 ? `${Math.floor(oldestMin/1440)}d old` :
                       oldestMin > 60 ? `${Math.floor(oldestMin/60)}h old` : `${oldestMin}m old`;
        dom.statSlaSub.textContent = `oldest: ${ageStr}`;
        dom.statSlaSub.style.color = stale > 50 ? 'var(--sev-critical)' : stale > 10 ? 'var(--sev-high)' : 'var(--sev-medium)';
        dom.statSlaCard.className = stale > 50 ? 'stat-card critical stat-clickable' : stale > 10 ? 'stat-card high stat-clickable' : 'stat-card medium stat-clickable';
      } else {
        dom.statSlaSub.textContent = mttr > 0 ? `MTTR: ${mttr}m` : 'all clear';
        dom.statSlaSub.style.color = 'var(--sev-low)';
        dom.statSlaCard.className = 'stat-card low stat-clickable';
      }
    }

    // Source breakdown
    renderBreakdown(dom.bySource,   data.by_source   || {}, {
      suricata: 'var(--src-suricata)',
      wazuh:    'var(--src-wazuh)',
      crowdsec: 'var(--src-crowdsec)',
      pfsense:  'var(--src-pfsense)',
      syslog:   'var(--src-syslog)',
    });

    // Severity breakdown
    renderBreakdown(dom.bySeverity, data.by_severity || {}, {
      critical: 'var(--sev-critical)',
      high:     'var(--sev-high)',
      medium:   'var(--sev-medium)',
      low:      'var(--sev-low)',
    });

  } catch (err) {
    console.error('fetchStats error:', err);
    toast(`Dashboard stats unavailable: ${err.message}`, 'error', 8000);
  }
}

function animateCount(el, target) {
  if (!el) return;
  const current = parseInt(el.textContent, 10) || 0;
  if (current === target) return;
  el.textContent = target.toLocaleString();
}

function renderBreakdown(container, data, colorMap) {
  if (!container) return;
  const total = Object.values(data).reduce((a, b) => a + b, 0) || 1;
  const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]);

  container.innerHTML = sorted.map(([key, cnt]) => {
    const pct = Math.round((cnt / total) * 100);
    const color = colorMap[key] || 'var(--text-muted)';
    return `
      <div class="breakdown-row">
        <span class="breakdown-label">${escHtml(key)}</span>
        <div class="breakdown-bar-wrap">
          <div class="breakdown-bar" style="width:${pct}%;background:${color}"></div>
        </div>
        <span class="breakdown-count">${cnt.toLocaleString()}</span>
      </div>`;
  }).join('');

  if (!sorted.length) {
    container.innerHTML = '<div class="empty-state" style="padding:0.5rem">No data</div>';
  }
}

// ── Alert list ─────────────────────────────────────────────────────────────

async function fetchAlerts(page = 0) {
  state.searchMode = false;
  state.page = page;

  const params = new URLSearchParams({
    limit:  state.pageSize,
    offset: page * state.pageSize,
  });
  if (state.filters.source)    params.set('source',   state.filters.source);
  if (state.filters.severity)  params.set('severity', state.filters.severity);
  if (state.filters.verdict)   params.set('verdict',  state.filters.verdict);
  if (state.filters.timerange) params.set('since',    state.filters.timerange);

  const endpoint = state.groupedView ? '/api/clusters' : '/api/alerts';

  try {
    dom.alertList.innerHTML = `<div class="empty-state"><span class="loading-spinner"></span>Loading alerts…</div>`;
    const clusterParams = new URLSearchParams({ limit: String(state.pageSize), offset: String(page * state.pageSize) });
    if (state.filters.verdict) clusterParams.set('verdict', state.filters.verdict);
    const fetchParams = state.groupedView ? clusterParams : params;
    const res = await fetch(`${endpoint}?${fetchParams}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    if (state.groupedView) {
      const clusters = data.clusters || [];
      state.totalFiltered = data.total ?? 0;
      renderClusterList(clusters);
      updatePagination(clusters.length, page);
    } else {
      state.alerts = data.alerts || [];
      state.totalFiltered = data.total ?? state.alerts.length;
      renderAlertList(state.alerts);
      updatePagination(state.alerts.length, page);
    }

    if (dom.filterCount) {
      const f = state.filters;
      const hasFilter = f.source || f.severity || f.verdict || f.timerange;
      dom.filterCount.textContent = hasFilter ? `${state.totalFiltered.toLocaleString()} matching` : '';
    }
  } catch (err) {
    console.error('fetchAlerts error:', err);
    dom.alertList.innerHTML = `<div class="empty-state">Failed to load alerts: ${escHtml(err.message)}</div>`;
  }
}

async function searchAlerts(query) {
  if (!query.trim()) {
    fetchAlerts(0);
    return;
  }
  state.searchMode = true;
  state.page = 0;

  try {
    dom.alertList.innerHTML = `<div class="empty-state"><span class="loading-spinner"></span>Searching…</div>`;
    const res = await fetch(`/api/alerts/search?q=${encodeURIComponent(query)}&limit=${state.pageSize}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.alerts = data.results || [];
    dom.alertCount.textContent = `${state.alerts.length} result(s) for "${escHtml(query)}"`;
    renderAlertList(state.alerts);
    // Hide pagination in search mode
    updatePagination(state.alerts.length, 0, true);
  } catch (err) {
    console.error('searchAlerts error:', err);
    dom.alertList.innerHTML = `<div class="empty-state">Search failed: ${escHtml(err.message)}</div>`;
  }
}

function renderAlertList(alerts) {
  if (!alerts.length) {
    const hasFilter = state.filters.source || state.filters.severity ||
                      state.filters.verdict || state.filters.timerange;
    const context = state.searchMode ? 'no-search-results' :
                    hasFilter ? 'no-filter-results' : 'no-alerts';
    dom.alertList.innerHTML = smartEmptyState(context);
    dom.alertCount.textContent = '0 alerts';
    dom.selectAllWrap.style.display = 'none';
    return;
  }
  dom.alertCount.textContent = `${alerts.length} alert${alerts.length !== 1 ? 's' : ''}`;
  dom.alertList.innerHTML = alerts.map(a => buildAlertCard(a)).join('');

  // Show select-all checkbox
  dom.selectAllWrap.style.display = 'inline-flex';

  // Attach expand listeners, checkbox handlers, and verdict buttons
  dom.alertList.querySelectorAll('.alert-card').forEach(card => {
    const summary = card.querySelector('.alert-summary');
    const cb = card.querySelector('.alert-select-cb');

    // Checkbox click - don't expand card
    if (cb) {
      cb.addEventListener('click', e => {
        e.stopPropagation();
        const aid = cb.dataset.alertId;
        if (cb.checked) {
          state.selected.add(aid);
          card.classList.add('selected');
        } else {
          state.selected.delete(aid);
          card.classList.remove('selected');
        }
        updateBulkToolbar();
      });
    }

    summary.addEventListener('click', (e) => {
      // Don't expand if clicking the checkbox
      if (e.target.classList.contains('alert-checkbox')) return;
      const wasExpanded = card.classList.contains('expanded');
      card.classList.toggle('expanded');
      // Fetch reputation + notes + context on first expand
      if (!wasExpanded && !card.dataset.repLoaded) {
        card.dataset.repLoaded = '1';
        enrichCardReputation(card);
        loadNotes(card);
        loadAlertContext(card);
      }
    });
    const rawBtn = card.querySelector('.raw-json-toggle');
    if (rawBtn) {
      rawBtn.addEventListener('click', e => {
        e.stopPropagation();
        const block = card.querySelector('.raw-json-block');
        block.classList.toggle('visible');
        rawBtn.textContent = block.classList.contains('visible')
          ? 'Hide raw JSON' : 'Show raw JSON';
      });
    }
    wireVerdictButtons(card);
    wireAckButton(card);
    wireNotesInput(card);
    wireSilenceButton(card);
    wireWhatIsThis(card);
    wireCopyButtons(card);
    wireAiButtons(card);
    wirePivotClicks(card);
  });
}

function buildAlertCard(a) {
  const ts    = fmtTime(a.timestamp || a.ingested_at);
  const rel   = fmtRelative(a.timestamp || a.ingested_at);
  const flow  = buildFlow(a);
  const rawJson = escHtml(JSON.stringify(
    (() => { try { return JSON.parse(a.raw || '{}'); } catch { return a.raw; } })(),
    null, 2
  ));

  const reasoningHtml = a.ai_reasoning
    ? `<div class="reasoning-block">
         <div class="reasoning-label">AI Reasoning</div>
         ${escHtml(a.ai_reasoning)}
       </div>`
    : '';

  const copyableFields = new Set(['Src IP', 'Dst IP', 'Sig ID']);
  const clickableFields = new Set(['Src IP', 'Dst IP', 'Src Port', 'Dst Port', 'Sig ID']);
  const detailFields = [
    ['ID',           a.id],
    ['Source Ref',   a.source_ref],
    ['Category',     a.category],
    ['Protocol',     a.proto],
    ['Src IP',       a.src_ip],
    ['Src Port',     a.src_port || ''],
    ['Dst IP',       a.dst_ip],
    ['Dst Port',     a.dst_port || ''],
    ['Src GEO',      a.src_geo],
    ['Dst GEO',      a.dst_geo],
    ['Src DNS',      a.src_dns],
    ['Dst DNS',      a.dst_dns],
    ['Src Asset',    a.src_asset],
    ['Dst Asset',    a.dst_asset],
    ['Confidence',   a.confidence != null ? `${(a.confidence * 100).toFixed(0)}%` : ''],
    ['Sig ID',       a.signature_id || ''],
    ['Ingested',     a.ingested_at ? fmtTime(a.ingested_at) : ''],
    ['Dedup Hash',   a.dedup_hash],
  ].filter(([, v]) => v !== '' && v !== null && v !== undefined);

  const detailGridHtml = detailFields.map(([k, v]) => {
    const copyBtn = copyableFields.has(k)
      ? ` <button class="copy-btn" data-copy="${escHtml(String(v))}" title="Copy">&#x29C9;</button>`
      : '';
    const ipBadgeSlot = (k === 'Src IP' || k === 'Dst IP')
      ? `<span class="ip-history-slot" data-ip="${escHtml(String(v))}"></span>`
      : '';
    const valStr = clickableFields.has(k)
      ? `<a class="detail-pivot" data-pivot-field="${escHtml(k)}" data-pivot-value="${escHtml(String(v))}" title="Filter by ${escHtml(k)}: ${escHtml(String(v))}">${escHtml(String(v))}</a>`
      : escHtml(String(v));
    return `<div class="detail-field">
      <span class="detail-key">${escHtml(k)}</span>
      <span class="detail-val">${valStr}${copyBtn}${ipBadgeSlot}</span>
    </div>`;
  }).join('');

  // Build IOC text for copy button (comprehensive)
  const iocParts = [
    a.title,
    a.src_ip && `src_ip: ${a.src_ip}${a.src_port ? ':' + a.src_port : ''}`,
    a.dst_ip && `dst_ip: ${a.dst_ip}${a.dst_port ? ':' + a.dst_port : ''}`,
    a.proto && `proto: ${a.proto}`,
    a.signature_id && `sig_id: ${a.signature_id}`,
    a.category && `category: ${a.category}`,
    a.source && `source: ${a.source}`,
    a.severity && `severity: ${a.severity}`,
    (a.timestamp || a.ingested_at) && `time: ${a.timestamp || a.ingested_at}`,
  ].filter(Boolean).join('\n');
  const copyIocBtn = `<button class="copy-btn copy-ioc-btn" data-copy="${escHtml(iocParts)}" title="Copy all IOCs to clipboard">&#x29C9; Copy IOCs</button>`;

  const acked = a.acknowledged_at;
  const verdictButtons = `
    <div class="verdict-actions" data-alert-id="${escHtml(a.id)}">
      <span class="verdict-actions-label">Set verdict:</span>
      <button class="verdict-btn v-suppress${a.verdict === 'suppress' ? ' active' : ''}" data-verdict="suppress" data-tooltip="Benign / false positive - hide from feed">Suppress</button>
      <button class="verdict-btn v-investigate${a.verdict === 'investigate' ? ' active' : ''}" data-verdict="investigate" data-tooltip="Needs human review - keep on radar">Investigate</button>
      <button class="verdict-btn v-escalate${a.verdict === 'escalate' ? ' active' : ''}" data-verdict="escalate" data-tooltip="Confirmed threat - escalate to incident response">Escalate</button>
      <button class="ack-btn${acked ? ' acked' : ''}" data-alert-id="${escHtml(a.id)}" title="${acked ? 'Unacknowledge' : 'Acknowledge'}">${acked ? 'Ack\'d' : 'Ack'}</button>
      <button class="btn btn-sm btn-pivot-card" onclick="event.stopPropagation(); openPivotView([${a.src_ip ? "'" + escHtml(a.src_ip) + "'" : ''}${a.src_ip && a.dst_ip ? ',' : ''}${a.dst_ip ? "'" + escHtml(a.dst_ip) + "'" : ''}].filter(Boolean))">Pivot</button>
      <button class="btn btn-sm btn-silence-card" onclick="event.stopPropagation(); silenceAndForget('${escHtml(a.id)}', '${escHtml((a.title || '').replace(/'/g, "\\'"))}')">Silence</button>
    </div>`;

  const checked = state.selected.has(a.id) ? ' checked' : '';

  return `
    <div class="alert-card${state.selected.has(a.id) ? ' selected' : ''}" data-id="${escHtml(a.id)}">
      <div class="alert-summary">
        <input type="checkbox" class="alert-checkbox alert-select-cb" data-alert-id="${escHtml(a.id)}"${checked} title="Select for bulk action" />
        <div class="alert-badges">
          ${severityBadge(a.severity)}
          ${sourceBadge(a.source)}
          ${verdictBadge(a.verdict)}
        </div>
        <div class="alert-main">
          <div class="alert-title">${escHtml(a.title || '(no title)')}</div>
          <div class="alert-meta">
            ${flow ? `<span class="alert-flow">${escHtml(flow)}</span>` : ''}
            ${a.category ? `<span>${escHtml(a.category)}</span>` : ''}
            ${a.description ? `<span>${escHtml(a.description.slice(0, 80))}${a.description.length > 80 ? '…' : ''}</span>` : ''}
          </div>
        </div>
        <div class="alert-time">
          <div>${rel || ts}</div>
          <span class="alert-chevron">&#9656;</span>
        </div>
      </div>
      <div class="alert-detail">
        <div class="context-slot" data-alert-id="${escHtml(a.id)}"></div>
        ${verdictButtons}
        <div class="ai-actions" data-alert-id="${escHtml(a.id)}">
          <button class="ai-btn ai-explain" data-action="explain" data-alert-id="${escHtml(a.id)}">Explain This</button>
          <button class="ai-btn ai-remediate" data-action="remediate" data-alert-id="${escHtml(a.id)}">What Should I Do?</button>
          <button class="ai-btn ai-hunt" data-action="hunt" data-alert-id="${escHtml(a.id)}">Hunt From Here</button>
        </div>
        <div class="ai-response-slot" data-alert-id="${escHtml(a.id)}"></div>
        <div class="ai-chat-panel" data-alert-id="${escHtml(a.id)}" style="display:none">
          <div class="ai-chat-history" data-alert-id="${escHtml(a.id)}"></div>
          <div class="ai-chat-input-wrap">
            <input type="text" class="ai-chat-input" placeholder="Ask a follow-up question..." data-alert-id="${escHtml(a.id)}" />
            <button class="btn ai-chat-send" data-alert-id="${escHtml(a.id)}">Ask</button>
          </div>
        </div>
        <div class="detail-actions-row">
          <button class="copy-btn copy-title-btn" data-copy="${escHtml(a.title || '')}" title="Copy title">&#x29C9; Title</button>
          ${copyIocBtn}
        </div>
        <div class="detail-grid">${detailGridHtml}</div>
        ${reasoningHtml}
        <div class="related-alerts-slot" data-alert-id="${escHtml(a.id)}"></div>
        <div class="notes-section" data-alert-id="${escHtml(a.id)}">
          <div class="notes-header">Investigation Notes</div>
          <div class="notes-list" id="notes-${escHtml(a.id)}"></div>
          <div class="notes-input-wrap">
            <input type="text" class="notes-input" placeholder="Add a note&hellip;" />
            <button class="btn notes-add-btn">Add</button>
          </div>
        </div>
        <div class="silence-btns" style="margin:0.5rem 0">
          ${a.src_ip && a.title ? `<button class="silence-btn silence-combo" data-title="${escHtml(a.title || '')}" data-ip="${escHtml(a.src_ip || '')}" title="Mute this title from this IP only">Mute IP+Title</button>` : ''}
          ${a.src_ip ? `<button class="silence-btn silence-ip" data-ip="${escHtml(a.src_ip || '')}" title="Mute ALL alerts from this source IP">Mute Src IP</button>` : ''}
          ${a.dst_ip ? `<button class="silence-btn silence-dst-ip" data-ip="${escHtml(a.dst_ip || '')}" title="Mute ALL alerts to this dest IP">Mute Dst IP</button>` : ''}
          <button class="silence-btn" data-title="${escHtml(a.title || '')}" title="Mute all alerts with this title from any source">Mute Title</button>
          ${a.src_ip ? `<button class="silence-btn" style="background:var(--danger);color:#fff" onclick="event.stopPropagation(); blockIp('${escHtml(a.src_ip)}', 'Alert: ${escHtml((a.title || '').replace(/'/g, ''))}')">Block IP</button>` : ''}
        </div>
        <button class="raw-json-toggle">Show raw JSON</button>
        <pre class="raw-json-block">${rawJson || '(no raw data)'}</pre>
      </div>
    </div>`;
}

function buildFlow(a) {
  let srcLabel = a.src_ip || '';
  if (a.src_dns && a.src_dns !== a.src_ip) srcLabel = `${a.src_ip} (${a.src_dns})`;
  else if (a.src_asset) srcLabel = `${a.src_ip} (${a.src_asset})`;
  if (a.src_port) srcLabel += `:${a.src_port}`;

  let dstLabel = a.dst_ip || '';
  if (a.dst_dns && a.dst_dns !== a.dst_ip) dstLabel = `${a.dst_ip} (${a.dst_dns})`;
  else if (a.dst_asset) dstLabel = `${a.dst_ip} (${a.dst_asset})`;
  if (a.dst_port) dstLabel += `:${a.dst_port}`;

  if (!srcLabel && !dstLabel) return '';
  if (!dstLabel) return srcLabel;
  return `${srcLabel} → ${dstLabel}`;
}

function updatePagination(count, page, hide = false) {
  if (hide || state.searchMode) {
    dom.btnPrev.disabled = true;
    dom.btnNext.disabled = true;
    dom.pageInfo.textContent = '';
    return;
  }
  dom.btnPrev.disabled = page === 0;
  dom.btnNext.disabled = count < state.pageSize;
  dom.pageInfo.textContent = `Page ${page + 1}`;
}

// ── WebSocket ──────────────────────────────────────────────────────────────

function connectWS() {
  setWsStatus('connecting');

  // Compute WS URL relative to the page host
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${location.host}/ws/alerts`;

  const ws = new WebSocket(url);
  state.ws = ws;

  ws.onopen = () => {
    setWsStatus('connected');
  };

  ws.onmessage = evt => {
    let msg;
    try { msg = JSON.parse(evt.data); } catch { return; }

    if (msg.type === 'alert' && msg.data) {
      prependLiveAlert(msg.data);
    } else if (msg.type === 'connected') {
      // welcome packet - update client count if we had a stat for it
    } else if (msg.type === 'squawk' && msg.data) {
      showSquawk(msg.data);
    } else if (msg.type === 'ai_decision' && msg.data) {
      // Refresh activity if panel is open
      if ($('ai-overlay') && $('ai-overlay').style.display !== 'none') loadAiActivity();
      fetchAiHistory();
    } else if (msg.type === 'ai_suggestion' && msg.data) {
      if ($('ai-overlay') && $('ai-overlay').style.display !== 'none') loadAiSuggestions();
    } else if (msg.type === 'ai_suggestion_resolved' && msg.data) {
      if ($('ai-overlay') && $('ai-overlay').style.display !== 'none') { loadAiSuggestions(); loadAiActivity(); }
    } else if (msg.type === 'squawk_dismiss') {
      dismissSquawk();
    } else if (msg.type === 'shift_report') {
      if ($('ai-overlay') && $('ai-overlay').style.display !== 'none') loadAiReports();
      fetchAiHistory();
    } else if (msg.type === 'incident') {
      fetchIncidents();
    } else if (msg.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong' }));
    }
  };

  ws.onclose = () => {
    setWsStatus('disconnected');
    state.ws = null;
    toast('Live feed disconnected - reconnecting…', 'warning', 6000);
    // Reconnect with backoff
    setTimeout(connectWS, 5000);
  };

  ws.onerror = () => {
    // onclose will fire next; suppress noisy ErrorEvent in console
  };
}

function prependLiveAlert(alertData) {
  // Only prepend to the visible list when on first page and no search active
  if (state.searchMode || state.page !== 0) return;

  const card = document.createElement('div');
  card.innerHTML = buildAlertCard(alertData).trim();
  const alertCard = card.firstElementChild;
  alertCard.classList.add('new-alert');

  // Wire checkbox
  const cb = alertCard.querySelector('.alert-select-cb');
  if (cb) {
    cb.addEventListener('click', e => {
      e.stopPropagation();
      const aid = cb.dataset.alertId;
      if (cb.checked) { state.selected.add(aid); alertCard.classList.add('selected'); }
      else { state.selected.delete(aid); alertCard.classList.remove('selected'); }
      updateBulkToolbar();
    });
  }

  // Wire expand/collapse
  alertCard.querySelector('.alert-summary').addEventListener('click', (e) => {
    if (e.target.classList.contains('alert-checkbox')) return;
    const wasExp = alertCard.classList.contains('expanded');
    alertCard.classList.toggle('expanded');
    if (!wasExp && !alertCard.dataset.repLoaded) {
      alertCard.dataset.repLoaded = '1';
      enrichCardReputation(alertCard);
      loadNotes(alertCard);
      loadAlertContext(alertCard);
    }
  });
  const rawBtn = alertCard.querySelector('.raw-json-toggle');
  if (rawBtn) {
    rawBtn.addEventListener('click', e => {
      e.stopPropagation();
      const block = alertCard.querySelector('.raw-json-block');
      block.classList.toggle('visible');
      rawBtn.textContent = block.classList.contains('visible')
        ? 'Hide raw JSON' : 'Show raw JSON';
    });
  }

  wireVerdictButtons(alertCard);
  wireCopyButtons(alertCard);
  wireAiButtons(alertCard);
  wirePivotClicks(alertCard);
  // wireWhatIsThis needs the alert in state.alerts - prepend it
  state.alerts.unshift(alertData);
  wireWhatIsThis(alertCard);

  // Remove the "new-alert" class after animation
  setTimeout(() => alertCard.classList.remove('new-alert'), 1000);

  const list = dom.alertList;
  const emptyState = list.querySelector('.empty-state');
  if (emptyState) emptyState.remove();

  list.insertBefore(alertCard, list.firstChild);

  // Cap the live list at 200 cards
  const cards = list.querySelectorAll('.alert-card');
  if (cards.length > 200) cards[cards.length - 1].remove();

  // Update total count
  fetchStats();
}

// ── AI Query ───────────────────────────────────────────────────────────────

async function askQuestion(question) {
  if (state.queryPending || !question.trim()) return;
  state.queryPending = true;
  dom.queryBtn.disabled = true;
  dom.queryBtn.textContent = 'Querying…';

  try {
    const res = await fetch('/api/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    dom.queryResultSum.textContent = data.summary || '(no summary)';
    dom.queryResultSql.textContent = data.sql || '';
    dom.queryResultCnt.textContent =
      `${data.count ?? (data.results || []).length} result(s) returned`;
    dom.queryResult.classList.add('visible');
    dom.queryResultSql.style.display = data.sql ? 'block' : 'none';

    // If the query returned results, show them in the alert list
    if (data.results && data.results.length) {
      state.searchMode = true;
      state.alerts = data.results;
      dom.alertCount.textContent = `${data.results.length} result(s) - AI query`;
      renderAlertList(data.results);
      updatePagination(data.results.length, 0, true);
    }
  } catch (err) {
    console.error('askQuestion error:', err);
    dom.queryResultSum.textContent = `Error: ${err.message}`;
    dom.queryResultSql.textContent = '';
    dom.queryResultCnt.textContent = '';
    dom.queryResult.classList.add('visible');
    dom.queryResultSql.style.display = 'none';
    toast(`Query failed: ${err.message}`, 'error');
  } finally {
    state.queryPending = false;
    dom.queryBtn.disabled = false;
    dom.queryBtn.textContent = 'Ask';
  }
}

// ── Verdict actions ────────────────────────────────────────────────────────

function wireVerdictButtons(card) {
  card.querySelectorAll('.verdict-btn').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      const alertId = btn.closest('.verdict-actions').dataset.alertId;
      const verdict = btn.dataset.verdict;
      btn.disabled = true;
      btn.textContent = '...';
      try {
        const res = await fetch(`/api/alerts/${alertId}/verdict`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ verdict }),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        // Update the badge in the card summary
        const badgeContainer = card.querySelector('.alert-badges');
        if (badgeContainer) {
          const oldVBadge = badgeContainer.querySelector('[class*="badge-v-"]');
          if (oldVBadge) {
            oldVBadge.className = `badge badge-v-${verdict}`;
            oldVBadge.textContent = verdict;
          }
        }
        // Update active state on buttons
        card.querySelectorAll('.verdict-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        toast(`Verdict set to ${verdict}`, 'success');
        fetchStats();

        // Post-verdict actions for escalate/investigate
        if (verdict === 'escalate' || verdict === 'investigate') {
          showPostVerdictActions(card, alertId, verdict);
        }
      } catch (err) {
        toast(`Failed to set verdict: ${err.message}`, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = verdict.charAt(0).toUpperCase() + verdict.slice(1);
      }
    });
  });
}

function showPostVerdictActions(card, alertId, verdict) {
  // Remove any existing post-verdict panel
  const existing = card.querySelector('.post-verdict-panel');
  if (existing) existing.remove();

  const verdictActions = card.querySelector('.verdict-actions');
  if (!verdictActions) return;

  const isEscalate = verdict === 'escalate';
  const panel = document.createElement('div');
  panel.className = 'post-verdict-panel';
  panel.innerHTML = `
    <div class="post-verdict-header">
      <span class="post-verdict-icon">${isEscalate ? '!' : '?'}</span>
      <span>${isEscalate ? 'Alert escalated' : 'Marked for investigation'} - what next?</span>
      <button class="post-verdict-dismiss" title="Dismiss">&times;</button>
    </div>
    <div class="post-verdict-note-wrap">
      <input type="text" class="post-verdict-note" placeholder="Add a note (why you ${verdict}d this)..." />
      <button class="btn post-verdict-save-note">Save Note</button>
    </div>
    <div class="post-verdict-suggestions">
      <button class="ai-btn ai-explain post-verdict-ai" data-action="${isEscalate ? 'explain' : 'hunt'}" data-alert-id="${alertId}">
        ${isEscalate ? 'AI: Explain This Alert' : 'AI: Hunt From Here'}
      </button>
      <button class="ai-btn ai-remediate post-verdict-ai" data-action="remediate" data-alert-id="${alertId}">
        AI: What Should I Do?
      </button>
    </div>`;
  verdictActions.after(panel);

  // Wire dismiss
  panel.querySelector('.post-verdict-dismiss').addEventListener('click', e => {
    e.stopPropagation();
    panel.remove();
  });

  // Wire save note
  const noteInput = panel.querySelector('.post-verdict-note');
  const saveBtn = panel.querySelector('.post-verdict-save-note');
  saveBtn.addEventListener('click', async e => {
    e.stopPropagation();
    const note = noteInput.value.trim();
    if (!note) return;
    try {
      const res = await fetch(`/api/alerts/${alertId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: `[${verdict.toUpperCase()}] ${note}` }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      toast('Note saved', 'success');
      noteInput.value = '';
      noteInput.placeholder = 'Note saved!';
    } catch (err) {
      toast(`Failed to save note: ${err.message}`, 'error');
    }
  });

  // Wire AI suggestion buttons
  panel.querySelectorAll('.post-verdict-ai').forEach(aiBtn => {
    aiBtn.addEventListener('click', e => {
      e.stopPropagation();
      const action = aiBtn.dataset.action;
      // Find the main AI button in the card and trigger it
      const mainBtn = card.querySelector(`.ai-btn[data-action="${action}"][data-alert-id="${alertId}"]`);
      if (mainBtn) {
        mainBtn.click();
      } else {
        // Directly call aiConsult if no main button found (e.g., in overlay)
        aiConsult(alertId, action, aiBtn, card);
      }
      panel.remove();
    });
  });

  // Enter key saves note
  noteInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.stopPropagation(); saveBtn.click(); }
  });
  noteInput.addEventListener('click', e => e.stopPropagation());
}

// ── Bulk actions ──────────────────────────────────────────────────────────

function updateBulkToolbar() {
  const count = state.selected.size;
  if (count > 0) {
    dom.bulkToolbar.style.display = 'flex';
    dom.bulkCount.textContent = `${count} selected`;
  } else {
    dom.bulkToolbar.style.display = 'none';
  }
  // Sync select-all checkbox
  const cbs = dom.alertList.querySelectorAll('.alert-select-cb');
  const allChecked = cbs.length > 0 && [...cbs].every(cb => cb.checked);
  dom.selectAllCb.checked = allChecked;
}

function selectAllOnPage(checked) {
  dom.alertList.querySelectorAll('.alert-select-cb').forEach(cb => {
    const aid = cb.dataset.alertId;
    cb.checked = checked;
    const card = cb.closest('.alert-card');
    if (checked) {
      state.selected.add(aid);
      card.classList.add('selected');
    } else {
      state.selected.delete(aid);
      card.classList.remove('selected');
    }
  });
  updateBulkToolbar();
}

function deselectAll() {
  state.selected.clear();
  dom.alertList.querySelectorAll('.alert-select-cb').forEach(cb => {
    cb.checked = false;
    cb.closest('.alert-card').classList.remove('selected');
  });
  dom.selectAllCb.checked = false;
  updateBulkToolbar();
}

async function bulkSetVerdict(verdict) {
  const ids = [...state.selected];
  if (!ids.length) return;
  if (!confirm(`Set ${ids.length} alert(s) to "${verdict}"?`)) return;
  try {
    const res = await fetch('/api/alerts/bulk-verdict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_ids: ids, verdict }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    toast(`${data.updated} alert(s) set to ${verdict}`, 'success');
    // Update badges on visible cards
    ids.forEach(id => {
      const card = dom.alertList.querySelector(`.alert-card[data-id="${id}"]`);
      if (card) {
        const badge = card.querySelector('[class*="badge-v-"]');
        if (badge) { badge.className = `badge badge-v-${verdict}`; badge.textContent = verdict; }
        card.querySelectorAll('.verdict-btn').forEach(b => b.classList.remove('active'));
        const active = card.querySelector(`.verdict-btn[data-verdict="${verdict}"]`);
        if (active) active.classList.add('active');
      }
    });
    deselectAll();
    fetchStats();
  } catch (err) {
    toast(`Bulk action failed: ${err.message}`, 'error');
  }
}

async function suppressAllFiltered() {
  const f = state.filters;
  const hasFilter = f.source || f.severity || f.verdict || f.timerange;
  if (!hasFilter) return;

  const desc = [f.source, f.severity, f.verdict, f.timerange].filter(Boolean).join(', ');
  if (!confirm(`Suppress ALL alerts matching filters: ${desc}?\nThis cannot be easily undone.`)) return;

  try {
    const res = await fetch('/api/alerts/suppress-filtered', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source: f.source || '',
        severity: f.severity || '',
        verdict: f.verdict || '',
        since: f.timerange || '',
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    toast(`${data.updated} alert(s) suppressed`, 'success');
    fetchAlerts(0);
    fetchStats();
  } catch (err) {
    toast(`Suppress all failed: ${err.message}`, 'error');
  }
}

function updateSuppressAllButton() {
  const f = state.filters;
  const hasFilter = f.source || f.severity || f.verdict || f.timerange;
  dom.btnSuppressAll.style.display = hasFilter ? 'inline-block' : 'none';
}

// ── Correlations ──────────────────────────────────────────────────────────

async function fetchCorrelations() {
  try {
    const res = await fetch('/api/correlations?limit=10');
    if (!res.ok) return;
    const data = await res.json();
    const corrs = data.correlations || [];
    if (!corrs.length) {
      dom.corrSection.style.display = 'block';
      dom.corrList.innerHTML = smartEmptyState('no-correlations');
      return;
    }
    dom.corrSection.style.display = 'block';
    dom.corrList.innerHTML = `<div class="corr-toolbar">
      <span>${corrs.length} correlation${corrs.length !== 1 ? 's' : ''}</span>
      <button class="btn btn-sm" onclick="clearAllCorrelations()">Clear All</button>
    </div>` + corrs.map(c => {
      const alertCount = (c.alert_ids || []).length;
      const sevClass = `sev-${(c.severity||'medium').toLowerCase()}`;
      return `
        <div class="correlation-card ${sevClass}" data-corr-id="${escHtml(c.id)}">
          <div class="corr-header">
            <span class="badge badge-sev-${(c.severity||'medium').toLowerCase()}">${escHtml(c.severity)}</span>
            <span class="corr-pattern">${escHtml(c.pattern || 'Pattern')}</span>
            <span class="corr-meta">
              ${alertCount} alert${alertCount !== 1 ? 's' : ''} &middot; ${fmtRelative(c.created_at)}
              <button class="btn-dismiss-corr" onclick="event.stopPropagation(); dismissCorrelation('${escHtml(c.id)}')" title="Dismiss">&times;</button>
            </span>
          </div>
          <div class="corr-summary">${escHtml(c.summary || '')}</div>
          <div class="corr-actions">
            <button class="ai-btn ai-explain corr-ai-btn" data-corr-id="${escHtml(c.id)}" title="AI analysis of this correlation">Analyze Pattern</button>
          </div>
          <div class="corr-ai-response" data-corr-id="${escHtml(c.id)}"></div>
          <div class="corr-alerts-detail"></div>
        </div>`;
    }).join('');

    // Wire click-to-expand on correlation cards
    dom.corrList.querySelectorAll('.correlation-card').forEach(card => {
      card.style.cursor = 'pointer';
      card.addEventListener('click', () => {
        const wasExpanded = card.classList.contains('corr-expanded');
        card.classList.toggle('corr-expanded');
        if (!wasExpanded && !card.dataset.loaded) {
          card.dataset.loaded = '1';
          loadCorrelationAlerts(card);
        }
      });
    });

    // Wire "Analyze Pattern" AI buttons on correlations
    dom.corrList.querySelectorAll('.corr-ai-btn').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        analyzeCorrelation(btn.dataset.corrId, btn);
      });
    });
  } catch (err) {
    console.error('fetchCorrelations error:', err);
  }
}

async function dismissCorrelation(corrId) {
  try {
    const res = await fetch(`/api/correlations/${corrId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const card = document.querySelector(`.correlation-card[data-corr-id="${corrId}"]`);
    if (card) card.remove();
  } catch (err) {
    console.error('dismissCorrelation error:', err);
  }
}

async function clearAllCorrelations() {
  if (!confirm('Clear all correlations? This cannot be undone.')) return;
  try {
    const res = await fetch('/api/correlations/clear', { method: 'POST' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    fetchCorrelations();
  } catch (err) {
    alert('Failed: ' + err.message);
  }
}

// ── AI History Panel ──────────────────────────────────────────────────────

const AI_HISTORY_GROUPS = [
  { key: 'suppressed',   label: 'Noise suppressed',        actions: ['suppress_noise', 'cluster_sweep'], icon: '\uD83D\uDD07' },
  { key: 'silence',      label: 'Silence rules created',   actions: ['silence_rule'],                    icon: '\uD83D\uDD15' },
  { key: 'escalated',    label: 'Threats escalated',        actions: ['escalate'],                        icon: '\uD83D\uDEA8' },
  { key: 'investigate',  label: 'Investigations flagged',   actions: ['investigate'],                     icon: '\uD83D\uDD0D' },
  { key: 'squawk',       label: 'Squawks raised',           actions: ['squawk'],                          icon: '\u26A0\uFE0F' },
];

async function fetchAiHistory() {
  try {
    const [decRes, repRes] = await Promise.all([
      fetch('/api/ai/decisions?limit=200'),
      fetch('/api/ai/reports'),
    ]);
    if (!decRes.ok) return;
    const decisions = await decRes.json();
    const reports = repRes.ok ? await repRes.json() : [];

    // Group decisions by action
    const groups = {};
    for (const g of AI_HISTORY_GROUPS) groups[g.key] = { ...g, items: [], latest: null };
    for (const d of decisions) {
      for (const g of AI_HISTORY_GROUPS) {
        if (g.actions.includes(d.action)) {
          groups[g.key].items.push(d);
          const t = new Date(d.timestamp || d.created_at);
          if (!groups[g.key].latest || t > groups[g.key].latest) groups[g.key].latest = t;
          break;
        }
      }
    }

    // Add shift reports as a group
    groups.reports = {
      key: 'reports', label: 'Shift reports', icon: '\uD83D\uDCCB',
      items: reports,
      latest: reports.length ? new Date(reports[0].created_at || reports[0].timestamp) : null,
    };

    const hasData = Object.values(groups).some(g => g.items.length > 0);
    if (!hasData) {
      if (dom.aiHistorySection) dom.aiHistorySection.style.display = 'none';
      return;
    }
    if (dom.aiHistorySection) dom.aiHistorySection.style.display = '';

    let html = '';
    for (const g of [...AI_HISTORY_GROUPS.map(x => groups[x.key]), groups.reports]) {
      if (!g.items.length) continue;
      const ago = g.latest ? timeAgo(g.latest) : '';
      html += `<div class="ai-history-group" data-group="${g.key}">
        <div class="ai-history-group-header">
          <span class="ai-history-icon">${g.icon}</span>
          <span class="ai-history-label">${g.label}</span>
          <span class="ai-history-count">${g.items.length}</span>
          <span class="ai-history-time">${ago}</span>
          <span class="ai-history-chevron">&#9654;</span>
        </div>
        <div class="ai-history-group-detail">`;
      const shown = g.items.slice(0, 20);
      for (const item of shown) {
        const t = item.timestamp || item.created_at;
        const time = t ? timeAgo(new Date(t)) : '';
        const text = item.reason || item.summary || item.title || item.action || '-';
        html += `<div class="ai-history-item">
          <span class="ai-history-item-time">${time}</span>
          <span class="ai-history-item-text">${escHtml(text)}</span>
        </div>`;
      }
      if (g.items.length > 20) {
        html += `<div class="ai-history-item" style="color:var(--text-muted);font-style:italic">+${g.items.length - 20} more</div>`;
      }
      html += `</div></div>`;
    }
    dom.aiHistoryList.innerHTML = html;

    // Wire expand/collapse
    dom.aiHistoryList.querySelectorAll('.ai-history-group-header').forEach(hdr => {
      hdr.addEventListener('click', () => {
        hdr.parentElement.classList.toggle('expanded');
      });
    });
  } catch (err) {
    console.error('fetchAiHistory error:', err);
  }
}

async function loadCorrelationAlerts(card) {
  const corrId = card.dataset.corrId;
  const detail = card.querySelector('.corr-alerts-detail');
  detail.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.8rem">Loading alerts...</div>';
  try {
    const res = await fetch(`/api/correlations/${encodeURIComponent(corrId)}/alerts`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const alerts = data.alerts || [];
    if (!alerts.length) {
      detail.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.8rem">No alerts found (may have been deleted)</div>';
      return;
    }
    detail.innerHTML = alerts.map(a => {
      const sev = (a.severity || 'medium').toLowerCase();
      const src = a.src_ip || '';
      const dst = a.dst_ip || '';
      const flow = src && dst ? `${escHtml(src)} → ${escHtml(dst)}` : '';
      return `
        <div class="corr-alert-row" data-alert-id="${escHtml(a.id)}">
          <span class="badge badge-sev-${sev}" style="font-size:0.65rem">${escHtml(a.severity || 'medium')}</span>
          <span class="corr-alert-title">${escHtml(a.title || '(no title)')}</span>
          ${flow ? `<span class="corr-alert-flow">${flow}</span>` : ''}
          <span class="corr-alert-time">${fmtRelative(a.timestamp)}</span>
        </div>`;
    }).join('');

    // Click an alert row to jump to it in the main feed
    detail.querySelectorAll('.corr-alert-row').forEach(row => {
      row.addEventListener('click', e => {
        e.stopPropagation();
        const alertId = row.dataset.alertId;
        scrollToAlert(alertId);
      });
    });
  } catch (err) {
    detail.innerHTML = `<div class="empty-state" style="padding:0.5rem;font-size:0.8rem">Failed: ${escHtml(err.message)}</div>`;
  }
}

function scrollToAlert(alertId) {
  // Try to find the alert card already in the DOM
  const existing = document.querySelector(`.alert-card[data-alert-id="${alertId}"]`);
  if (existing) {
    existing.scrollIntoView({ behavior: 'smooth', block: 'center' });
    existing.classList.add('highlight-pulse');
    setTimeout(() => existing.classList.remove('highlight-pulse'), 2000);
    // Auto-expand it
    if (!existing.classList.contains('expanded')) {
      existing.querySelector('.alert-summary')?.click();
    }
    return;
  }
  // Not in current view - fetch it directly and show in a modal-like overlay
  showAlertOverlay(alertId);
}

async function showAlertOverlay(alertId) {
  try {
    const [alertRes, ctxRes] = await Promise.all([
      fetch(`/api/alerts/${encodeURIComponent(alertId)}`),
      fetch(`/api/alerts/${encodeURIComponent(alertId)}/context`),
    ]);
    if (!alertRes.ok) throw new Error(`HTTP ${alertRes.status}`);
    const a = await alertRes.json();
    const ctx = ctxRes.ok ? await ctxRes.json() : {};
    const sev = (a.severity || 'medium').toLowerCase();
    const flow = buildFlow(a);

    // Build IOC copy text (comprehensive)
    const iocText = [
      a.title,
      a.src_ip && `src_ip: ${a.src_ip}`,
      a.dst_ip && `dst_ip: ${a.dst_ip}`,
      a.proto && `proto: ${a.proto}`,
      a.signature_id && `sig_id: ${a.signature_id}`,
      a.category && `category: ${a.category}`,
      a.source && `source: ${a.source}`,
      a.severity && `severity: ${a.severity}`,
      a.timestamp && `time: ${a.timestamp}`,
    ].filter(Boolean).join('\n');

    // Suggested action banner
    const suggestedHtml = ctx.triage && ctx.triage.suggested_action
      ? `<div class="suggested-action"><span class="suggested-action-label">Suggested action</span><span>${escHtml(ctx.triage.suggested_action)}</span></div>`
      : '';

    // IP summary helpers
    function ipSummaryHtml(summary, label) {
      if (!summary) return '';
      return `<span class="ip-history">${summary.last_24h} in 24h &middot; ${summary.total} total</span>`;
    }

    // Src/Dst IP with copy + history
    const srcIpHtml = a.src_ip
      ? `<div class="detail-field"><span class="detail-key">Src IP</span><span class="detail-val"><a class="detail-pivot" data-pivot-field="Src IP" data-pivot-value="${escHtml(a.src_ip)}" title="Filter by Src IP">${escHtml(a.src_ip)}</a> <button class="copy-btn" data-copy="${escHtml(a.src_ip)}" title="Copy">&#x29C9;</button>${ipSummaryHtml(ctx.src_summary, 'src')}</span></div>`
      : '';
    const dstIpHtml = a.dst_ip
      ? `<div class="detail-field"><span class="detail-key">Dst IP</span><span class="detail-val"><a class="detail-pivot" data-pivot-field="Dst IP" data-pivot-value="${escHtml(a.dst_ip)}" title="Filter by Dst IP">${escHtml(a.dst_ip)}</a> <button class="copy-btn" data-copy="${escHtml(a.dst_ip)}" title="Copy">&#x29C9;</button>${ipSummaryHtml(ctx.dst_summary, 'dst')}</span></div>`
      : '';

    // Related alerts
    const relatedHtml = ctx.related_alerts && ctx.related_alerts.length
      ? `<div class="related-alerts">
          <div class="related-header"><span>Other alerts from ${escHtml(a.src_ip || '')}</span></div>
          <div class="related-list">${ctx.related_alerts.map(r => `
            <div class="corr-alert-row related-alert-row" data-alert-id="${escHtml(r.id)}">
              ${severityBadge(r.severity)}
              <span class="corr-alert-title">${escHtml(r.title || '(no title)')}</span>
              <span class="corr-alert-time">${fmtRelative(r.timestamp)}</span>
            </div>`).join('')}
          </div>
        </div>`
      : '';

    // Verdict buttons
    const verdictButtonsHtml = `
      <div class="verdict-actions" data-alert-id="${escHtml(a.id)}">
        <span class="verdict-actions-label">Set verdict:</span>
        <button class="verdict-btn v-suppress${a.verdict === 'suppress' ? ' active' : ''}" data-verdict="suppress" data-tooltip="Benign / false positive - hide from feed">Suppress</button>
        <button class="verdict-btn v-investigate${a.verdict === 'investigate' ? ' active' : ''}" data-verdict="investigate" data-tooltip="Needs human review - keep on radar">Investigate</button>
        <button class="verdict-btn v-escalate${a.verdict === 'escalate' ? ' active' : ''}" data-verdict="escalate" data-tooltip="Confirmed threat - escalate to incident response">Escalate</button>
      </div>`;

    const overlay = document.createElement('div');
    overlay.className = 'alert-overlay';
    overlay.innerHTML = `
      <div class="alert-overlay-backdrop"></div>
      <div class="alert-overlay-content">
        <div class="alert-overlay-header">
          <span class="badge badge-sev-${sev}">${escHtml(a.severity)}</span>
          <span style="flex:1;font-weight:600">${escHtml(a.title || '(no title)')}</span>
          <button class="copy-btn" data-copy="${escHtml(a.title || '')}" title="Copy title">&#x29C9;</button>
          <button class="alert-overlay-close">&times;</button>
        </div>
        <div class="alert-overlay-body">
          ${suggestedHtml}
          ${verdictButtonsHtml}
          <div class="detail-actions-row">
            <button class="copy-btn copy-ioc-btn" data-copy="${escHtml(iocText)}" title="Copy IOCs">&#x29C9; Copy IOCs</button>
          </div>
          <div class="detail-field"><span class="detail-key">Source</span><span class="detail-val">${escHtml(a.source || '')}</span></div>
          <div class="detail-field"><span class="detail-key">Time</span><span class="detail-val">${fmtTime(a.timestamp)}</span></div>
          ${flow ? `<div class="detail-field"><span class="detail-key">Flow</span><span class="detail-val">${flow}</span></div>` : ''}
          ${srcIpHtml}
          ${dstIpHtml}
          ${a.signature_id ? `<div class="detail-field"><span class="detail-key">Sig ID</span><span class="detail-val"><a class="detail-pivot" data-pivot-field="Sig ID" data-pivot-value="${escHtml(String(a.signature_id))}" title="Filter by Sig ID">${escHtml(a.signature_id)}</a> <button class="copy-btn" data-copy="${escHtml(String(a.signature_id))}" title="Copy">&#x29C9;</button></span></div>` : ''}
          ${a.category ? `<div class="detail-field"><span class="detail-key">Category</span><span class="detail-val">${escHtml(a.category)}</span></div>` : ''}
          ${a.src_geo ? `<div class="detail-field"><span class="detail-key">Src Geo</span><span class="detail-val">${escHtml(a.src_geo)}</span></div>` : ''}
          ${a.dst_geo ? `<div class="detail-field"><span class="detail-key">Dst Geo</span><span class="detail-val">${escHtml(a.dst_geo)}</span></div>` : ''}
          ${a.ai_reasoning ? `<div class="detail-field" style="flex-direction:column"><span class="detail-key">AI Reasoning</span><span class="detail-val" style="white-space:pre-wrap">${escHtml(a.ai_reasoning)}</span></div>` : ''}
          ${a.verdict ? `<div class="detail-field"><span class="detail-key">Verdict</span><span class="detail-val">${verdictBadge(a.verdict)}</span></div>` : ''}
          ${relatedHtml}

          <div class="ai-actions" data-alert-id="${escHtml(a.id)}">
            <button class="ai-btn ai-explain" data-action="explain" data-alert-id="${escHtml(a.id)}">Explain This</button>
            <button class="ai-btn ai-remediate" data-action="remediate" data-alert-id="${escHtml(a.id)}">What Should I Do?</button>
            <button class="ai-btn ai-hunt" data-action="hunt" data-alert-id="${escHtml(a.id)}">Hunt From Here</button>
          </div>
          <div class="ai-response-slot" data-alert-id="${escHtml(a.id)}"></div>
          <div class="ai-chat-panel" data-alert-id="${escHtml(a.id)}" style="display:none">
            <div class="ai-chat-history" data-alert-id="${escHtml(a.id)}"></div>
            <div class="ai-chat-input-wrap">
              <input type="text" class="ai-chat-input" placeholder="Ask a follow-up question..." data-alert-id="${escHtml(a.id)}" />
              <button class="btn ai-chat-send" data-alert-id="${escHtml(a.id)}">Ask</button>
            </div>
          </div>
        </div>
      </div>`;
    document.body.appendChild(overlay);

    // Wire close
    overlay.querySelector('.alert-overlay-close').addEventListener('click', () => overlay.remove());
    overlay.querySelector('.alert-overlay-backdrop').addEventListener('click', () => overlay.remove());

    // Wire copy buttons
    wireCopyButtons(overlay);

    // Wire verdict buttons
    wireVerdictButtons(overlay);

    // Wire AI buttons
    wireAiButtons(overlay);

    // Wire pivot clicks (clickable IPs, sig IDs)
    wirePivotClicks(overlay);

    // Wire related alert clicks
    overlay.querySelectorAll('.related-alert-row').forEach(row => {
      row.addEventListener('click', () => {
        overlay.remove();
        scrollToAlert(row.dataset.alertId);
      });
    });
  } catch (err) {
    toast(`Could not load alert: ${err.message}`, 'error');
  }
}

// ── Filters ────────────────────────────────────────────────────────────────

function applyFilters() {
  state.filters.timerange = dom.filterTimerange.value;
  state.filters.source    = dom.filterSource.value;
  state.filters.severity  = dom.filterSeverity.value;
  state.filters.verdict   = dom.filterVerdict.value;
  updateSuppressAllButton();
  fetchAlerts(0);
}

// ── Help panel ────────────────────────────────────────────────────────────

function openHelp() {
  $('help-overlay').style.display = 'block';
  document.body.style.overflow = 'hidden';
  // Auto-fill server IP in install commands
  document.querySelectorAll('.help-placeholder').forEach(el => {
    el.textContent = location.hostname || 'YOUR_SERVER_IP';
    el.style.color = 'var(--accent)';
    el.style.fontWeight = '600';
  });
}

function closeHelp() {
  $('help-overlay').style.display = 'none';
  document.body.style.overflow = '';
}

// ── Init ───────────────────────────────────────────────────────────────────

// ── Stat Card Clicks ──────────────────────────────────────────────────────

function statCardNav(verdictValue, scrollTarget) {
  // Set the verdict filter dropdown
  dom.filterVerdict.value = verdictValue;
  // Clear other filters for a clean view
  dom.filterTimerange.value = '';
  dom.filterSource.value = '';
  dom.filterSeverity.value = '';
  dom.searchBox.value = '';
  state.searchMode = false;
  applyFilters();
  // Scroll to target
  const el = typeof scrollTarget === 'string' ? $(scrollTarget) : scrollTarget;
  if (el) setTimeout(() => el.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
}

function initStatCardClicks() {
  const cardMap = {
    'card-review':       () => openNeedsReviewOverlay(),
    'card-threats':      () => openThreatsOverlay(),
    'card-autohandled':  () => statCardNav('suppress', 'alert-feed-anchor'),
    'card-youractivity': () => statCardNav('', 'alert-feed-anchor'),
    'stat-agents-card':  () => {
      const sec = $('agents-section');
      if (sec) sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
    },
    'card-sla': () => openStaleAlertsOverlay(),
  };
  for (const [id, handler] of Object.entries(cardMap)) {
    const el = $(id);
    if (el) el.addEventListener('click', handler);
  }
}

// ── Incidents ──────────────────────────────────────────────────────────────

async function fetchIncidents() {
  try {
    const filter = dom.incidentFilter?.value || '';
    // Default: show new + investigating (active incidents)
    let url = '/api/incidents?limit=20';
    if (filter) {
      url += `&status=${filter}`;
    }
    const res = await fetch(url);
    const incidents = await res.json();
    renderIncidents(filter ? incidents : incidents.filter(i => i.status !== 'resolved' && i.status !== 'false_positive'));

    // Also fetch counts
    const cRes = await fetch('/api/incidents/counts');
    const counts = await cRes.json();
    if (dom.incidentCounts) {
      const parts = [];
      if (counts.new) parts.push(`${counts.new} new`);
      if (counts.investigating) parts.push(`${counts.investigating} investigating`);
      dom.incidentCounts.textContent = parts.join(', ') || 'none active';
    }
  } catch (e) {
    console.error('fetchIncidents error:', e);
  }
}

function renderIncidents(incidents) {
  if (!dom.incidentsList) return;
  if (!incidents.length) {
    dom.incidentsList.innerHTML = '<div class="empty-state" style="padding:1.5rem;font-size:0.9rem">No incidents. When threats are detected, they\'ll appear here with step-by-step guidance.</div>';
    return;
  }

  const urgencyLabels = { noise: 'Likely Noise', check: 'Worth a Look', act_now: 'Act Now' };

  dom.incidentsList.innerHTML = `
    <div class="incident-bulk-toolbar" id="incident-bulk-toolbar">
      <label class="incident-select-all-wrap">
        <input type="checkbox" id="incident-select-all-cb" /> Select All
      </label>
      <span class="incident-bulk-count" id="incident-bulk-count"></span>
      <button class="btn btn-sm btn-resolve" id="incident-bulk-resolve" style="display:none">Resolve All</button>
      <button class="btn btn-sm btn-fp" id="incident-bulk-fp" style="display:none">FP All</button>
    </div>` +
    incidents.map(inc => {
    const ago = timeAgo(new Date(inc.created_at));
    const ips = (inc.affected_ips || []).slice(0, 3).join(', ');
    const urgency = inc.urgency || 'check';
    const urgLabel = urgencyLabels[urgency] || 'Check';
    return `
      <div class="incident-card severity-${inc.severity}" data-incident-id="${escHtml(inc.id)}">
        <div class="incident-header">
          <input type="checkbox" class="incident-select-cb" data-incident-id="${escHtml(inc.id)}" onclick="event.stopPropagation(); toggleIncidentSelect(this)" />
          <span class="urgency-badge ${urgency}">${urgLabel}</span>
          <span class="incident-sev-badge ${inc.severity}">${inc.severity}</span>
          <span class="incident-status-badge ${inc.status}">${inc.status.replace('_', ' ')}</span>
          <span class="incident-title" onclick="showIncidentDetail('${inc.id}')">${escHtml(inc.title)}</span>
        </div>
        <div class="incident-meta" onclick="showIncidentDetail('${inc.id}')">
          <span>${inc.alert_count} alert${inc.alert_count !== 1 ? 's' : ''}</span>
          <span>${ago}</span>
          ${ips ? `<span>${escHtml(ips)}</span>` : ''}
          ${inc.category ? `<span>${escHtml(inc.category.replace(/_/g, ' '))}</span>` : ''}
        </div>
        <div class="incident-summary" onclick="showIncidentDetail('${inc.id}')">${escHtml(inc.summary)}</div>
      </div>`;
  }).join('');

  wireIncidentBulkActions();
}

const _selectedIncidents = new Set();

function toggleIncidentSelect(cb) {
  const id = cb.dataset.incidentId;
  if (cb.checked) _selectedIncidents.add(id); else _selectedIncidents.delete(id);
  updateIncidentBulkToolbar();
}

function updateIncidentBulkToolbar() {
  const count = _selectedIncidents.size;
  const countEl = document.getElementById('incident-bulk-count');
  const resolveBtn = document.getElementById('incident-bulk-resolve');
  const fpBtn = document.getElementById('incident-bulk-fp');
  if (countEl) countEl.textContent = count ? `${count} selected` : '';
  if (resolveBtn) resolveBtn.style.display = count ? 'inline-block' : 'none';
  if (fpBtn) fpBtn.style.display = count ? 'inline-block' : 'none';
}

function wireIncidentBulkActions() {
  _selectedIncidents.clear();

  const selectAllCb = document.getElementById('incident-select-all-cb');
  if (selectAllCb) {
    selectAllCb.addEventListener('change', () => {
      const cbs = dom.incidentsList.querySelectorAll('.incident-select-cb');
      cbs.forEach(cb => {
        cb.checked = selectAllCb.checked;
        if (selectAllCb.checked) _selectedIncidents.add(cb.dataset.incidentId);
        else _selectedIncidents.delete(cb.dataset.incidentId);
      });
      updateIncidentBulkToolbar();
    });
  }

  const resolveBtn = document.getElementById('incident-bulk-resolve');
  if (resolveBtn) {
    resolveBtn.addEventListener('click', () => bulkIncidentAction('resolved'));
  }
  const fpBtn = document.getElementById('incident-bulk-fp');
  if (fpBtn) {
    fpBtn.addEventListener('click', () => bulkIncidentAction('false_positive'));
  }
}

// -- Edge Scout -------------------------------------------------------------

async function fetchScoutCards() {
  if (!dom.scoutCards) return;
  try {
    const res = await fetch('/api/scout/cards?limit=12&status=new');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderScoutCards(data.cards || []);
  } catch (e) {
    console.error('fetchScoutCards error:', e);
    dom.scoutCards.innerHTML = `<div class="empty-state" style="padding:1rem;font-size:0.85rem">Scout cards unavailable: ${escHtml(e.message)}</div>`;
    if (dom.scoutCount) dom.scoutCount.textContent = 'unavailable';
  }
}

function renderScoutCards(cards) {
  if (!dom.scoutCards) return;
  if (dom.scoutCount) {
    dom.scoutCount.textContent = cards.length
      ? `${cards.length} candidate${cards.length === 1 ? '' : 's'}`
      : 'none new';
  }

  if (!cards.length) {
    dom.scoutCards.innerHTML = '<div class="empty-state" style="padding:1rem;font-size:0.85rem">No new scout cards. The scout will surface candidates here when mechanical checks find something unusual.</div>';
    return;
  }

  dom.scoutCards.innerHTML = cards.map(card => {
    const extracted = card.extracted_json || {};
    const reasons = Array.isArray(card.reasons) ? card.reasons : [];
    const facts = normalizeScoutFacts(card.context_facts);
    const score = Number(card.score || 0);
    const title = extracted.title || 'Untitled alert';
    const path = [
      extracted.src_ip,
      extracted.src_port ? `:${extracted.src_port}` : '',
      extracted.dst_ip ? ' -> ' : '',
      extracted.dst_ip || '',
      extracted.dst_port ? `:${extracted.dst_port}` : '',
    ].join('');
    const badges = [
      sourceBadge(extracted.source || 'unknown'),
      severityBadge(extracted.severity || 'unknown'),
      verdictBadge(extracted.verdict || 'pending'),
      `<span class="badge scout-score">score ${escHtml(score)}</span>`,
    ].join('');

    return `
      <div class="scout-card">
        <div class="scout-card-head">
          <div class="scout-card-title">
            <span>${escHtml(title)}</span>
            <span class="scout-card-time">${escHtml(fmtRelative(card.created_at))}</span>
          </div>
          <div class="scout-badges">${badges}</div>
        </div>
        <div class="scout-path">${escHtml(path || 'No endpoint tuple extracted')}</div>
        <div class="scout-note">${escHtml(card.scout_note || 'Candidate missed signal surfaced by scout checks. No verdict was made.')}</div>
        <div class="scout-grid">
          <div>
            <div class="scout-label">Mechanical Reasons</div>
            <div class="scout-reasons">
              ${reasons.length ? reasons.map(reason => `<span>${escHtml(reason)}</span>`).join('') : '<em>none recorded</em>'}
            </div>
          </div>
          <div>
            <div class="scout-label">Corpus Context</div>
            <div class="scout-facts">${facts.length ? facts.map(fact => `<div>${escHtml(fact)}</div>`).join('') : '<em>No corpus facts returned.</em>'}</div>
          </div>
        </div>
        <div class="scout-fields">
          <span>${escHtml(extracted.proto || '-')}</span>
          <span>sig ${escHtml(extracted.signature_id || '-')}</span>
          <span>${escHtml(extracted.category || '-')}</span>
          <span>${escHtml(fmtTime(extracted.timestamp || card.created_at))}</span>
        </div>
        <div class="scout-actions">
          <button class="btn btn-sm" onclick="showAlertOverlay('${escHtml(card.alert_id)}')">View Alert</button>
        </div>
      </div>
    `;
  }).join('');
}

function normalizeScoutFacts(value) {
  if (Array.isArray(value)) return value.map(item => String(item)).filter(Boolean);
  if (value && typeof value === 'object') {
    return Object.entries(value).map(([key, val]) => `${key}: ${Array.isArray(val) ? val.join(', ') : val}`);
  }
  if (value === null || value === undefined || value === '') return [];
  return [String(value)];
}

async function bulkIncidentAction(status) {
  const ids = [..._selectedIncidents];
  if (!ids.length) return;
  if (!confirm(`${status === 'resolved' ? 'Resolve' : 'Mark as FP'} ${ids.length} incident(s)?`)) return;
  try {
    await Promise.all(ids.map(id =>
      fetch(`/api/incidents/${id}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, resolved_by: 'bulk-action' }),
      })
    ));
    _selectedIncidents.clear();
    toast(`${ids.length} incident(s) updated`, 'success');
    fetchIncidents();
  } catch (err) {
    toast(`Bulk action failed: ${err.message}`, 'error');
  }
}

async function showIncidentDetail(id) {
  try {
    const res = await fetch(`/api/incidents/${id}`);
    const inc = await res.json();

    const overlay = document.createElement('div');
    overlay.className = 'incident-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

    const urgencyLabels = { noise: 'Likely Noise', check: 'Worth a Look', act_now: 'Act Now' };
    const urgency = inc.urgency || 'check';

    // Build interactive runbook
    const runbook = inc.runbook || [];
    const runbookHtml = runbook.map((step, i) => {
      const isObj = typeof step === 'object' && step !== null;
      const desc = isObj ? (step.description || '') : String(step);
      const cmd = isObj ? step.command : null;
      const expect = isObj ? step.expect : null;
      const badSign = isObj ? step.bad_sign : null;
      const decision = isObj ? step.decision : null;

      // Format description - highlight commands
      const fmtDesc = desc.replace(/`([^`]+)`/g, '<code>$1</code>');

      let cmdBar = '';
      if (cmd) {
        cmdBar = `
          <div class="step-command-bar">
            <span class="step-command-text">${escHtml(cmd)}</span>
            <button class="btn-run-cmd" onclick="executeRunbookStep('${id}', ${i}, this)" data-cmd="${escHtml(cmd)}">Run</button>
          </div>`;
      }

      let hints = '';
      if (expect || badSign) {
        hints = `<div class="step-hints">
          ${expect ? `<span class="step-hint good"><span class="step-hint-icon">&#10003;</span> ${escHtml(expect)}</span>` : ''}
          ${badSign ? `<span class="step-hint bad"><span class="step-hint-icon">&#9888;</span> ${escHtml(badSign)}</span>` : ''}
        </div>`;
      }

      let decisionHtml = decision ? `<div class="step-decision">${escHtml(decision)}</div>` : '';

      return `
        <div class="runbook-step-interactive" id="runbook-step-${i}">
          <div class="step-header">
            <span class="step-number">${i + 1}</span>
            <span class="step-desc">${fmtDesc}</span>
          </div>
          ${hints}
          ${cmdBar}
          ${decisionHtml}
        </div>`;
    }).join('');

    // Build linked alerts - clickable to expand
    const alertsHtml = (inc.alerts || []).slice(0, 20).map(a => {
      const t = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '';
      const aid = a.id || '';
      return `<div class="linked-alert-row clickable" onclick="expandLinkedAlert('${escHtml(aid)}', this)">
        <span class="linked-alert-sev ${a.severity || 'medium'}"></span>
        <span class="linked-alert-time">${t}</span>
        <span class="linked-alert-title">${escHtml(a.title || '')}</span>
        <span class="linked-alert-ip">${a.src_ip || ''} &rarr; ${a.dst_ip || ''}</span>
        <span class="linked-alert-expand">&#9654;</span>
      </div>`;
    }).join('');

    // Build affected IPs section with reputation lookup
    const affectedIps = inc.affected_ips || [];
    const ipsHtml = affectedIps.length ? affectedIps.map(ip =>
      `<div class="ip-card" id="ip-card-${ip.replace(/\./g, '-')}" data-ip="${escHtml(ip)}">
        <span class="ip-card-addr">${escHtml(ip)}</span>
        <span class="ip-card-rep" id="ip-rep-${ip.replace(/\./g, '-')}">checking...</span>
        <div class="ip-card-actions">
          <button class="btn-sm" onclick="filterAlertsByIp('${escHtml(ip)}')">View Alerts</button>
          <button class="btn-sm" onclick="window.open('/api/reputation/${encodeURIComponent(ip)}', '_blank')">Full Report</button>
        </div>
      </div>`
    ).join('') : '';

    // Decision buttons based on status
    let actionsHtml = '';
    if (inc.status === 'new' || inc.status === 'investigating') {
      actionsHtml = `
        ${inc.status === 'new' ? `<button class="btn btn-investigate" onclick="decideIncident('${id}', 'investigating')">Start Investigating</button>` : ''}
        <button class="btn btn-resolve" onclick="decideIncident('${id}', 'resolved')">Mark Resolved</button>
        <button class="btn btn-fp" onclick="decideIncident('${id}', 'false_positive')">False Positive</button>`;
    } else {
      actionsHtml = `<button class="btn btn-investigate" onclick="decideIncident('${id}', 'investigating')">Reopen</button>`;
    }

    overlay.innerHTML = `
      <div class="incident-detail">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:0.75rem">
          <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">
            <span class="urgency-badge ${urgency}">${urgencyLabels[urgency] || 'Check'}</span>
            <span class="incident-sev-badge ${inc.severity}">${inc.severity}</span>
            <span class="incident-status-badge ${inc.status}">${inc.status.replace('_', ' ')}</span>
          </div>
          <button class="btn btn-close-overlay" onclick="this.closest('.incident-overlay').remove()" style="padding:0.25rem 0.5rem">&times;</button>
        </div>
        <h2>${escHtml(inc.title)}</h2>
        <div class="incident-summary">${escHtml(inc.summary)}</div>
        <div class="incident-meta" style="margin-top:0.5rem">
          <span>${inc.alert_count} alert${inc.alert_count !== 1 ? 's' : ''}</span>
          <span>${timeAgo(new Date(inc.created_at))}</span>
          ${inc.category ? `<span>${escHtml(inc.category.replace(/_/g, ' '))}</span>` : ''}
        </div>

        <!-- Affected IPs -->
        ${ipsHtml ? `<div class="incident-ips-bar">${ipsHtml}</div>` : ''}

        <!-- Tab bar -->
        <div class="incident-tabs">
          <button class="incident-tab active" data-tab="investigate" onclick="switchIncidentTab(this, 'investigate', '${id}')">Investigate</button>
          <button class="incident-tab" data-tab="runbook" onclick="switchIncidentTab(this, 'runbook', '${id}')">Runbook</button>
          <button class="incident-tab" data-tab="alerts" onclick="switchIncidentTab(this, 'alerts', '${id}')">Alerts (${inc.alerts?.length || 0})</button>
          <button class="incident-tab" data-tab="timeline" onclick="switchIncidentTab(this, 'timeline', '${id}')">Timeline</button>
          <button class="incident-tab" data-tab="notes" onclick="switchIncidentTab(this, 'notes', '${id}')">Notes</button>
        </div>

        <!-- Tab panels -->
        <div class="incident-tab-panel active" id="tab-investigate-${id}">
          <div class="investigate-panel">
            <div class="investigate-actions">
              <button class="btn btn-primary" onclick="runIncidentJttw('${id}', this)">Deep AI Investigation</button>
              <button class="btn" onclick='filterAlertsByIncident("${id}", ${JSON.stringify(inc.affected_ips || [])})'>View All Alerts From These IPs</button>
            </div>
            <div class="investigate-hints">
              <h4>What to check</h4>
              <ul>
                <li>Are the affected IPs <strong>devices you recognize</strong> on your network?</li>
                <li>Is the traffic pattern <strong>normal for these devices</strong>? (e.g., a server talking to a workstation)</li>
                <li>Check the <strong>IP reputation cards</strong> above - red = known bad</li>
                <li>Look at the <strong>Alerts tab</strong> to see exactly what triggered this</li>
                <li>Use <strong>Deep AI Investigation</strong> to get a full analysis</li>
              </ul>
            </div>
            <div id="incident-jttw-${id}" class="incident-jttw-result"></div>
          </div>
        </div>

        <div class="incident-tab-panel" id="tab-runbook-${id}">
          ${runbookHtml ? `<div class="incident-runbook">${runbookHtml}</div>` : '<div class="empty-state" style="padding:1rem">No runbook steps defined.</div>'}
        </div>

        <div class="incident-tab-panel" id="tab-alerts-${id}">
          ${alertsHtml ? `<div class="incident-linked-alerts">${alertsHtml}</div>` : '<div class="empty-state" style="padding:1rem">No linked alerts.</div>'}
        </div>

        <div class="incident-tab-panel" id="tab-notes-${id}">
          <div class="incident-notes-area">
            <div class="incident-notes-list" id="notes-list-${id}">Loading notes...</div>
            <div class="incident-note-form">
              <textarea id="note-input-${id}" placeholder="Add a note..." rows="2"></textarea>
              <button class="btn" onclick="addIncidentNote('${id}')">Add Note</button>
            </div>
          </div>
        </div>

        <div class="incident-actions" id="incident-actions-${id}">
          ${actionsHtml}
          <button class="btn btn-close-overlay" onclick="this.closest('.incident-overlay').remove()">Close</button>
        </div>
        <div id="learning-feedback-${id}"></div>
      </div>`;

    document.body.appendChild(overlay);

    // Load timeline, notes, and IP reputation in background
    loadIncidentTimeline(id);
    loadIncidentNotes(id);
    loadIncidentIpReputation(affectedIps);
  } catch (e) {
    console.error('showIncidentDetail error:', e);
  }
}

async function executeRunbookStep(incidentId, stepIndex, btn) {
  const cmd = btn.dataset.cmd;
  if (!cmd) return;
  btn.disabled = true;
  btn.textContent = 'Running...';

  const stepEl = document.getElementById(`runbook-step-${stepIndex}`);

  try {
    const res = await fetch(`/api/incidents/${incidentId}/runbook/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: cmd }),
    });
    const data = await res.json();

    if (data.error) {
      stepEl.insertAdjacentHTML('beforeend', `
        <div class="step-output"><pre style="color:var(--sev-critical)">${escHtml(data.error)}</pre></div>`);
      btn.textContent = 'Run';
      btn.disabled = false;
      return;
    }

    // Show output
    const output = (data.stdout || '') + (data.stderr ? '\n[stderr] ' + data.stderr : '');
    stepEl.insertAdjacentHTML('beforeend', `
      <div class="step-output"><pre>${escHtml(output || '(no output)')}</pre></div>`);

    btn.textContent = 'Interpreting...';

    // Get AI interpretation
    const expectEl = stepEl.querySelector('.step-hint.good');
    const badEl = stepEl.querySelector('.step-hint.bad');
    const interpRes = await fetch(`/api/incidents/${incidentId}/runbook/interpret`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        command: cmd,
        stdout: data.stdout || '',
        stderr: data.stderr || '',
        context: stepEl.querySelector('.step-desc')?.textContent || '',
        expect: expectEl?.textContent || '',
        bad_sign: badEl?.textContent || '',
      }),
    });
    const interpData = await interpRes.json();

    stepEl.insertAdjacentHTML('beforeend', `
      <div class="step-interpretation">
        <div class="interp-label">AI Analysis</div>
        ${escHtml(interpData.interpretation || 'No interpretation available.')}
      </div>`);

    stepEl.classList.add('completed');
    btn.textContent = 'Done';
    btn.disabled = true;
  } catch (e) {
    console.error('executeRunbookStep error:', e);
    btn.textContent = 'Run';
    btn.disabled = false;
  }
}

async function decideIncident(id, decision) {
  try {
    const res = await fetch(`/api/incidents/${id}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision }),
    });
    const data = await res.json();

    // Show learning suggestion if available
    if (data.suggestion) {
      const feedbackEl = document.getElementById(`learning-feedback-${id}`);
      if (feedbackEl) {
        feedbackEl.innerHTML = `
          <div class="learning-banner">
            <span class="learning-icon">&#129504;</span>
            <span class="learning-text">${escHtml(data.suggestion.message)}</span>
            <button class="btn btn-resolve" onclick="this.closest('.learning-banner').innerHTML = '&#10003; Got it! Similar incidents will be flagged as noise.'">Yes, auto-dismiss</button>
            <button class="btn btn-close-overlay" onclick="this.closest('.learning-banner').remove()">No thanks</button>
          </div>`;
        return;  // Don't close overlay - let them see the suggestion
      }
    }

    // Close overlay and refresh
    document.querySelector('.incident-overlay')?.remove();
    fetchIncidents();
  } catch (e) {
    console.error('decideIncident error:', e);
  }
}

async function updateIncidentStatus(id, status) {
  // Legacy wrapper - redirect to decideIncident
  await decideIncident(id, status);
}

async function checkSystemHealth() {
  try {
    const res = await fetch('/api/health');
    if (!res.ok) {
      toast(`System health check failed (HTTP ${res.status})`, 'error', 8000);
      return;
    }
    const data = await res.json();
    const cb = data?.triage?.circuit_breaker;
    const bannerId = 'cb-banner';
    let banner = document.getElementById(bannerId);
    if (cb?.tripped) {
      const sec = cb.cooldown_remaining_sec ?? 0;
      const msg = `AI triage is paused (circuit breaker open - resets in ${sec}s). Alerts are being rule-tagged only.`;
      if (!banner) {
        banner = document.createElement('div');
        banner.id = bannerId;
        banner.style.cssText = 'background:#b45309;color:#fff;padding:8px 16px;text-align:center;font-size:0.85rem;position:sticky;top:0;z-index:999';
        document.body.prepend(banner);
      }
      banner.textContent = msg;
    } else if (banner) {
      banner.remove();
    }
  } catch { /* silently ignore - WS disconnect already toasted */ }
}

function init() {
  // Theme
  initTheme();

  // Settings modal
  initSettings();

  // Apply default filter (Needs Attention = exclude suppressed)
  state.filters.verdict = dom.filterVerdict.value || '';

  // Initial data load
  fetchStats();
  fetchSecurityOps();
  fetchIncidents();
  fetchScoutCards();
  fetchAgents();
  fetchRecentAlerts();
  fetchAlerts(0);
  fetchCorrelations();
  fetchAiHistory();
  fetchTimeline();
  fetchTopTalkers();
  fetchConnections();
  fetchNetworkHosts();
  fetchVulnerabilities();
  loadSavedSearches();

  // Auto-refresh stats, correlations, timeline.
  // Stats hits an unindexed GROUP BY on the clusters table; 10s polling
  // pegged the DB on busy systems. 30s is plenty for a dashboard.
  state.statsInterval = setInterval(fetchStats, 30_000);
  setInterval(fetchSecurityOps, 60_000);
  setInterval(fetchAgents, 30_000);
  setInterval(fetchRecentAlerts, 30_000);
  setInterval(fetchIncidents, 60_000);
  setInterval(fetchScoutCards, 60_000);
  setInterval(fetchCorrelations, 120_000);
  setInterval(fetchAiHistory, 120_000);
  setInterval(() => { fetchTimeline(); fetchTopTalkers(); fetchConnections(); }, 120_000);
  setInterval(checkSystemHealth, 60_000);

  // WebSocket
  connectWS();

  // Filter controls
  dom.filterTimerange.addEventListener('change', applyFilters);
  dom.filterSource.addEventListener('change',    applyFilters);
  dom.filterSeverity.addEventListener('change',  applyFilters);
  dom.filterVerdict.addEventListener('change',   applyFilters);
  dom.incidentFilter?.addEventListener('change', fetchIncidents);
  dom.scoutRefresh?.addEventListener('click', fetchScoutCards);

  // Search box - FTS on Enter or debounce
  let searchDebounce;
  dom.searchBox.addEventListener('input', () => {
    clearTimeout(searchDebounce);
    const q = dom.searchBox.value.trim();
    if (!q) {
      fetchAlerts(0);
      return;
    }
    searchDebounce = setTimeout(() => searchAlerts(q), 400);
  });

  dom.searchBox.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      clearTimeout(searchDebounce);
      searchAlerts(dom.searchBox.value.trim());
    }
  });

  // AI Query bar
  dom.queryInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') askQuestion(dom.queryInput.value);
  });
  dom.queryBtn.addEventListener('click', () => askQuestion(dom.queryInput.value));

  // Pagination
  dom.btnPrev.addEventListener('click', () => {
    if (state.page > 0) fetchAlerts(state.page - 1);
  });
  dom.btnNext.addEventListener('click', () => {
    fetchAlerts(state.page + 1);
  });

  // Bulk actions
  dom.selectAllCb.addEventListener('change', () => selectAllOnPage(dom.selectAllCb.checked));
  dom.bulkSuppress.addEventListener('click', () => bulkSetVerdict('suppress'));
  dom.bulkInvestigate.addEventListener('click', () => bulkSetVerdict('investigate'));
  dom.bulkEscalate.addEventListener('click', () => bulkSetVerdict('escalate'));
  dom.bulkDeselect.addEventListener('click', deselectAll);
  dom.btnSuppressAll.addEventListener('click', suppressAllFiltered);

  // Wiki panel
  $('btn-wiki').addEventListener('click', () => openWiki());
  $('wiki-close').addEventListener('click', closeWiki);
  $('wiki-overlay').addEventListener('click', e => {
    if (e.target === $('wiki-overlay')) closeWiki();
  });

  // Tuning panel
  const btnTuning = $('btn-silence-rules');
  if (btnTuning) btnTuning.addEventListener('click', openTuning);
  const tuningClose = $('tuning-close');
  if (tuningClose) tuningClose.addEventListener('click', closeTuning);
  const tuningOverlay = $('tuning-overlay');
  if (tuningOverlay) tuningOverlay.addEventListener('click', e => {
    if (e.target === tuningOverlay) closeTuning();
  });
  const tuningAddBtn = $('tuning-add-btn');
  if (tuningAddBtn) tuningAddBtn.addEventListener('click', addTuningRule);
  const tuningMatchType = $('tuning-match-type');
  if (tuningMatchType) {
    tuningMatchType.addEventListener('change', () => {
      const p2 = $('tuning-pattern2');
      if (p2) p2.style.display = tuningMatchType.value === 'src_ip+title' ? '' : 'none';
      const p1 = $('tuning-pattern');
      if (p1) {
        const labels = { 'title': 'Title substring...', 'sig_id': 'Signature ID...', 'src_ip': 'Source IP...', 'dst_ip': 'Dest IP...', 'category': 'Category substring...', 'src_ip+title': 'IP address...', 'src_cidr': 'Source CIDR (e.g. 192.168.2.0/24)...', 'dst_cidr': 'Dest CIDR (e.g. 224.0.0.0/4)...' };
        p1.placeholder = labels[tuningMatchType.value] || 'Pattern...';
      }
    });
  }

  // AI-assisted silence rule
  const tuningAiBtn = $('tuning-ai-btn');
  if (tuningAiBtn) tuningAiBtn.addEventListener('click', askAiSilence);
  const tuningAiInput = $('tuning-ai-input');
  if (tuningAiInput) tuningAiInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') askAiSilence();
  });

  // Deploy guide button → open setup at Agents tab
  const deployGuideBtn = $('btn-deploy-guide');
  if (deployGuideBtn) {
    deployGuideBtn.addEventListener('click', () => openSetup('agents'));
  }

  // Setup panel
  const btnSetup = $('btn-setup');
  if (btnSetup) btnSetup.addEventListener('click', () => openSetup());
  const setupOverlay = $('setup-overlay');
  if (setupOverlay) {
    setupOverlay.addEventListener('click', e => {
      if (e.target === setupOverlay) closeSetup();
    });
  }

  // Agent pill → scroll to agents section
  if (dom.agentPill) {
    dom.agentPill.addEventListener('click', () => {
      const sec = $('agents-section');
      if (sec) sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  // Stat card click → filter + scroll to alert feed
  initStatCardClicks();

  // Help panel
  $('btn-help').addEventListener('click', openHelp);
  $('help-close').addEventListener('click', closeHelp);
  $('help-overlay').addEventListener('click', e => {
    if (e.target === $('help-overlay')) closeHelp();
  });
  // Copy buttons in help panel
  document.querySelectorAll('.help-copy').forEach(btn => {
    btn.addEventListener('click', () => {
      const code = btn.parentElement.querySelector('code');
      if (!code) return;
      const text = code.textContent.replace(/YOUR_SERVER_IP/g, location.hostname);
      navigator.clipboard.writeText(text).then(() => {
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
      });
    });
  });

  // Version check
  fetchVersion();
  setInterval(fetchVersion, 30 * 60_000); // check every 30 minutes

  // Update modal
  dom.updateBadge.addEventListener('click', openUpdateModal);
  dom.updateCancel.addEventListener('click', closeUpdateModal);
  dom.updateOverlay.addEventListener('click', closeUpdateModal);
  dom.updateConfirm.addEventListener('click', pullUpdate);

  // Theme toggle
  if (dom.btnTheme) dom.btnTheme.addEventListener('click', toggleTheme);

  // Export
  if (dom.btnExport) dom.btnExport.addEventListener('click', exportAlerts);

  // Saved searches
  if (dom.btnSaveSearch) dom.btnSaveSearch.addEventListener('click', saveCurrentSearch);
  if (dom.savedSearches) {
    dom.savedSearches.addEventListener('change', () => {
      const query = dom.savedSearches.value;
      if (query) {
        dom.searchBox.value = query;
        searchAlerts(query);
      }
    });
  }

  // View toggle (grouped/flat)
  if (dom.btnViewToggle) {
    dom.btnViewToggle.textContent = state.groupedView ? 'Flat' : 'Clusters';
    dom.btnViewToggle.addEventListener('click', toggleGroupedView);
  }

  // Keyboard shortcuts
  initKeyboard();
  if (dom.kbdClose) dom.kbdClose.addEventListener('click', () => toggleKbdHelp());
  if (dom.kbdOverlay) dom.kbdOverlay.addEventListener('click', e => {
    if (e.target === dom.kbdOverlay) toggleKbdHelp();
  });

  // Educational tips (delayed to avoid blocking initial render)
  setTimeout(() => showTips(), 1500);
}

// ── Educational Tips System ────────────────────────────────────────────────

const TIPS_STORAGE_KEY = 'shallots_tips_dismissed';
const TIPS_ALL_OFF_KEY = 'shallots_tips_off';

function getDismissedTips() {
  try { return JSON.parse(localStorage.getItem(TIPS_STORAGE_KEY) || '[]'); }
  catch { return []; }
}

function dismissTip(tipId) {
  const dismissed = getDismissedTips();
  if (!dismissed.includes(tipId)) {
    dismissed.push(tipId);
    localStorage.setItem(TIPS_STORAGE_KEY, JSON.stringify(dismissed));
  }
  const el = document.querySelector(`.tip-banner[data-tip="${tipId}"]`);
  if (el) el.remove();
}

function dismissAllTips() {
  localStorage.setItem(TIPS_ALL_OFF_KEY, 'true');
  dom.tipsContainer.innerHTML = '';
}

function showTips() {
  if (localStorage.getItem(TIPS_ALL_OFF_KEY) === 'true') return;
  const dismissed = getDismissedTips();
  const stats = state.lastStats || {};
  const bySource = stats.by_source || {};
  const total = stats.total_alerts || 0;
  const pending = stats.pending_triage || 0;
  const suppressed = stats.suppressed || 0;
  const correlations = stats.correlations || 0;

  const tips = [
    { id: 'what-is-severity', condition: true, content:
      'Severity levels: <strong>Critical</strong> = active exploitation or compromise. <strong>High</strong> = likely malicious. <strong>Medium</strong> = suspicious, needs review. <strong>Low</strong> = informational noise.' },
    { id: 'pending-explained', condition: pending > 0, content:
      '<strong>Pending</strong> alerts haven\'t been triaged yet. The AI reviews them in batches. You can also manually set verdicts.' },
    { id: 'suppress-explained', condition: total > 0 && suppressed > total * 0.4, content:
      'A large portion of your alerts are suppressed - this is normal. Suppressed means the alert is known noise (benign scanners, internal traffic, etc). Use <strong>Suppress All Filtered</strong> to clear backlogs.' },
    { id: 'external-internal', condition: true, content:
      '<strong>External→Internal</strong> traffic (internet hitting your network) is generally more concerning than internal→internal. Shallots automatically bumps severity for inbound threats.' },
    { id: 'what-is-suricata', condition: 'suricata' in bySource, content:
      '<strong>Suricata</strong> is your network IDS - it inspects all traffic and flags known malicious signatures. Alerts here mean packets matched a threat pattern.' },
    { id: 'what-is-wazuh', condition: 'wazuh' in bySource, content:
      '<strong>Wazuh</strong> monitors your endpoints - file integrity, log analysis, rootkit detection. Alerts here mean something changed on a host.' },
    { id: 'what-is-argus', condition: 'argus' in bySource, content:
      '<strong>Argus</strong> is the heavy endpoint sentinel - it watches for physical access, screen locks, USB devices, and runs forensic captures.' },
    { id: 'correlation-meaning', condition: correlations > 0, content:
      '<strong>Correlations</strong> are patterns the AI found across multiple alerts - for example, the same IP triggering different rules, or a sequence of events suggesting lateral movement.' },
    { id: 'try-ai-query', condition: true, content:
      'The <strong>AI Query</strong> bar understands plain English. Try: <em>"What external IPs hit my network in the last 24 hours?"</em>' },
    { id: 'bulk-select-tip', condition: true, content:
      'Use <strong>checkboxes</strong> to select multiple alerts and apply bulk verdicts in one action.' },
  ];

  // Show at most 3 tips at a time
  let shown = 0;
  for (const tip of tips) {
    if (shown >= 3) break;
    if (dismissed.includes(tip.id) || !tip.condition) continue;

    const el = document.createElement('div');
    el.className = 'tip-banner';
    el.dataset.tip = tip.id;
    el.innerHTML = `
      <button class="tip-dismiss" title="Dismiss">&times;</button>
      ${tip.content}
      <div class="tip-actions">
        <button class="tip-dismiss-all">Don't show tips</button>
      </div>`;
    el.querySelector('.tip-dismiss').addEventListener('click', () => dismissTip(tip.id));
    el.querySelector('.tip-dismiss-all').addEventListener('click', dismissAllTips);
    dom.tipsContainer.appendChild(el);
    shown++;
  }
}

// ── Alert Education ("What is this?") ─────────────────────────────────────

const EDUCATION_LOOKUP = {
  'ET MALWARE': 'This alert matched a known malware communication signature from Emerging Threats. It could indicate malware beaconing, downloading payloads, or exfiltrating data.',
  'ET SCAN': 'Network scanning detected - someone is probing your systems for open ports or services. Common in reconnaissance, the first stage of an attack.',
  'ET TROJAN': 'Traffic matched a known trojan command-and-control pattern. This could indicate an infected host communicating with an attacker.',
  'ET EXPLOIT': 'An exploit attempt was detected - someone is trying to leverage a vulnerability in a service or application.',
  'ET INFO': 'Informational alert - not necessarily malicious, but noteworthy. Examples: uncommon user agents, known VPN/proxy usage, or unusual DNS queries.',
  'ET POLICY': 'Policy violation detected - traffic that may violate your security policies, like P2P file sharing or unauthorized software.',
  'ET DOS': 'Denial-of-service activity detected - someone may be flooding your systems to disrupt availability.',
  'ET WEB_SERVER': 'Web server attack detected - could be SQL injection, XSS, directory traversal, or other web application attacks against your servers.',
  'ET WEB_CLIENT': 'Web client compromise attempt - malicious content targeting a browser or web client on your network.',
  'Authentication Failure': 'A login attempt failed - could be a brute force attack, credential stuffing, or just a user who forgot their password. Multiple failures from the same source are more concerning.',
  'File integrity': 'A monitored file was modified - check if this was an expected change (update, config edit) or potentially unauthorized tampering.',
  'Rootkit': 'Possible rootkit detected - this is a serious finding. Rootkits hide malicious software at the OS level. Investigate immediately.',
  'USB': 'A USB device event was detected. Could be a new device connected to a monitored endpoint. Unauthorized USB devices can be used for data theft or malware delivery.',
  'Screen lock': 'A screen lock/unlock event was recorded. Useful for tracking physical access patterns to workstations.',
  'Network anomaly': 'Unusual network behavior detected that doesn\'t match known signatures. Could indicate new or evolving threats.',
};

function getEducation(alert) {
  const title = (alert.title || '').toUpperCase();
  const category = (alert.category || '').toUpperCase();
  const combined = title + ' ' + category;
  for (const [prefix, explanation] of Object.entries(EDUCATION_LOOKUP)) {
    if (combined.includes(prefix.toUpperCase())) return explanation;
  }
  return null;
}

function wireWhatIsThis(card) {
  const alertId = card.dataset.id;
  const alert = state.alerts.find(a => a.id === alertId);
  if (!alert) return;

  const detail = card.querySelector('.alert-detail');
  if (!detail) return;
  const rawBtn = detail.querySelector('.raw-json-toggle');
  if (!rawBtn) return;

  // Inline explanation (existing feature)
  const explanation = getEducation(alert);
  if (explanation) {
    const link = document.createElement('button');
    link.className = 'what-is-this-link';
    link.textContent = 'What is this?';

    const block = document.createElement('div');
    block.className = 'what-is-this-block';
    block.textContent = explanation;

    link.addEventListener('click', e => {
      e.stopPropagation();
      block.classList.toggle('visible');
      link.textContent = block.classList.contains('visible') ? 'Hide explanation' : 'What is this?';
    });

    detail.insertBefore(block, rawBtn);
    detail.insertBefore(link, block);
  }

  // Wiki article link
  if (typeof resolveWikiArticle === 'function') {
    const article = resolveWikiArticle(alert);
    if (article) {
      const wikiLink = document.createElement('button');
      wikiLink.className = 'wiki-article-link';
      wikiLink.textContent = `Wiki: ${article.title}`;
      wikiLink.addEventListener('click', e => {
        e.stopPropagation();
        openWiki(article.id);
      });
      detail.insertBefore(wikiLink, rawBtn);
    }
  }
}

// ── IP Reputation ─────────────────────────────────────────────────────────

const _repCache = {};

async function fetchReputation(ip) {
  if (!ip || ip === '-') return null;
  if (_repCache[ip]) return _repCache[ip];
  try {
    const res = await fetch(`/api/reputation/${encodeURIComponent(ip)}`);
    if (!res.ok) return null;
    const data = await res.json();
    if (data.status === 'not_checked') return null;
    _repCache[ip] = data;
    return data;
  } catch { return null; }
}

function buildRepDot(rep) {
  if (!rep || !rep.verdict) return '';
  const v = rep.verdict;
  const score = [];
  if (rep.vt_malicious > 0 || rep.vt_total > 0)
    score.push(`VT: ${rep.vt_malicious}/${rep.vt_total}`);
  if (rep.abuse_score > 0)
    score.push(`Abuse: ${rep.abuse_score}%`);
  const info = score.join(', ') || v;

  const detailRows = [];
  if (rep.vt_total > 0) detailRows.push(`<div class="rep-row"><span class="rep-label">VT Detections</span><span class="rep-value ${v}">${rep.vt_malicious}/${rep.vt_total}</span></div>`);
  if (rep.abuse_score > 0) detailRows.push(`<div class="rep-row"><span class="rep-label">AbuseIPDB</span><span class="rep-value ${v}">${rep.abuse_score}%</span></div>`);
  if (rep.country) detailRows.push(`<div class="rep-row"><span class="rep-label">Country</span><span class="rep-value">${escHtml(rep.country)}</span></div>`);
  if (rep.isp) detailRows.push(`<div class="rep-row"><span class="rep-label">ISP</span><span class="rep-value">${escHtml(rep.isp)}</span></div>`);

  return `<span class="rep-wrapper" title="${escHtml(info)}">
    <span class="rep-dot ${v}"></span>
    <span class="rep-popover">
      <div class="rep-row"><span class="rep-label">Verdict</span><span class="rep-value ${v}">${v}</span></div>
      ${detailRows.join('')}
      <div class="rep-links">
        <a href="https://www.virustotal.com/gui/ip-address/${escHtml(rep.ip)}" target="_blank" rel="noopener">VirusTotal</a>
        <a href="https://www.abuseipdb.com/check/${escHtml(rep.ip)}" target="_blank" rel="noopener">AbuseIPDB</a>
      </div>
    </span>
  </span>`;
}

async function enrichCardReputation(card) {
  const fields = card.querySelectorAll('.detail-field');
  for (const field of fields) {
    const key = field.querySelector('.detail-key');
    const val = field.querySelector('.detail-val');
    if (!key || !val) continue;
    const label = key.textContent.trim();
    if (label !== 'Src IP' && label !== 'Dst IP') continue;
    const ip = val.textContent.trim();
    if (!ip) continue;
    const rep = await fetchReputation(ip);
    if (rep && rep.verdict) {
      if (!val.querySelector('.rep-wrapper')) {
        val.insertAdjacentHTML('afterbegin', buildRepDot(rep) + ' ');
      }
      // Show ISP/org name beside IP
      if (rep.isp && !val.querySelector('.ip-org')) {
        val.insertAdjacentHTML('beforeend',
          ` <span class="ip-org">(${escHtml(rep.isp)})</span>`);
      }
    }
  }
}

// ── Alert Context (Investigation Powerups) ────────────────────────────────

async function loadAlertContext(card) {
  const alertId = card.dataset.id || card.querySelector('[data-alert-id]')?.dataset?.alertId;
  if (!alertId) return;
  const ctxSlot = card.querySelector('.context-slot');
  const relSlot = card.querySelector('.related-alerts-slot');
  if (!ctxSlot) return;

  try {
    const res = await fetch(`/api/alerts/${encodeURIComponent(alertId)}/context`);
    if (!res.ok) return;
    const ctx = await res.json();

    // Suggested action banner
    let ctxHtml = '';
    if (ctx.triage && ctx.triage.suggested_action) {
      ctxHtml += `<div class="suggested-action">
        <span class="suggested-action-label">Suggested action</span>
        <span>${escHtml(ctx.triage.suggested_action)}</span>
      </div>`;
    }

    // Pattern frequency indicator
    const srcTotal = ctx.src_summary ? ctx.src_summary.total : 0;
    const src24h = ctx.src_summary ? ctx.src_summary.last_24h : 0;
    if (srcTotal > 1) {
      ctxHtml += `<div class="pattern-freq">This source IP appeared in <strong>${srcTotal}</strong> alert${srcTotal !== 1 ? 's' : ''} total (<strong>${src24h}</strong> in last 24h)</div>`;
    }
    if (ctxHtml) ctxSlot.innerHTML = ctxHtml;

    // IP history badges
    if (ctx.src_summary) {
      const slot = card.querySelector('.ip-history-slot[data-ip="' + CSS.escape(ctx.src_summary.ip) + '"]');
      if (slot) {
        slot.innerHTML = `<span class="ip-history">${ctx.src_summary.last_24h} in 24h &middot; ${ctx.src_summary.total} total</span>` +
          ` <a class="view-all-link" data-filter-ip="${escHtml(ctx.src_summary.ip)}">View all &rarr;</a>`;
      }
    }
    if (ctx.dst_summary) {
      const slot = card.querySelector('.ip-history-slot[data-ip="' + CSS.escape(ctx.dst_summary.ip) + '"]');
      if (slot) {
        slot.innerHTML = `<span class="ip-history">${ctx.dst_summary.last_24h} in 24h &middot; ${ctx.dst_summary.total} total</span>` +
          ` <a class="view-all-link" data-filter-ip="${escHtml(ctx.dst_summary.ip)}">View all &rarr;</a>`;
      }
    }

    // Wire "View all" links
    card.querySelectorAll('.view-all-link[data-filter-ip]').forEach(link => {
      link.addEventListener('click', e => {
        e.stopPropagation();
        const ip = link.dataset.filterIp;
        // Switch to flat view filtered by src_ip
        state.groupedView = false;
        if (dom.btnViewToggle) dom.btnViewToggle.textContent = 'Clusters';
        state.filters.source = '';
        state.filters.severity = '';
        state.filters.verdict = '';
        dom.filterSource.value = '';
        dom.filterSeverity.value = '';
        dom.filterVerdict.value = '';
        // Use search box to show filter
        dom.searchBox.value = `src_ip:${ip}`;
        // Fetch with src_ip filter
        fetchFilteredByIp(ip);
      });
    });

    // Related alerts
    if (relSlot && ctx.related_alerts && ctx.related_alerts.length) {
      const srcIp = ctx.src_summary ? ctx.src_summary.ip : '';
      relSlot.innerHTML = `<div class="related-alerts">
        <div class="related-header">
          <span>Other alerts from ${escHtml(srcIp)}</span>
          <a class="view-all-link" data-filter-ip="${escHtml(srcIp)}">View all &rarr;</a>
        </div>
        <div class="related-list">${ctx.related_alerts.map(r => `
          <div class="corr-alert-row related-alert-row" data-alert-id="${escHtml(r.id)}">
            ${severityBadge(r.severity)}
            <span class="corr-alert-title">${escHtml(r.title || '(no title)')}</span>
            <span class="corr-alert-flow">${escHtml(r.src_ip || '')}${r.dst_ip ? ' → ' + escHtml(r.dst_ip) : ''}</span>
            <span class="corr-alert-time">${fmtRelative(r.timestamp)}</span>
          </div>`).join('')}
        </div>
      </div>`;

      // Wire related alert clicks
      relSlot.querySelectorAll('.related-alert-row').forEach(row => {
        row.addEventListener('click', e => {
          e.stopPropagation();
          scrollToAlert(row.dataset.alertId);
        });
      });

      // Wire "View all" in related section
      relSlot.querySelectorAll('.view-all-link[data-filter-ip]').forEach(link => {
        link.addEventListener('click', e => {
          e.stopPropagation();
          const ip = link.dataset.filterIp;
          state.groupedView = false;
          if (dom.btnViewToggle) dom.btnViewToggle.textContent = 'Clusters';
          dom.searchBox.value = `src_ip:${ip}`;
          fetchFilteredByIp(ip);
        });
      });
    } else if (relSlot) {
      relSlot.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.8rem;color:var(--text-muted)">No related alerts from this source IP in the last 7 days.</div>';
    }
  } catch (err) {
    console.debug('loadAlertContext error:', err);
  }
}

async function fetchFilteredByIp(ip) {
  // Custom fetch that adds src_ip filter
  const params = new URLSearchParams({
    limit: String(state.pageSize),
    offset: '0',
  });
  params.set('src_ip', ip);
  if (state.filters.timerange) params.set('since', state.filters.timerange);
  try {
    const res = await fetch(`/api/alerts?${params}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.alerts = data.alerts || [];
    state.page = 0;
    state.searchMode = false;
    renderAlertList(state.alerts);
    updatePagination(state.alerts.length, 0);
    dom.alertCount.textContent = `${data.total ?? state.alerts.length} alerts from ${ip}`;
  } catch (err) {
    toast(`Filter failed: ${err.message}`, 'error');
  }
}

function wirePivotClicks(container) {
  container.querySelectorAll('.detail-pivot').forEach(link => {
    if (link.dataset.wired) return;
    link.dataset.wired = '1';
    link.addEventListener('click', e => {
      e.stopPropagation();
      e.preventDefault();
      const field = link.dataset.pivotField;
      const value = link.dataset.pivotValue;
      if (!value) return;
      // Close any overlay
      document.querySelectorAll('.alert-overlay').forEach(o => o.remove());
      // Put value in search box and search
      state.groupedView = false;
      if (dom.btnViewToggle) dom.btnViewToggle.textContent = 'Clusters';
      dom.searchBox.value = value;
      searchAlerts(value);
      const feedEl = document.getElementById('alert-feed');
      if (feedEl) setTimeout(() => feedEl.scrollIntoView({ behavior: 'smooth' }), 150);
    });
  });
}

function wireCopyButtons(container) {
  container.querySelectorAll('.copy-btn').forEach(btn => {
    if (btn.dataset.wired) return;
    btn.dataset.wired = '1';
    btn.addEventListener('click', e => {
      e.stopPropagation();
      copyToClipboard(btn.dataset.copy || '');
    });
  });
}

// ── Version / Update ──────────────────────────────────────────────────────

let _versionData = null;

async function fetchVersion() {
  try {
    const res = await fetch('/api/version');
    if (!res.ok) return;
    _versionData = await res.json();

    // Footer
    if (dom.versionText) {
      const dirty = _versionData.git_dirty ? ' (dirty)' : '';
      const hash = _versionData.git_hash ? `-${_versionData.git_hash}` : '';
      dom.versionText.textContent = `Security Shallots v${_versionData.version}${hash}${dirty}`;
    }

    // Update badge
    if (_versionData.update_available && dom.updateBadge) {
      dom.updateBadge.textContent = `Update (${_versionData.commits_behind} commit${_versionData.commits_behind !== 1 ? 's' : ''})`;
      dom.updateBadge.classList.add('visible');
    } else if (dom.updateBadge) {
      dom.updateBadge.classList.remove('visible');
    }
  } catch (err) {
    console.debug('fetchVersion error:', err);
  }
}

function openUpdateModal() {
  if (!_versionData) return;
  dom.updateInfo.textContent = `${_versionData.commits_behind} commit(s) behind origin/${_versionData.git_branch}. Pull to update?`;
  dom.updateOutput.style.display = 'none';
  dom.updateOutput.textContent = '';
  dom.updateConfirm.disabled = false;
  dom.updateConfirm.textContent = 'Pull Update';
  dom.updateOverlay.classList.add('visible');
  dom.updateModal.classList.add('visible');
}

function closeUpdateModal() {
  dom.updateOverlay.classList.remove('visible');
  dom.updateModal.classList.remove('visible');
}

async function pullUpdate() {
  dom.updateConfirm.disabled = true;
  dom.updateConfirm.textContent = 'Pulling...';
  try {
    const res = await fetch('/api/update', { method: 'POST' });
    const data = await res.json();
    dom.updateOutput.textContent = data.stdout || data.stderr || data.message || '(no output)';
    dom.updateOutput.style.display = 'block';
    if (data.ok) {
      toast('Update pulled. Restart shallotd to apply.', 'success', 8000);
      dom.updateConfirm.textContent = 'Done';
      if (dom.updateBadge) dom.updateBadge.classList.remove('visible');
    } else {
      toast('Update failed. Check output.', 'error');
      dom.updateConfirm.textContent = 'Failed';
    }
  } catch (err) {
    toast(`Update error: ${err.message}`, 'error');
    dom.updateConfirm.textContent = 'Error';
  }
}

// ── Cluster View ──────────────────────────────────────────────────────────

function renderClusterList(clusters) {
  if (!clusters.length) {
    const hasFilter = state.filters.verdict;
    const context = hasFilter ? 'no-filter-results' : 'no-alerts';
    dom.alertList.innerHTML = smartEmptyState(context);
    dom.alertCount.textContent = '0 clusters';
    dom.selectAllWrap.style.display = 'none';
    return;
  }
  dom.alertCount.textContent = `${clusters.length} cluster${clusters.length !== 1 ? 's' : ''}`;
  dom.selectAllWrap.style.display = 'none';
  dom.alertList.innerHTML = clusters.map(c => buildClusterCard(c)).join('');

  // Wire verdict buttons
  dom.alertList.querySelectorAll('.cluster-verdict-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      setClusterVerdict(btn.dataset.clusterId, btn.dataset.verdict);
    });
  });

  // Wire silence buttons
  dom.alertList.querySelectorAll('.silence-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      if (btn.classList.contains('silence-combo')) {
        silenceIpTitle(btn.dataset.ip, btn.dataset.title);
      } else if (btn.classList.contains('silence-dst-ip')) {
        silenceDstIp(btn.dataset.ip);
      } else if (btn.classList.contains('silence-ip')) {
        silenceIp(btn.dataset.ip);
      } else {
        silenceTitle(btn.dataset.title);
      }
    });
  });

  // Wire click-to-expand on cluster cards
  dom.alertList.querySelectorAll('.grouped-card').forEach(card => {
    const summary = card.querySelector('.alert-summary');
    summary.addEventListener('click', e => {
      if (e.target.closest('.cluster-verdict-btn') || e.target.closest('.silence-btn')) return;
      const wasExpanded = card.classList.contains('expanded');
      card.classList.toggle('expanded');
      if (!wasExpanded && !card.dataset.loaded) {
        card.dataset.loaded = '1';
        loadClusterAlerts(card);
      }
    });
  });
}

function buildClusterCard(c) {
  const cnt = c.alert_count || 1;
  const badge = cnt > 1 ? `<span class="group-count">&times;${cnt}</span>` : '';
  const srcLabel = escHtml(c.src_ip || '(no IP)');
  const timeRange = cnt > 1
    ? `${fmtRelative(c.first_seen)} - ${fmtRelative(c.last_seen)}`
    : fmtRelative(c.last_seen);
  const verdictClass = c.verdict ? `verdict-${c.verdict}` : '';
  const verdictLabel = c.verdict || 'pending';

  return `
    <div class="alert-card grouped-card" data-cluster-id="${escHtml(c.id)}" data-group-title="${escHtml(c.title || '')}" data-group-ip="${escHtml(c.src_ip || '')}">
      <div class="alert-summary">
        <div class="alert-badges">
          ${severityBadge(c.severity)}
          ${badge}
          <span class="badge badge-verdict ${verdictClass}">${escHtml(verdictLabel)}</span>
        </div>
        <div class="alert-main">
          <div class="alert-title">${escHtml(c.title || '(no title)')}</div>
          <div class="alert-meta">
            <span class="alert-flow">${srcLabel}</span>
          </div>
        </div>
        <div class="alert-time">
          <div>${timeRange}</div>
          <div class="cluster-actions">
            <button class="cluster-verdict-btn cv-suppress" data-cluster-id="${escHtml(c.id)}" data-verdict="suppress" title="Suppress all alerts in this cluster">Suppress</button>
            <button class="cluster-verdict-btn cv-investigate" data-cluster-id="${escHtml(c.id)}" data-verdict="investigate" title="Mark for investigation">Investigate</button>
            <button class="cluster-verdict-btn cv-escalate" data-cluster-id="${escHtml(c.id)}" data-verdict="escalate" title="Escalate all alerts">Escalate</button>
            <span class="alert-chevron">&#9656;</span>
          </div>
        </div>
      </div>
      <div class="group-detail" id="cd-${escHtml(c.id)}">
        <div class="empty-state" style="padding:0.5rem;font-size:0.8rem">Click to load alerts…</div>
      </div>
    </div>`;
}

async function setClusterVerdict(clusterId, verdict) {
  if (!clusterId || !verdict) return;
  try {
    const res = await fetch(`/api/clusters/${encodeURIComponent(clusterId)}/verdict`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verdict }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    toast(`Cluster ${verdict}: ${data.alerts_updated} alert(s) updated`, 'success');
    fetchAlerts(state.page);
    fetchStats();
  } catch (err) {
    toast(`Failed to set cluster verdict: ${err.message}`, 'error');
  }
}

async function loadClusterAlerts(card) {
  const clusterId = card.dataset.clusterId;
  const detail = card.querySelector('.group-detail');
  if (!detail || !clusterId) return;

  detail.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.8rem"><span class="loading-spinner"></span> Loading…</div>';

  try {
    const res = await fetch(`/api/clusters/${encodeURIComponent(clusterId)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const alerts = data.alerts || [];

    if (!alerts.length) {
      detail.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.8rem">No member alerts found</div>';
      return;
    }

    detail.innerHTML = alerts.map(a => {
      const flow = a.src_ip && a.dst_ip
        ? `${escHtml(a.src_ip)}:${a.src_port || '?'} → ${escHtml(a.dst_ip)}:${a.dst_port || '?'}`
        : a.src_ip || a.dst_ip || '';
      const verdictClass = a.verdict ? `verdict-${a.verdict}` : '';
      return `<div class="group-alert-item">
        <span class="group-alert-time">${fmtRelative(a.timestamp)}</span>
        <span class="group-alert-badges">${severityBadge(a.severity)} <span class="badge badge-verdict ${verdictClass}">${escHtml(a.verdict || 'pending')}</span></span>
        <span class="group-alert-flow">${flow}</span>
        <span class="group-alert-link" data-alert-id="${escHtml(a.id)}">View ↗</span>
      </div>`;
    }).join('');

    // Wire "View" links
    detail.querySelectorAll('.group-alert-link').forEach(link => {
      link.addEventListener('click', e => {
        e.stopPropagation();
        const alertId = link.dataset.alertId;
        state.groupedView = false;
        if (dom.btnViewToggle) dom.btnViewToggle.textContent = 'Clusters';
        fetchAlerts(0).then(() => {
          const target = dom.alertList.querySelector(`[data-id="${alertId}"]`);
          if (target) {
            target.classList.add('expanded', 'kbd-focus');
            target.scrollIntoView({ block: 'center', behavior: 'smooth' });
            if (!target.dataset.repLoaded) {
              target.dataset.repLoaded = '1';
              enrichCardReputation(target);
              loadNotes(target);
              loadAlertContext(target);
            }
          }
        });
      });
    });
  } catch (err) {
    detail.innerHTML = `<div class="empty-state" style="padding:0.5rem;font-size:0.8rem">Failed to load: ${escHtml(err.message)}</div>`;
  }
}

function toggleGroupedView() {
  state.groupedView = !state.groupedView;
  if (dom.btnViewToggle) {
    dom.btnViewToggle.textContent = state.groupedView ? 'Flat' : 'Clusters';
  }
  fetchAlerts(0);
}

// ── Silence ───────────────────────────────────────────────────────────────

async function silenceTitle(title) {
  if (!title) return;
  if (!confirm(`PERMANENTLY MUTE this alert type?\n\n"${title}"\n\nAll existing alerts with this title will be suppressed, and any future alerts matching this title will be auto-suppressed.\n\nYou can undo this later from the Silence Rules panel.`)) return;
  try {
    const res = await fetch('/api/silence-rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        match_type: 'title',
        pattern: title,
        reason: 'Silenced from dashboard',
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    toast(`Silenced. ${data.suppressed} existing alert(s) suppressed.`, 'success');
    fetchAlerts(state.page);
    fetchStats();
  } catch (err) {
    toast(`Silence failed: ${err.message}`, 'error');
  }
}

async function silenceIp(ip) {
  if (!ip) return;
  if (!confirm(`MUTE ALL ALERTS from IP: ${ip}?\n\nAll existing and future alerts with this source IP will be suppressed.\n\nYou can undo this from the Silence Rules panel.`)) return;
  try {
    const res = await fetch('/api/silence-rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        match_type: 'src_ip',
        pattern: ip,
        reason: `Silenced IP from dashboard`,
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    toast(`IP muted. ${data.suppressed} existing alert(s) suppressed.`, 'success');
    fetchAlerts(state.page);
    fetchStats();
  } catch (err) {
    toast(`Silence failed: ${err.message}`, 'error');
  }
}

async function silenceDstIp(ip) {
  if (!ip) return;
  if (!confirm(`MUTE ALL ALERTS to dest IP: ${ip}?\n\nAll existing and future alerts with this destination IP will be suppressed.\n\nYou can undo this from the Silence Rules panel.`)) return;
  try {
    const res = await fetch('/api/silence-rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        match_type: 'dst_ip',
        pattern: ip,
        reason: `Silenced dest IP from dashboard`,
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    toast(`Dest IP muted. ${data.suppressed} existing alert(s) suppressed.`, 'success');
    fetchAlerts(state.page);
    fetchStats();
  } catch (err) {
    toast(`Silence failed: ${err.message}`, 'error');
  }
}

async function silenceIpTitle(ip, title) {
  if (!ip || !title) return;
  if (!confirm(`MUTE "${title}" FROM ${ip}?\n\nOnly alerts matching BOTH this title AND this source IP will be suppressed.\n\nYou can undo this from the Silence Rules panel.`)) return;
  try {
    const res = await fetch('/api/silence-rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        match_type: 'src_ip+title',
        pattern: ip,
        pattern2: title,
        reason: `Silenced IP+Title from dashboard`,
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    toast(`IP+Title muted. ${data.suppressed} existing alert(s) suppressed.`, 'success');
    fetchAlerts(state.page);
    fetchStats();
  } catch (err) {
    toast(`Silence failed: ${err.message}`, 'error');
  }
}

async function silenceAndForget(alertId, title) {
  if (!title) { toast('No title to silence', 'error'); return; }
  if (!confirm(`Silence all alerts with title:\n"${title}"\n\nThis card will be removed.`)) return;
  try {
    const res = await fetch('/api/silence-rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        match_type: 'title',
        pattern: title,
        reason: 'Silence & Forget from alert card',
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    // Fade out the card
    const card = dom.alertList?.querySelector(`[data-id="${alertId}"]`);
    if (card) {
      card.style.transition = 'opacity 0.4s, transform 0.4s';
      card.style.opacity = '0';
      card.style.transform = 'translateX(40px)';
      setTimeout(() => card.remove(), 400);
    }
    toast(`Silenced. ${data.suppressed || 0} alert(s) suppressed.`, 'success');
    fetchStats();
  } catch (err) {
    toast(`Silence failed: ${err.message}`, 'error');
  }
}

async function askAiSilence() {
  const input = document.getElementById('tuning-ai-input');
  const status = document.getElementById('tuning-ai-status');
  const btn = document.getElementById('tuning-ai-btn');
  if (!input || !status) return;

  const request = input.value.trim();
  if (!request) { toast('Type what you want to silence', 'error'); return; }

  btn.disabled = true;
  btn.textContent = 'Thinking...';
  status.style.display = 'block';
  status.className = 'tuning-ai-status thinking';
  status.textContent = 'AI is analyzing your alerts...';

  try {
    const res = await fetch('/api/silence-rules/ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request }),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      status.className = 'tuning-ai-status error';
      status.textContent = data.error || data.ai_raw || 'AI failed to create a rule';
      return;
    }
    const p2 = data.pattern2 ? ` + "${data.pattern2}"` : '';
    status.className = 'tuning-ai-status success';
    status.innerHTML = `Rule created: <strong>${escHtml(data.match_type)}</strong> → <code>${escHtml(data.pattern)}${escHtml(p2)}</code><br>${escHtml(data.reason)}<br>${data.suppressed} existing alert(s) suppressed.`;
    input.value = '';
    fetchAlerts(state.page);
    fetchStats();
    loadTuningRules();
  } catch (err) {
    status.className = 'tuning-ai-status error';
    status.textContent = `Failed: ${err.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Ask AI';
  }
}

function wireSilenceButton(card) {
  card.querySelectorAll('.silence-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      if (btn.classList.contains('silence-combo')) {
        silenceIpTitle(btn.dataset.ip, btn.dataset.title);
      } else if (btn.classList.contains('silence-dst-ip')) {
        silenceDstIp(btn.dataset.ip);
      } else if (btn.classList.contains('silence-ip')) {
        silenceIp(btn.dataset.ip);
      } else {
        silenceTitle(btn.dataset.title);
      }
    });
  });
}

// ── Tuning Rules Panel ────────────────────────────────────────────────────

function openTuning() {
  const overlay = document.getElementById('tuning-overlay');
  if (overlay) { overlay.style.display = 'flex'; loadTuningRules(); }
}

function closeTuning() {
  const overlay = document.getElementById('tuning-overlay');
  if (overlay) overlay.style.display = 'none';
}

async function loadTuningRules() {
  const list = document.getElementById('tuning-rules-list');
  if (!list) return;
  try {
    const res = await fetch('/api/silence-rules');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const rules = data.rules || [];
    if (!rules.length) {
      list.innerHTML = '<div class="empty-state" style="padding:1rem;font-size:0.85rem">No silence rules yet. Use the form above or click "Mute" on any alert group.</div>';
      return;
    }
    list.innerHTML = rules.map(r => {
      const typeLabel = {
        'title': 'Title',
        'sig_id': 'Sig ID',
        'src_ip': 'Source IP',
        'dst_ip': 'Dest IP',
        'category': 'Category',
        'src_ip+title': 'IP+Title',
        'src_cidr': 'Source CIDR',
        'dst_cidr': 'Dest CIDR',
      }[r.match_type] || r.match_type;
      const pattern2 = r.pattern2 ? ` + "${escHtml(r.pattern2)}"` : '';
      const hits = r.hit_count ? `<span class="tuning-hits">${r.hit_count} hits</span>` : '';
      const lastHit = r.last_hit ? `<span class="tuning-last-hit">last: ${fmtRelative(r.last_hit)}</span>` : '';
      return `<div class="tuning-rule" data-rule-id="${escHtml(r.id)}">
        <div class="tuning-rule-info">
          <span class="tuning-rule-type">${typeLabel}</span>
          <span class="tuning-rule-pattern">${escHtml(r.pattern)}${pattern2}</span>
          ${r.reason ? `<span class="tuning-rule-reason">${escHtml(r.reason)}</span>` : ''}
          <span class="tuning-rule-meta">${hits} ${lastHit} created ${fmtRelative(r.created_at)}</span>
        </div>
        <button class="btn tuning-delete-btn" data-rule-id="${escHtml(r.id)}" title="Delete this rule">Delete</button>
      </div>`;
    }).join('');

    // Wire delete buttons
    list.querySelectorAll('.tuning-delete-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.ruleId;
        if (!confirm('Delete this silence rule? Alerts already suppressed will stay suppressed.')) return;
        try {
          const res = await fetch(`/api/silence-rules/${id}`, { method: 'DELETE' });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          toast('Rule deleted', 'success');
          loadTuningRules();
        } catch (err) {
          toast(`Delete failed: ${err.message}`, 'error');
        }
      });
    });
  } catch (err) {
    list.innerHTML = `<div class="empty-state" style="padding:1rem">Failed: ${escHtml(err.message)}</div>`;
  }
}

async function addTuningRule() {
  const matchType = document.getElementById('tuning-match-type').value;
  const pattern = document.getElementById('tuning-pattern').value.trim();
  const pattern2 = document.getElementById('tuning-pattern2').value.trim();
  if (!pattern) { toast('Pattern is required', 'error'); return; }
  if (matchType === 'src_ip+title' && !pattern2) { toast('Title pattern is required for IP+Title rules', 'error'); return; }

  try {
    const body = { match_type: matchType, pattern, reason: 'Added from Tuning panel' };
    if (pattern2) body.pattern2 = pattern2;
    const res = await fetch('/api/silence-rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    toast(`Rule added. ${data.suppressed} existing alert(s) suppressed.`, 'success');
    document.getElementById('tuning-pattern').value = '';
    document.getElementById('tuning-pattern2').value = '';
    loadTuningRules();
    fetchAlerts(state.page);
    fetchStats();
  } catch (err) {
    toast(`Failed: ${err.message}`, 'error');
  }
}

// ── Detection Rules (Custom Rules) ────────────────────────────────────────

function switchTuningTab(tab) {
  const silenceTab = document.getElementById('tuning-tab-silence');
  const detectionTab = document.getElementById('tuning-tab-detection');
  const tabSilence = document.getElementById('tab-silence');
  const tabDetection = document.getElementById('tab-detection');
  if (tab === 'silence') {
    if (silenceTab) silenceTab.style.display = '';
    if (detectionTab) detectionTab.style.display = 'none';
    if (tabSilence) tabSilence.classList.add('active');
    if (tabDetection) tabDetection.classList.remove('active');
    loadTuningRules();
  } else {
    if (silenceTab) silenceTab.style.display = 'none';
    if (detectionTab) detectionTab.style.display = '';
    if (tabSilence) tabSilence.classList.remove('active');
    if (tabDetection) tabDetection.classList.add('active');
    loadDetectionRules();
  }
}

async function loadDetectionRules() {
  const list = document.getElementById('detection-rules-list');
  if (!list) return;
  try {
    const res = await fetch('/api/rules');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const rules = data.rules || [];
    if (!rules.length) {
      list.innerHTML = '<div class="empty-state" style="padding:1rem;font-size:0.85rem">No detection rules yet. Use the form above to create one.</div>';
      return;
    }
    list.innerHTML = rules.map(r => {
      const opLabel = { contains: 'contains', equals: '=', startswith: 'starts with', regex: '~', gt: '>', lt: '<' }[r.match_op] || r.match_op;
      const actionClass = { escalate: 'sev-high', investigate: 'sev-medium', suppress: 'sev-low' }[r.action] || '';
      const sevBadge = r.severity_override ? `<span class="sev-pill sev-${r.severity_override}">${r.severity_override}</span>` : '';
      const hits = r.hit_count ? `<span class="tuning-hits">${r.hit_count} hits</span>` : '';
      const lastHit = r.last_hit ? `<span class="tuning-last-hit">last: ${fmtRelative(r.last_hit)}</span>` : '';
      const enabled = r.enabled ? '' : ' style="opacity:0.5"';
      const cond2 = (r.match_field2 && r.match_value2)
        ? `<span class="det-cond2"> AND ${r.match_field2} ${r.match_op2 || 'contains'} "${escHtml(r.match_value2)}"</span>`
        : '';
      return `<div class="tuning-rule"${enabled} data-rule-id="${escHtml(r.id)}">
        <div class="tuning-rule-info">
          <span class="tuning-rule-pattern"><strong>${escHtml(r.name)}</strong></span>
          <span class="det-condition">${r.match_field} ${opLabel} "${escHtml(r.match_value)}"${cond2}</span>
          <span class="tuning-rule-meta">
            <span class="sev-pill ${actionClass}" style="font-size:0.7rem">${r.action}</span>
            ${sevBadge} ${hits} ${lastHit} created ${fmtRelative(r.created_at)}
          </span>
        </div>
        <div style="display:flex;gap:0.25rem;align-items:center">
          <button class="btn det-toggle-btn" data-rule-id="${escHtml(r.id)}" data-enabled="${r.enabled}">${r.enabled ? 'Disable' : 'Enable'}</button>
          <button class="btn tuning-delete-btn det-delete-btn" data-rule-id="${escHtml(r.id)}">Delete</button>
        </div>
      </div>`;
    }).join('');

    // Wire toggle buttons
    list.querySelectorAll('.det-toggle-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.ruleId;
        const newEnabled = btn.dataset.enabled === '1' ? 0 : 1;
        try {
          const res = await fetch(`/api/rules/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: newEnabled }),
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          toast(newEnabled ? 'Rule enabled' : 'Rule disabled', 'success');
          loadDetectionRules();
        } catch (err) { toast(`Failed: ${err.message}`, 'error'); }
      });
    });

    // Wire delete buttons
    list.querySelectorAll('.det-delete-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.ruleId;
        if (!confirm('Delete this detection rule?')) return;
        try {
          const res = await fetch(`/api/rules/${id}`, { method: 'DELETE' });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          toast('Rule deleted', 'success');
          loadDetectionRules();
        } catch (err) { toast(`Delete failed: ${err.message}`, 'error'); }
      });
    });
  } catch (err) {
    list.innerHTML = `<div class="empty-state" style="padding:1rem">Failed: ${escHtml(err.message)}</div>`;
  }
}

async function addDetectionRule() {
  const name = document.getElementById('det-name').value.trim();
  const matchField = document.getElementById('det-field').value;
  const matchOp = document.getElementById('det-op').value;
  const matchValue = document.getElementById('det-value').value.trim();
  const action = document.getElementById('det-action').value;
  const sevOverride = document.getElementById('det-severity').value;

  if (!name) { toast('Rule name is required', 'error'); return; }
  if (!matchValue) { toast('Match value is required', 'error'); return; }

  try {
    const res = await fetch('/api/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name, match_field: matchField, match_op: matchOp,
        match_value: matchValue, action, severity_override: sevOverride,
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    toast('Detection rule created', 'success');
    document.getElementById('det-name').value = '';
    document.getElementById('det-value').value = '';
    loadDetectionRules();
  } catch (err) {
    toast(`Failed: ${err.message}`, 'error');
  }
}

async function testDetectionRule() {
  const matchField = document.getElementById('det-field').value;
  const matchOp = document.getElementById('det-op').value;
  const matchValue = document.getElementById('det-value').value.trim();
  const resultDiv = document.getElementById('det-test-result');

  if (!matchValue) { toast('Enter a value to test', 'error'); return; }
  resultDiv.style.display = 'block';
  resultDiv.textContent = 'Testing against last 500 alerts...';

  try {
    const res = await fetch('/api/rules/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ match_field: matchField, match_op: matchOp, match_value: matchValue }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    resultDiv.innerHTML = `<strong>${data.matched}</strong> of ${data.tested} recent alerts match. ` +
      (data.samples.length ? `Samples: ${data.samples.slice(0, 3).map(s => `"${escHtml(s.title || '')}"`).join(', ')}` : '');
    resultDiv.style.color = data.matched > 0 ? 'var(--accent)' : 'var(--text-muted)';
  } catch (err) {
    resultDiv.textContent = `Test failed: ${err.message}`;
    resultDiv.style.color = 'var(--danger)';
  }
}

// ── Acknowledge ───────────────────────────────────────────────────────────

function wireAckButton(card) {
  const btn = card.querySelector('.ack-btn');
  if (!btn) return;
  btn.addEventListener('click', async e => {
    e.stopPropagation();
    const alertId = btn.dataset.alertId;
    btn.disabled = true;
    try {
      const res = await fetch(`/api/alerts/${alertId}/acknowledge`, {
        method: 'PATCH',
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data.acknowledged) {
        btn.classList.add('acked');
        btn.textContent = "Ack'd";
        btn.title = 'Unacknowledge';
      } else {
        btn.classList.remove('acked');
        btn.textContent = 'Ack';
        btn.title = 'Acknowledge';
      }
    } catch (err) {
      toast(`Acknowledge failed: ${err.message}`, 'error');
    } finally {
      btn.disabled = false;
    }
  });
}

// ── Notes ─────────────────────────────────────────────────────────────────

function wireNotesInput(card) {
  const section = card.querySelector('.notes-section');
  if (!section) return;
  const input = section.querySelector('.notes-input');
  const btn = section.querySelector('.notes-add-btn');
  const alertId = section.dataset.alertId;

  const submit = async () => {
    const note = input.value.trim();
    if (!note) return;
    btn.disabled = true;
    try {
      const res = await fetch(`/api/alerts/${alertId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      input.value = '';
      loadNotes(card);
    } catch (err) {
      toast(`Add note failed: ${err.message}`, 'error');
    } finally {
      btn.disabled = false;
    }
  };

  btn.addEventListener('click', e => { e.stopPropagation(); submit(); });
  input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.stopPropagation(); submit(); } });
  input.addEventListener('click', e => e.stopPropagation());
}

async function loadNotes(card) {
  const section = card.querySelector('.notes-section');
  if (!section) return;
  const alertId = section.dataset.alertId;
  const listEl = section.querySelector('.notes-list');
  try {
    const res = await fetch(`/api/alerts/${alertId}/notes`);
    if (!res.ok) return;
    const data = await res.json();
    const notes = data.notes || [];
    if (!notes.length) {
      listEl.innerHTML = '<div class="notes-empty">No notes yet</div>';
      return;
    }
    listEl.innerHTML = notes.map(n =>
      `<div class="note-item"><span class="note-time">${fmtRelative(n.created_at)}</span> ${escHtml(n.note)}</div>`
    ).join('');
  } catch { /* ignore */ }
}

// ── Timeline ──────────────────────────────────────────────────────────────

async function fetchTimeline() {
  try {
    const res = await fetch('/api/dashboard/timeline?since=24h');
    if (!res.ok) return;
    const data = await res.json();
    renderTimeline(data.timeline || []);
  } catch (err) {
    console.error('fetchTimeline error:', err);
  }
}

function renderTimeline(buckets) {
  if (!dom.timelineChart) return;
  if (!buckets.length) {
    dom.timelineChart.innerHTML = '<div class="empty-state" style="padding:0.5rem">No data in last 24h</div>';
    return;
  }
  const maxCnt = Math.max(...buckets.map(b => b.cnt), 1);
  const barWidth = Math.max(Math.floor(100 / buckets.length), 2);

  dom.timelineChart.innerHTML = `
    <div class="timeline-bars">
      ${buckets.map(b => {
        const h = Math.max(Math.round((b.cnt / maxCnt) * 100), 2);
        const critH = b.critical ? Math.max(Math.round((b.critical / maxCnt) * 100), 1) : 0;
        const highH = b.high ? Math.max(Math.round((b.high / maxCnt) * 100), 1) : 0;
        const hour = b.bucket ? b.bucket.slice(11, 16) : '';
        return `<div class="tl-bar-wrap" title="${hour}: ${b.cnt} alerts (${b.critical || 0} crit, ${b.high || 0} high)">
          <div class="tl-bar" style="height:${h}%">
            ${critH ? `<div class="tl-bar-crit" style="height:${critH}%"></div>` : ''}
            ${highH ? `<div class="tl-bar-high" style="height:${highH}%"></div>` : ''}
          </div>
          <div class="tl-label">${hour}</div>
        </div>`;
      }).join('')}
    </div>`;
}

// ── Top Talkers ───────────────────────────────────────────────────────────

async function fetchTopTalkers() {
  try {
    const res = await fetch('/api/dashboard/top-talkers?since=24h&limit=10');
    if (!res.ok) return;
    const data = await res.json();
    renderTalkerList(dom.topSrcIps, data.src_ips || []);
    renderTalkerList(dom.topDstIps, data.dst_ips || []);
    renderSigList(dom.topSigs, data.signatures || []);
  } catch (err) {
    console.error('fetchTopTalkers error:', err);
  }
}

function renderTalkerList(container, items) {
  if (!container) return;
  if (!items.length) {
    container.innerHTML = '<div class="empty-state" style="padding:0.5rem">No data</div>';
    return;
  }
  const max = items[0]?.cnt || 1;
  container.innerHTML = items.map(item => {
    const pct = Math.round((item.cnt / max) * 100);
    const label = item.dns && item.dns !== item.ip
      ? `${item.ip} <span class="talker-dns">(${escHtml(item.dns)})</span>`
      : item.asset
        ? `${item.ip} <span class="talker-dns">(${escHtml(item.asset)})</span>`
        : escHtml(item.ip);
    return `<div class="talker-row">
      <span class="talker-ip">${label}</span>
      <div class="talker-bar-wrap"><div class="talker-bar" style="width:${pct}%"></div></div>
      <span class="talker-count">${item.cnt}</span>
    </div>`;
  }).join('');
}

function renderSigList(container, items) {
  if (!container) return;
  if (!items.length) {
    container.innerHTML = '<div class="empty-state" style="padding:0.5rem">No data</div>';
    return;
  }
  const max = items[0]?.cnt || 1;
  container.innerHTML = items.map(item => {
    const pct = Math.round((item.cnt / max) * 100);
    return `<div class="talker-row">
      <span class="talker-ip">${severityBadge(item.severity)} ${escHtml(item.title || '(untitled)')}</span>
      <span class="talker-count">${item.cnt}</span>
    </div>`;
  }).join('');
}

// ── Connections ───────────────────────────────────────────────────────────

async function fetchConnections() {
  try {
    const res = await fetch('/api/dashboard/connections?since=24h');
    if (!res.ok) return;
    const data = await res.json();
    if (dom.statConnections) {
      animateCount(dom.statConnections, data.total_unique ?? 0);
    }
  } catch (err) {
    console.error('fetchConnections error:', err);
  }
}

// ── Network Hosts ─────────────────────────────────────────────────────────

async function fetchNetworkHosts() {
  try {
    const res = await fetch('/api/network/hosts?since=7d');
    if (!res.ok) return;
    const data = await res.json();
    const hosts = data.hosts || [];
    if (!hosts.length) return;

    dom.hostsSection.style.display = 'block';
    dom.hostCount.textContent = `${hosts.length} host${hosts.length !== 1 ? 's' : ''}`;

    dom.hostsTableWrap.innerHTML = `
      <table class="hosts-table">
        <thead><tr>
          <th>IP</th><th>Hostname / Asset</th><th>Geo</th><th>Alerts</th><th>High+Crit</th><th>Last Seen</th>
        </tr></thead>
        <tbody>
          ${hosts.map(h => {
            const name = h.dns || h.asset || '';
            const highClass = h.high_alerts > 0 ? ' class="host-high"' : '';
            return `<tr>
              <td class="host-ip"><a href="#" class="host-ip-link" data-ip="${escHtml(h.ip)}">${escHtml(h.ip)}</a></td>
              <td>${escHtml(name)}</td>
              <td>${escHtml(h.geo || '')}</td>
              <td>${h.alert_count}</td>
              <td${highClass}>${h.high_alerts || 0}</td>
              <td>${fmtRelative(h.last_seen)}</td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>`;

    // Wire IP clicks to investigate that host
    dom.hostsTableWrap.querySelectorAll('.host-ip-link').forEach(link => {
      link.addEventListener('click', e => {
        e.preventDefault();
        investigateHost(link.dataset.ip);
      });
    });
  } catch (err) {
    console.error('fetchNetworkHosts error:', err);
  }
}

function investigateHost(ip) {
  // Switch to flat view filtered by this IP (as src or dst)
  state.groupedView = false;
  if (dom.btnViewToggle) dom.btnViewToggle.textContent = 'Clusters';

  // Put IP in search box and search for it
  if (dom.searchBox) dom.searchBox.value = ip;
  searchAlerts(ip);

  // Scroll to the alert feed
  const feedEl = document.getElementById('alert-feed');
  if (feedEl) feedEl.scrollIntoView({ behavior: 'smooth' });
}

// ── Vulnerabilities ───────────────────────────────────────────────────────

async function fetchVulnerabilities() {
  try {
    const res = await fetch('/api/vulnerabilities?since=30d');
    if (!res.ok) return;
    const data = await res.json();
    const vulns = data.vulnerabilities || [];
    if (!vulns.length) return;

    dom.vulnSection.style.display = 'block';
    dom.vulnCount.textContent = `${data.total_cves} CVE${data.total_cves !== 1 ? 's' : ''}`;

    dom.vulnList.innerHTML = vulns.map(v =>
      `<div class="vuln-card">
        <div class="vuln-header">
          ${severityBadge(v.severity)}
          <span class="vuln-id">${escHtml(v.cve)}</span>
          <span class="vuln-meta">${v.count} alert${v.count !== 1 ? 's' : ''} &middot; ${v.hosts.length} host${v.hosts.length !== 1 ? 's' : ''}</span>
        </div>
        <div class="vuln-desc">${escHtml(v.description || '')}</div>
        <div class="vuln-hosts">${v.hosts.map(h => `<span class="vuln-host">${escHtml(h)}</span>`).join(' ')}</div>
      </div>`
    ).join('');
  } catch (err) {
    console.error('fetchVulnerabilities error:', err);
  }
}

// ── Saved Searches ────────────────────────────────────────────────────────

async function loadSavedSearches() {
  try {
    const res = await fetch('/api/saved-searches');
    if (!res.ok) return;
    const data = await res.json();
    const sel = dom.savedSearches;
    if (!sel) return;
    // Keep first option
    sel.innerHTML = '<option value="">Saved Searches</option>';
    for (const s of (data.searches || [])) {
      const opt = document.createElement('option');
      opt.value = s.query;
      opt.textContent = s.name;
      opt.dataset.searchId = s.id;
      sel.appendChild(opt);
    }
  } catch { /* ignore */ }
}

async function saveCurrentSearch() {
  const query = dom.searchBox.value.trim();
  if (!query) { toast('Enter a search query first', 'info'); return; }
  const name = prompt('Name for this saved search:', query.slice(0, 40));
  if (!name) return;
  try {
    const res = await fetch('/api/saved-searches', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, query }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    toast('Search saved', 'success');
    loadSavedSearches();
  } catch (err) {
    toast(`Save failed: ${err.message}`, 'error');
  }
}

// ── Export ─────────────────────────────────────────────────────────────────

function exportAlerts() {
  const params = new URLSearchParams({ format: 'csv' });
  if (state.filters.source) params.set('source', state.filters.source);
  if (state.filters.severity) params.set('severity', state.filters.severity);
  if (state.filters.verdict) params.set('verdict', state.filters.verdict);
  if (state.filters.timerange) params.set('since', state.filters.timerange);
  // Include search query if in search mode
  const searchQuery = dom.searchBox ? dom.searchBox.value.trim() : '';
  if (searchQuery) params.set('q', searchQuery);
  window.open(`/api/alerts/export?${params}`, '_blank');
}

// ── Theme Toggle ──────────────────────────────────────────────────────────

const THEME_KEY = 'shallots_theme';

function initTheme() {
  const saved = localStorage.getItem(THEME_KEY) || 'dark';
  applyTheme(saved);
}

function toggleTheme() {
  const current = document.documentElement.dataset.theme || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  localStorage.setItem(THEME_KEY, next);
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  if (dom.btnTheme) {
    dom.btnTheme.textContent = theme === 'dark' ? 'Light' : 'Dark';
  }
}

// ── Keyboard Shortcuts ───────────────────────────────────────────────────

function initKeyboard() {
  document.addEventListener('keydown', e => {
    // Escape closes overlays
    if (e.key === 'Escape') {
      const setupOverlay = $('setup-overlay');
      if (setupOverlay && setupOverlay.style.display !== 'none') {
        closeSetup();
        return;
      }
      const helpOverlay = $('help-overlay');
      if (helpOverlay && helpOverlay.style.display !== 'none') {
        closeHelp();
        return;
      }
      const wikiOverlay = $('wiki-overlay');
      if (wikiOverlay && wikiOverlay.style.display !== 'none') {
        closeWiki();
        return;
      }
      return;
    }

    // Ignore when typing in inputs
    const tag = e.target.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
    if (e.ctrlKey || e.altKey || e.metaKey) return;

    const cards = dom.alertList.querySelectorAll('.alert-card');
    if (!cards.length && e.key !== '/' && e.key !== '?') return;

    switch (e.key) {
      case 'j': // next
        e.preventDefault();
        state.focusedCard = Math.min(state.focusedCard + 1, cards.length - 1);
        focusCard(cards, state.focusedCard);
        break;
      case 'k': // prev
        e.preventDefault();
        state.focusedCard = Math.max(state.focusedCard - 1, 0);
        focusCard(cards, state.focusedCard);
        break;
      case 'e':
      case 'Enter':
        e.preventDefault();
        if (state.focusedCard >= 0 && state.focusedCard < cards.length) {
          const card = cards[state.focusedCard];
          card.classList.toggle('expanded');
          if (card.classList.contains('expanded') && !card.dataset.repLoaded) {
            card.dataset.repLoaded = '1';
            enrichCardReputation(card);
            loadNotes(card);
            loadAlertContext(card);
          }
        }
        break;
      case 's':
        e.preventDefault();
        setFocusedVerdict(cards, 'suppress');
        break;
      case 'i':
        e.preventDefault();
        setFocusedVerdict(cards, 'investigate');
        break;
      case 'x':
        e.preventDefault();
        setFocusedVerdict(cards, 'escalate');
        break;
      case 'a':
        e.preventDefault();
        if (state.focusedCard >= 0 && state.focusedCard < cards.length) {
          const ackBtn = cards[state.focusedCard].querySelector('.ack-btn');
          if (ackBtn) ackBtn.click();
        }
        break;
      case '/':
        e.preventDefault();
        dom.searchBox.focus();
        break;
      case '?':
        e.preventDefault();
        toggleKbdHelp();
        break;
    }
  });
}

function focusCard(cards, idx) {
  cards.forEach(c => c.classList.remove('kbd-focus'));
  if (idx >= 0 && idx < cards.length) {
    cards[idx].classList.add('kbd-focus');
    cards[idx].scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
}

function setFocusedVerdict(cards, verdict) {
  if (state.focusedCard < 0 || state.focusedCard >= cards.length) return;
  const btn = cards[state.focusedCard].querySelector(`.verdict-btn[data-verdict="${verdict}"]`);
  if (btn) btn.click();
}

function toggleKbdHelp() {
  if (!dom.kbdOverlay) return;
  const visible = dom.kbdOverlay.style.display !== 'none';
  dom.kbdOverlay.style.display = visible ? 'none' : 'block';
}

// ── Smart Empty States ────────────────────────────────────────────────────

function smartEmptyState(context) {
  const states = {
    'no-alerts': {
      icon: '&#x1F6E1;',
      title: 'All clear',
      desc: 'No events to show. Your sensors are monitoring the network - alerts will appear here when something is detected. This is a good thing.',
    },
    'no-filter-results': {
      icon: '&#x2714;',
      title: 'Nothing here',
      desc: 'No alerts match these filters. That usually means things are looking good. Try "All Verdicts" to see cleared noise too.',
    },
    'no-search-results': {
      icon: '🔎',
      title: 'No search results',
      desc: 'No matches found. Search checks titles, descriptions, and categories. Try the AI query bar for natural language questions.',
    },
    'no-correlations': {
      icon: '🧩',
      title: 'No patterns detected',
      desc: 'The AI correlator runs every 5 minutes looking for related alerts across sources. Patterns will appear here when found.',
    },
  };
  const s = states[context] || states['no-alerts'];
  return `<div class="empty-state-smart">
    <div class="empty-icon">${s.icon}</div>
    <div class="empty-title">${s.title}</div>
    <div class="empty-desc">${s.desc}</div>
  </div>`;
}

// ── Recent Alerts Summary Strip ───────────────────────────────────────────

async function fetchRecentAlerts() {
  try {
    const res = await fetch('/api/alerts?limit=10&verdict=!suppress', { headers: authHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    const alerts = data.alerts || [];
    const container = $('recent-alerts-list');
    if (!container) return;

    if (alerts.length === 0) {
      container.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.8rem">No recent alerts</div>';
      return;
    }

    container.innerHTML = alerts.map(a => {
      const rel = fmtRelative(a.timestamp || a.ingested_at);
      return `<div class="recent-alert-row" data-id="${escHtml(a.id)}">
        ${severityBadge(a.severity)}
        ${sourceBadge(a.source)}
        <span class="recent-alert-title">${escHtml(a.title || '(no title)')}</span>
        <span class="recent-alert-time">${rel}</span>
      </div>`;
    }).join('');

    container.querySelectorAll('.recent-alert-row').forEach(row => {
      row.addEventListener('click', () => {
        const anchor = $('alert-feed-anchor');
        if (anchor) anchor.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    });
  } catch (e) {
    // silent
  }
}

// ── Agent Health ──────────────────────────────────────────────────────────

async function fetchAgents() {
  try {
    const res = await fetch('/api/agents', { headers: authHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    const agents = data.agents || [];

    // Summary counts
    const online = agents.filter(a => a.status === 'online').length;
    const degraded = agents.filter(a => a.status === 'degraded').length;
    const offline = agents.filter(a => a.status === 'offline').length;
    const total = agents.length;

    // Update header pill
    if (dom.agentPillDot && dom.agentPillLabel) {
      if (total === 0) {
        dom.agentPillDot.className = 'agent-pill-dot';
        dom.agentPillLabel.textContent = 'No agents';
      } else if (offline > 0) {
        dom.agentPillDot.className = 'agent-pill-dot red';
        dom.agentPillLabel.textContent = `${offline} OFFLINE`;
      } else if (degraded > 0) {
        dom.agentPillDot.className = 'agent-pill-dot amber';
        dom.agentPillLabel.textContent = `${online} online, ${degraded} degraded`;
      } else {
        dom.agentPillDot.className = 'agent-pill-dot green';
        dom.agentPillLabel.textContent = `${online}/${total} online`;
      }
    }

    if (agents.length === 0) {
      // Show deploy prompt (Phase 2c)
      if (dom.agentsSection) dom.agentsSection.style.display = '';
      if (dom.agentsGrid) dom.agentsGrid.style.display = 'none';
      const prompt = $('agents-deploy-prompt');
      if (prompt) prompt.style.display = '';
      return;
    }
    if (dom.agentsSection) dom.agentsSection.style.display = '';
    if (dom.agentsGrid) dom.agentsGrid.style.display = '';
    const deployPrompt = $('agents-deploy-prompt');
    if (deployPrompt) deployPrompt.style.display = 'none';

    // Summary text
    const parts = [];
    if (online) parts.push(`${online} online`);
    if (degraded) parts.push(`${degraded} degraded`);
    if (offline) parts.push(`${offline} offline`);
    if (dom.agentSummary) dom.agentSummary.textContent = parts.join(', ');

    // Render cards
    if (dom.agentsGrid) {
      dom.agentsGrid.innerHTML = agents.map(a => renderAgentCard(a)).join('');
      // Wire expandable drawers: troubleshoot for offline, detail panel for Argus
      dom.agentsGrid.querySelectorAll('.agent-card[data-expandable="true"]').forEach(card => {
        card.style.cursor = 'pointer';
        card.addEventListener('click', () => {
          const detail = card.querySelector('.argus-detail-panel');
          const drawer = card.querySelector('.agent-troubleshoot');
          if (detail) detail.classList.toggle('open');
          if (drawer) drawer.classList.toggle('open');
        });
      });
    }
  } catch (e) {
    // silent
  }
}

// ── Argus-specific rendering ─────────────────────────────────────────────

const ALL_ARGUS_MONITORS = [
  'windows_events', 'process', 'file_sentinel',
  'persistence', 'anti_tamper', 'session', 'defender_health',
  'usb', 'dns', 'registry', 'service',
  'audit_policy', 'firewall', 'posture',
  'browser_extensions', 'wmi_subs', 'ads',
];

const ARGUS_MONITOR_LABELS = {
  windows_events: 'Windows Events',
  process: 'Process',
  file_sentinel: 'File Sentinel',
  persistence: 'Persistence',
  anti_tamper: 'Anti-Tamper',
  usb: 'USB Devices',
  dns: 'DNS/Network',
  registry: 'Registry',
  service: 'Services',
  audit_policy: 'Audit Policy',
  firewall: 'Firewall',
  posture: 'Security Posture',
  browser_extensions: 'Browser Extensions',
  wmi_subs: 'WMI Subscriptions',
  ads: 'NTFS ADS',
  session: 'Session',
  defender_health: 'Defender Health',
};

function renderArgusStateBadge(argusState) {
  const s = (argusState || 'DISARMED').toUpperCase();
  const labels = {
    ARMED_HOME: 'Armed Home',
    ARMED_AWAY: 'Armed Away',
    LOCKDOWN: 'Lockdown',
    DISARMED: 'Disarmed',
  };
  const cls = {
    ARMED_HOME: 'badge-argus-armed-home',
    ARMED_AWAY: 'badge-argus-armed-away',
    LOCKDOWN: 'badge-argus-lockdown',
    DISARMED: 'badge-argus-disarmed',
  };
  return `<span class="badge ${cls[s] || 'badge-argus-disarmed'}">${labels[s] || s}</span>`;
}

function renderArgusMonitors(monitors) {
  if (!monitors || !monitors.length) return '';
  const tags = monitors.map(m =>
    `<span class="argus-monitor-tag">${esc(ARGUS_MONITOR_LABELS[m] || m)}</span>`
  ).join('');
  return `<div class="argus-monitors"><span class="argus-monitors-label">Monitors:</span>${tags}</div>`;
}

function buildArgusDetailPanel(a) {
  const health = a.health_data || {};
  const argusState = health.state || 'DISARMED';
  const activeMonitors = health.active_monitors || [];
  const activeSet = new Set(activeMonitors);

  const stateDescs = {
    ARMED_HOME: 'Monitoring with home-mode sensitivity. Auto-escalates to ARMED_AWAY on inactivity.',
    ARMED_AWAY: 'Elevated monitoring - user is away. All monitors at full sensitivity.',
    LOCKDOWN: 'Threat detected. Workstation locked, evidence captured, SMS sent.',
    DISARMED: 'Monitoring is off. No active protection.',
  };

  // TimeLock info (from heartbeat details)
  let timelockHtml = '';
  if (health.timelock_active) {
    const rem = health.timelock_remaining_seconds || 0;
    const mins = Math.floor(rem / 60);
    const secs = rem % 60;
    timelockHtml = `<div class="timelock-banner">
      <strong>TIMELOCK ACTIVE</strong> - System isolated.
      Network disabled. ${mins}m ${secs}s remaining.
      ${health.timelock_expires_utc ? `<br>Expires: ${new Date(health.timelock_expires_utc).toLocaleTimeString()}` : ''}
    </div>`;
  }

  const rows = ALL_ARGUS_MONITORS.map(m => {
    const active = activeSet.has(m);
    const icon = active
      ? '<span style="color:var(--sev-low)">&#10003;</span>'
      : '<span style="color:var(--text-muted)">&mdash;</span>';
    return `<tr><td>${esc(ARGUS_MONITOR_LABELS[m] || m)}</td><td style="text-align:center">${icon}</td></tr>`;
  }).join('');

  return `<div class="argus-detail-panel">
    ${timelockHtml}
    <div class="argus-detail-state">
      ${renderArgusStateBadge(argusState)}
      <span class="argus-detail-desc">${stateDescs[argusState.toUpperCase()] || ''}</span>
    </div>
    <table class="argus-monitor-table">
      <tr><th>Monitor</th><th style="text-align:center">Active</th></tr>
      ${rows}
    </table>
  </div>`;
}

function renderAgentCard(a) {
  const statusClass = a.status === 'online' ? 'agent-online' :
                      a.status === 'degraded' ? 'agent-degraded' : 'agent-offline';
  const dotClass = a.status === 'degraded' ? 'agent-dot pulse' : 'agent-dot';
  const lastSeen = a.last_heartbeat ? timeAgo(new Date(a.last_heartbeat)) : 'never';
  const health = a.health_data || {};
  const isArgus = (a.agent_type || '').toLowerCase() === 'argus';

  let healthMetrics = '';
  if (health.cpu !== undefined || health.memory !== undefined || health.disk !== undefined) {
    const parts = [];
    if (health.cpu !== undefined) parts.push(`CPU ${health.cpu}%`);
    if (health.memory !== undefined) parts.push(`RAM ${health.memory}%`);
    if (health.disk !== undefined) parts.push(`Disk ${health.disk}%`);
    healthMetrics = `<div class="agent-metrics">${parts.join(' · ')}</div>`;
  }

  let services = '';
  if (health.services && Object.keys(health.services).length > 0) {
    const svcHtml = Object.entries(health.services).map(([name, st]) => {
      const color = st === 'active' ? 'var(--sev-low)' : 'var(--sev-critical)';
      return `<span style="color:${color}">${name}: ${st}</span>`;
    }).join(' · ');
    services = `<div class="agent-services">${svcHtml}</div>`;
  }

  // Argus state badge in header
  const argusStateBadge = isArgus && health.state
    ? renderArgusStateBadge(health.state) : '';

  // Argus monitors section
  const argusMonitors = isArgus
    ? renderArgusMonitors(health.active_monitors) : '';

  // Argus detail panel (expandable) or troubleshoot drawer
  const detailPanel = isArgus ? buildArgusDetailPanel(a) : '';
  const troubleshoot = a.status !== 'online' ? buildAgentTroubleshoot(a) : '';

  return `<div class="agent-card ${statusClass}${isArgus ? ' agent-argus' : ''}" data-expandable="${isArgus || a.status !== 'online'}">
    <div class="agent-header">
      <div class="${dotClass}"></div>
      <span class="agent-name">${esc(a.agent_name)}</span>
      <span class="badge badge-agent-type">${esc(a.agent_type)}</span>
      ${a.os ? `<span class="badge badge-agent-os">${esc(a.os)}</span>` : ''}
      ${argusStateBadge}
    </div>
    <div class="agent-details">
      ${a.ip ? `<span class="agent-ip">${esc(a.ip)}</span>` : ''}
      <span class="agent-lastseen">Last seen: ${lastSeen}</span>
      ${a.alert_count ? `<span class="agent-alerts">${a.alert_count} alert${a.alert_count !== 1 ? 's' : ''}</span>` : ''}
    </div>
    ${healthMetrics}
    ${services}
    ${argusMonitors}
    ${detailPanel}
    ${troubleshoot}
  </div>`;
}

function buildAgentTroubleshoot(a) {
  const type = (a.agent_type || '').toLowerCase();
  const os = (a.os || '').toLowerCase();
  const cmds = [];

  if (type === 'argus' || os.includes('windows')) {
    cmds.push({
      label: 'Check Argus status',
      cmd: 'python -m argus --config config.toml status',
    });
    cmds.push({
      label: 'Restart Argus',
      cmd: 'python -m argus --config config.toml on',
    });
    cmds.push({
      label: 'Reinstall via clove.ps1 (PowerShell as Admin)',
      cmd: `.\\clove.ps1 -Manager ${location.hostname || 'SERVER_IP'}`,
    });
  }

  if (type === 'wazuh' || type === 'clove') {
    if (os.includes('linux') || !os.includes('windows')) {
      cmds.push({
        label: 'Check Wazuh agent status',
        cmd: 'systemctl status wazuh-agent',
      });
      cmds.push({
        label: 'Restart Wazuh agent',
        cmd: 'sudo systemctl restart wazuh-agent',
      });
      cmds.push({
        label: 'Re-enroll (idempotent)',
        cmd: `curl -fsSL https://github.com/benolenick/security-shallots/raw/main/setup/endpoint/clove | sudo bash -s -- --manager ${location.hostname || 'SERVER_IP'}`,
      });
    } else {
      cmds.push({
        label: 'Check Wazuh agent (Windows)',
        cmd: 'Get-Service WazuhSvc | Select Status',
      });
      cmds.push({
        label: 'Restart Wazuh agent (Windows)',
        cmd: 'Restart-Service WazuhSvc',
      });
    }
  }

  if (cmds.length === 0) {
    cmds.push({
      label: 'Check agent connectivity',
      cmd: `ping ${a.ip || 'AGENT_IP'}`,
    });
  }

  const cmdHtml = cmds.map(c =>
    `<div class="agent-troubleshoot-item">
      <div class="agent-troubleshoot-label">${esc(c.label)}</div>
      <div class="agent-troubleshoot-cmd">
        <code>${esc(c.cmd)}</code>
        <button class="copy-btn" onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent)" title="Copy">&#x29C9;</button>
      </div>
    </div>`
  ).join('');

  return `<div class="agent-troubleshoot">
    <div class="agent-troubleshoot-header">Troubleshoot</div>
    ${cmdHtml}
  </div>`;
}

// ── Test Detection Pipeline ──────────────────────────────────────────────

async function runTestDetection() {
  const btn = document.getElementById('btn-test-detection');
  if (!btn) return;
  const origText = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Testing...';
  btn.style.opacity = '0.6';

  try {
    const resp = await fetch('/api/test-detection', { method: 'POST', headers: authHeaders() });
    const data = await resp.json();

    // Build results overlay
    const stageIcons = { pass: '\u2705', fail: '\u274C', warn: '\u26A0\uFE0F' };
    const stageLabels = {
      ingest: 'Alert Ingestion',
      storage: 'Database Storage',
      search: 'Full-Text Search',
      websocket: 'WebSocket Broadcast',
      agents: 'Agent Connectivity',
      data_sources: 'Data Source Freshness',
    };

    let html = `<div style="padding:1.5rem;max-width:500px">`;
    html += `<h3 style="margin:0 0 1rem">Detection Pipeline Test</h3>`;

    const overallColor = data.overall === 'pass' ? 'var(--sev-low)' : data.overall === 'fail' ? 'var(--sev-critical)' : 'var(--sev-medium)';
    html += `<div style="padding:0.5rem 1rem;border-radius:6px;background:${overallColor}22;border:1px solid ${overallColor};margin-bottom:1rem;font-weight:600;color:${overallColor}">`;
    html += `Overall: ${data.overall === 'pass' ? 'ALL SYSTEMS GO' : data.overall === 'fail' ? 'PIPELINE FAILURE' : 'PARTIAL - CHECK WARNINGS'}</div>`;

    for (const [key, stage] of Object.entries(data.stages || {})) {
      const icon = stageIcons[stage.status] || '\u2753';
      const label = stageLabels[key] || key;
      html += `<div style="display:flex;align-items:flex-start;gap:0.5rem;margin-bottom:0.5rem;padding:0.4rem 0;border-bottom:1px solid var(--border)">`;
      html += `<span style="font-size:1.1em">${icon}</span>`;
      html += `<div><strong>${label}</strong>`;
      if (stage.detail) html += `<div style="font-size:0.8em;color:var(--text-muted)">${esc(stage.detail)}</div>`;
      if (stage.error) html += `<div style="font-size:0.8em;color:var(--sev-critical)">${esc(stage.error)}</div>`;
      if (stage.active_agents) html += `<div style="font-size:0.8em;color:var(--text-muted)">Agents: ${stage.active_agents.map(a => esc(a)).join(', ') || 'none'}</div>`;
      if (stage.active_sources) {
        const srcList = Object.entries(stage.active_sources).map(([s, d]) => `${s}: ${d.count_24h} alerts`).join(', ');
        html += `<div style="font-size:0.8em;color:var(--text-muted)">${srcList}</div>`;
      }
      html += `</div></div>`;
    }

    if (data.cleanup) html += `<div style="font-size:0.75em;color:var(--text-muted);margin-top:0.75rem">${esc(data.cleanup)}</div>`;
    html += `<button class="btn btn-primary" onclick="this.closest('.modal-overlay').remove()" style="margin-top:1rem;width:100%">Close</button>`;
    html += `</div>`;

    // Show as modal overlay
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:9999';
    overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
    const modal = document.createElement('div');
    modal.style.cssText = 'background:var(--bg-panel);border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.4);max-height:80vh;overflow-y:auto';
    modal.innerHTML = html;
    overlay.appendChild(modal);
    document.body.appendChild(overlay);

  } catch (err) {
    alert('Test failed: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = origText;
    btn.style.opacity = '1';
  }
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function timeAgo(date) {
  const seconds = Math.floor((new Date() - date) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// ── AI Investigation Console ──────────────────────────────────────────────

function wireAiButtons(card) {
  card.querySelectorAll('.ai-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const alertId = btn.dataset.alertId;
      const action = btn.dataset.action;
      aiConsult(alertId, action, btn, card);
    });
  });
  // Chat send
  const chatSend = card.querySelector('.ai-chat-send');
  if (chatSend) {
    const input = card.querySelector('.ai-chat-input');
    chatSend.addEventListener('click', e => {
      e.stopPropagation();
      const msg = input.value.trim();
      if (msg) {
        input.value = '';
        aiConsult(chatSend.dataset.alertId, 'chat', null, card, msg);
      }
    });
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.stopPropagation();
        const msg = input.value.trim();
        if (msg) {
          input.value = '';
          aiConsult(input.dataset.alertId, 'chat', null, card, msg);
        }
      }
    });
  }
}

async function aiConsult(alertId, action, btn, card, message = '') {
  const responseSlot = card.querySelector(`.ai-response-slot[data-alert-id="${alertId}"]`);
  const chatPanel = card.querySelector(`.ai-chat-panel[data-alert-id="${alertId}"]`);
  const chatHistory = card.querySelector(`.ai-chat-history[data-alert-id="${alertId}"]`);

  // Show loading on button
  if (btn) {
    btn.classList.add('loading');
    btn.disabled = true;
  }

  // For chat action, show user message immediately
  if (action === 'chat' && message && chatHistory) {
    chatHistory.innerHTML += `<div class="ai-chat-msg user">${escHtml(message)}</div>`;
    chatHistory.scrollTop = chatHistory.scrollHeight;
  }

  // Show response area with typing indicator
  const actionLabels = { explain: 'Explanation', remediate: 'Remediation', hunt: 'Threat Hunt', chat: 'Response' };

  if (action !== 'chat') {
    responseSlot.innerHTML = `
      <div class="ai-response-label">${actionLabels[action] || 'AI Response'}</div>
      <div class="ai-response">
        <div class="ai-typing"><span>.</span><span>.</span><span>.</span></div>
      </div>`;
  }

  try {
    const url = `/api/alerts/${alertId}/ai/${action}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'text/event-stream' },
      body: JSON.stringify({ message }),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(err || `HTTP ${res.status}`);
    }

    const contentType = res.headers.get('Content-Type') || '';

    if (contentType.includes('text/event-stream')) {
      // SSE streaming
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let fullText = '';
      let buffer = '';

      const responseEl = action !== 'chat'
        ? responseSlot.querySelector('.ai-response')
        : null;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const data = JSON.parse(line.slice(6));
            if (data.done) break;
            if (data.token) {
              fullText += data.token;
              if (responseEl) {
                responseEl.innerHTML = renderAiMarkdown(fullText);
                responseEl.scrollTop = responseEl.scrollHeight;
              }
            }
          } catch { /* skip malformed SSE lines */ }
        }
      }

      // For chat, add assistant message to chat history
      if (action === 'chat' && chatHistory && fullText) {
        chatHistory.innerHTML += `<div class="ai-chat-msg assistant">${renderAiMarkdown(fullText)}</div>`;
        chatHistory.scrollTop = chatHistory.scrollHeight;
      }
    } else {
      // JSON response (non-streaming)
      const data = await res.json();
      const text = data.response || '(no response)';

      if (action !== 'chat') {
        responseSlot.innerHTML = `
          <div class="ai-response-label">${actionLabels[action] || 'AI Response'}</div>
          <div class="ai-response">${renderAiMarkdown(text)}</div>`;
      } else if (chatHistory) {
        chatHistory.innerHTML += `<div class="ai-chat-msg assistant">${renderAiMarkdown(text)}</div>`;
        chatHistory.scrollTop = chatHistory.scrollHeight;
      }
    }

    // Show chat panel after first AI interaction
    if (chatPanel) chatPanel.style.display = 'block';

    // Load chat history on first interaction
    if (!card.dataset.chatLoaded) {
      card.dataset.chatLoaded = '1';
      loadChatHistory(alertId, chatHistory);
    }

  } catch (err) {
    const errMsg = `AI request failed: ${err.message}`;
    if (action !== 'chat') {
      responseSlot.innerHTML = `
        <div class="ai-response-label">${actionLabels[action] || 'AI Response'}</div>
        <div class="ai-response" style="color:var(--sev-critical)">${escHtml(errMsg)}</div>`;
    } else if (chatHistory) {
      chatHistory.innerHTML += `<div class="ai-chat-msg assistant" style="color:var(--sev-critical)">${escHtml(errMsg)}</div>`;
    }
    toast(errMsg, 'error');
  } finally {
    if (btn) {
      btn.classList.remove('loading');
      btn.disabled = false;
    }
  }
}

async function loadChatHistory(alertId, chatHistoryEl) {
  if (!chatHistoryEl) return;
  try {
    const res = await fetch(`/api/alerts/${alertId}/chat`);
    if (!res.ok) return;
    const data = await res.json();
    const messages = data.messages || [];
    if (messages.length === 0) return;
    // Render existing messages (skip if already rendered from current session)
    const existing = chatHistoryEl.querySelectorAll('.ai-chat-msg').length;
    if (existing > 0) return; // already have messages from this session
    chatHistoryEl.innerHTML = messages.map(m =>
      `<div class="ai-chat-msg ${m.role}">${m.role === 'user' ? escHtml(m.content) : renderAiMarkdown(m.content)}</div>`
    ).join('');
    chatHistoryEl.scrollTop = chatHistoryEl.scrollHeight;
  } catch { /* silent */ }
}

function renderAiMarkdown(text) {
  if (!text) return '';
  let html = escHtml(text);

  // Code blocks (``` ... ```)
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) =>
    `<pre><code>${code.trim()}</code></pre>`
  );

  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

  // Bold
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

  // Italic
  html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');

  // Headers
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');

  // Numbered lists
  html = html.replace(/^(\d+)\. (.+)$/gm, '<li>$2</li>');

  // Bullet points
  html = html.replace(/^[-*] (.+)$/gm, '<li>$1</li>');

  // Wrap consecutive <li> in <ul>
  html = html.replace(/(<li>.*?<\/li>\n?)+/g, match => `<ul>${match}</ul>`);

  // Line breaks (but not inside pre/code)
  html = html.replace(/\n/g, '<br>');

  // Clean up extra <br> around block elements
  html = html.replace(/<br>\s*(<pre|<h[123]|<ul|<\/ul)/g, '$1');
  html = html.replace(/(<\/pre>|<\/h[123]>|<\/ul>)\s*<br>/g, '$1');

  return html;
}

// ── Correlation AI Analysis ──────────────────────────────────────────────────

async function analyzeCorrelation(corrId, btn) {
  if (btn.classList.contains('loading')) return;
  btn.classList.add('loading');
  btn.disabled = true;

  const responseEl = document.querySelector(`.corr-ai-response[data-corr-id="${corrId}"]`);
  if (!responseEl) { btn.classList.remove('loading'); btn.disabled = false; return; }

  responseEl.innerHTML = `
    <div class="ai-response-label">Pattern Analysis</div>
    <div class="ai-response"><span class="ai-typing"><span>.</span><span>.</span><span>.</span></span></div>`;

  try {
    const res = await fetch(`/api/correlations/${encodeURIComponent(corrId)}/ai`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'text/event-stream' },
    });

    if (res.headers.get('Content-Type')?.includes('text/event-stream')) {
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let fullText = '';
      const display = responseEl.querySelector('.ai-response');

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split('\n');
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const payload = line.slice(6).trim();
          if (payload === '[DONE]') break;
          try {
            const data = JSON.parse(payload);
            if (data.token) {
              fullText += data.token;
              if (display) {
                display.innerHTML = renderAiMarkdown(fullText);
                display.scrollTop = display.scrollHeight;
              }
            }
          } catch { /* skip malformed */ }
        }
      }
    } else {
      const data = await res.json();
      const text = data.response || '(no response)';
      responseEl.innerHTML = `
        <div class="ai-response-label">Pattern Analysis</div>
        <div class="ai-response">${renderAiMarkdown(text)}</div>`;
    }
  } catch (err) {
    responseEl.innerHTML = `
      <div class="ai-response-label">Pattern Analysis</div>
      <div class="ai-response" style="color:var(--sev-critical)">${escHtml('AI request failed: ' + err.message)}</div>`;
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

// ── Settings Modal ──────────────────────────────────────────────────────────

function initSettings() {
  const overlay = $('settings-overlay');
  const btnSettings = $('btn-settings');
  const btnClose = $('settings-close');
  const btnCancel = $('settings-cancel');
  const btnSave = $('settings-save');
  const btnScan = $('btn-ai-scan');

  if (!overlay || !btnSettings) return;

  btnSettings.addEventListener('click', () => {
    overlay.classList.add('visible');
    loadAiSettings();
  });

  const closeSettings = () => overlay.classList.remove('visible');
  btnClose.addEventListener('click', closeSettings);
  btnCancel.addEventListener('click', closeSettings);
  overlay.addEventListener('click', e => {
    if (e.target === overlay) closeSettings();
  });

  btnSave.addEventListener('click', saveAiSettings);
  btnScan.addEventListener('click', scanForLlms);

  // Key reveal toggles
  overlay.querySelectorAll('.settings-reveal').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = $( btn.dataset.target);
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = 'Hide';
      } else {
        input.type = 'password';
        btn.textContent = 'Show';
      }
    });
  });
}

async function loadAiSettings() {
  try {
    const res = await fetch('/api/settings/ai');
    if (!res.ok) return;
    const data = await res.json();

    $('ai-tier').value = data.tier || 'none';
    $('ai-ollama-url').value = data.ollama_url || '';

    const modelSelect = $('ai-ollama-model');
    if (data.ollama_model) {
      // Add current model as option if not in list
      let found = false;
      for (const opt of modelSelect.options) {
        if (opt.value === data.ollama_model) { found = true; break; }
      }
      if (!found) {
        const opt = document.createElement('option');
        opt.value = data.ollama_model;
        opt.textContent = data.ollama_model;
        modelSelect.appendChild(opt);
      }
      modelSelect.value = data.ollama_model;
    }
  } catch (e) {
    console.error('loadAiSettings error:', e);
  }
}

async function saveAiSettings() {
  const body = {
    tier: $('ai-tier').value,
    ollama_url: $('ai-ollama-url').value,
    ollama_model: $('ai-ollama-model').value,
  };
  const openaiKey = $('ai-openai-key').value.trim();
  const anthropicKey = $('ai-anthropic-key').value.trim();
  if (openaiKey) body.openai_api_key = openaiKey;
  if (anthropicKey) body.anthropic_api_key = anthropicKey;

  try {
    const res = await fetch('/api/settings/ai', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    toast('AI settings saved', 'success');
    $('settings-overlay').classList.remove('visible');
  } catch (e) {
    toast(`Failed to save settings: ${e.message}`, 'error');
  }
}

async function scanForLlms() {
  const container = $('llm-scan-results');
  container.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.8rem"><span class="loading-spinner"></span> Scanning...</div>';

  try {
    const res = await fetch('/api/settings/ai/scan', { method: 'POST' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const providers = data.providers || [];

    if (!providers.length) {
      container.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.8rem">No LLM providers found</div>';
      return;
    }

    const modelSelect = $('ai-ollama-model');
    const currentModel = modelSelect.value;

    container.innerHTML = providers.map(p => {
      const statusClass = p.status === 'online' ? 'online' :
                          p.status === 'configured' ? 'online' : 'offline';
      const models = (p.models || []).map(m =>
        `<span class="llm-model-tag${m === currentModel ? ' active' : ''}" data-model="${escHtml(m)}" data-url="${escHtml(p.url)}" data-type="${escHtml(p.type)}">${escHtml(m)}</span>`
      ).join('');

      return `<div class="llm-provider ${statusClass}">
        <div class="llm-provider-header">
          <span>${escHtml(p.type)} - ${escHtml(p.url)}</span>
          <span class="llm-status ${statusClass}">${escHtml(p.status)}</span>
        </div>
        ${models ? `<div class="llm-model-list">${models}</div>` : ''}
      </div>`;
    }).join('');

    // Click model tags to select them
    container.querySelectorAll('.llm-model-tag').forEach(tag => {
      tag.addEventListener('click', () => {
        // Clear other actives
        container.querySelectorAll('.llm-model-tag').forEach(t => t.classList.remove('active'));
        tag.classList.add('active');

        const model = tag.dataset.model;
        const url = tag.dataset.url;
        const type = tag.dataset.type;

        // Update form
        if (type === 'ollama') {
          $('ai-ollama-url').value = url;
          // Add model to select if not present
          let found = false;
          for (const opt of modelSelect.options) {
            if (opt.value === model) { found = true; break; }
          }
          if (!found) {
            const opt = document.createElement('option');
            opt.value = model;
            opt.textContent = model;
            modelSelect.appendChild(opt);
          }
          modelSelect.value = model;
        }
      });
    });

    // Populate model dropdown with all Ollama models
    const allOllamaModels = providers
      .filter(p => p.type === 'ollama' && p.status === 'online')
      .flatMap(p => p.models || []);

    for (const m of allOllamaModels) {
      let found = false;
      for (const opt of modelSelect.options) {
        if (opt.value === m) { found = true; break; }
      }
      if (!found) {
        const opt = document.createElement('option');
        opt.value = m;
        opt.textContent = m;
        modelSelect.appendChild(opt);
      }
    }
    if (currentModel) modelSelect.value = currentModel;

  } catch (e) {
    container.innerHTML = `<div class="empty-state" style="padding:0.5rem;font-size:0.8rem;color:var(--sev-critical)">Scan failed: ${escHtml(e.message)}</div>`;
  }
}

// ── JTTW Investigation ──────────────────────────────────────────────────────

function initJttw() {
  // Inject JTTW button after the stats grid
  const statsGrid = document.querySelector('.stats-grid');
  if (!statsGrid) return;

  const btn = document.createElement('button');
  btn.id = 'jttw-btn';
  btn.className = 'jttw-btn';
  btn.innerHTML = '&#9889; JTTW';
  btn.title = 'Jesus Take The Wheel - AI Deep Investigation';
  btn.addEventListener('click', runJttw);
  statsGrid.parentElement.insertBefore(btn, statsGrid.nextSibling);

  // Create modal overlay
  const overlay = document.createElement('div');
  overlay.id = 'jttw-overlay';
  overlay.className = 'modal-overlay jttw-overlay';
  overlay.style.display = 'none';
  overlay.innerHTML = `
    <div class="modal jttw-modal">
      <div class="modal-header">
        <div class="jttw-header-left">
          <h3>&#9889; Investigation Report</h3>
          <button class="btn btn-sm jttw-history-btn" id="jttw-history-btn" title="View past investigations">History</button>
        </div>
        <button class="modal-close" id="jttw-close">&times;</button>
      </div>
      <div class="modal-body" id="jttw-body">
        <div class="jttw-loading" id="jttw-loading">
          <div class="spinner"></div>
          <p>AI is investigating all alerts...</p>
        </div>
        <div id="jttw-report" style="display:none"></div>
        <div id="jttw-history" style="display:none"></div>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  // Close handlers: button, click-outside, ESC key
  const closeModal = () => { overlay.style.display = 'none'; };
  document.getElementById('jttw-close').addEventListener('click', closeModal);
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && overlay.style.display !== 'none') closeModal();
  });

  // Past investigations history
  document.getElementById('jttw-history-btn').addEventListener('click', loadJttwHistory);
}

async function runJttw() {
  const overlay = document.getElementById('jttw-overlay');
  const loading = document.getElementById('jttw-loading');
  const report = document.getElementById('jttw-report');
  if (!overlay) return;

  overlay.style.display = 'flex';
  loading.style.display = 'flex';
  report.style.display = 'none';

  try {
    const res = await fetch('/api/investigations/run', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({since: '24h', min_severity: 'medium', auto_verdict: false}),
    });
    const data = await res.json();
    loading.style.display = 'none';
    report.style.display = 'block';

    if (data.error) {
      report.innerHTML = `<div class="empty-state" style="color:var(--sev-critical)">${escHtml(data.error)}</div>`;
      return;
    }

    let html = `<div class="jttw-meta">
      <span>Alerts: <b>${data.alert_count || 0}</b></span>
      <span>Model: <b>${escHtml(data.model || '?')}</b></span>
      <span>Latency: <b>${data.latency_ms || 0}ms</b></span>
    </div>`;

    html += `<h4>Executive Summary</h4><p class="jttw-summary">${escHtml(data.executive_summary || 'No summary')}</p>`;

    if (data.findings && data.findings.length) {
      html += '<h4>Findings</h4>';
      for (const f of data.findings) {
        html += `<div class="jttw-finding">
          <div class="jttw-finding-title">${escHtml(f.title || 'Untitled')}
            <span class="badge sev-${f.severity || 'medium'}">${f.severity || '?'}</span>
          </div>
          <p>${escHtml(f.narrative || '')}</p>
          ${f.mitre_techniques ? `<small>MITRE: ${f.mitre_techniques.map(escHtml).join(', ')}</small>` : ''}
        </div>`;
      }
    }

    if (data.verdicts && data.verdicts.length) {
      html += `<h4>Verdicts (${data.verdicts.length})</h4><div class="jttw-verdicts">`;
      html += `<button class="btn btn-sm btn-accent" id="jttw-apply-all">Apply All Verdicts</button>`;
      html += '<table class="mini-table"><tr><th>Alert</th><th>Verdict</th><th>Reasoning</th></tr>';
      for (const v of data.verdicts) {
        html += `<tr>
          <td><code>${escHtml((v.alert_id || '').substring(0, 12))}...</code></td>
          <td><span class="badge verdict-${v.verdict}">${v.verdict}</span></td>
          <td>${escHtml((v.reasoning || '').substring(0, 80))}</td>
        </tr>`;
      }
      html += '</table></div>';
    }

    if (data.recommendations && data.recommendations.length) {
      html += '<h4>Recommendations</h4><ul>';
      for (const r of data.recommendations) {
        html += `<li>${escHtml(r)}</li>`;
      }
      html += '</ul>';
    }

    report.innerHTML = html;

    // Apply all verdicts button
    const applyBtn = document.getElementById('jttw-apply-all');
    if (applyBtn && data.verdicts) {
      applyBtn.addEventListener('click', async () => {
        applyBtn.disabled = true;
        applyBtn.textContent = 'Applying...';
        let applied = 0;
        let failed = [];
        for (const v of data.verdicts) {
          try {
            const r = await fetch(`/api/alerts/${v.alert_id}/verdict`, {
              method: 'PATCH',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({verdict: v.verdict}),
            });
            if (r.ok) applied++;
            else failed.push(v.alert_id.substring(0, 8));
          } catch (e) { failed.push(v.alert_id.substring(0, 8)); }
        }
        applyBtn.textContent = `Applied ${applied}/${data.verdicts.length}`;
        if (failed.length) toast(`${failed.length} verdict(s) failed to apply`, 'error');
        if (typeof fetchStats === 'function') fetchStats();
      });
    }

  } catch (err) {
    loading.style.display = 'none';
    report.style.display = 'block';
    report.innerHTML = `<div class="empty-state" style="color:var(--sev-critical)">Error: ${escHtml(err.message)}</div>`;
  }
}

async function loadJttwHistory() {
  const report = document.getElementById('jttw-report');
  const history = document.getElementById('jttw-history');
  const loading = document.getElementById('jttw-loading');
  if (!history) return;

  report.style.display = 'none';
  loading.style.display = 'none';
  history.style.display = 'block';
  history.innerHTML = '<div class="jttw-loading" style="display:flex"><div class="spinner"></div><p>Loading history...</p></div>';

  try {
    const res = await fetch('/api/investigations?limit=20');
    const list = await res.json();
    if (!list.length) {
      history.innerHTML = '<div class="empty-state">No past investigations found.</div>';
      return;
    }
    let html = '<h4>Past Investigations</h4><table class="mini-table"><tr><th>Date</th><th>Alerts</th><th>Model</th><th>Latency</th><th></th></tr>';
    for (const inv of list) {
      html += `<tr>
        <td>${escHtml(inv.created_at || '')}</td>
        <td>${inv.alert_count || 0}</td>
        <td>${escHtml(inv.model || '?')}</td>
        <td>${inv.latency_ms || 0}ms</td>
        <td><button class="btn btn-sm jttw-view-inv" data-inv-id="${escHtml(inv.id)}">View</button></td>
      </tr>`;
    }
    html += '</table>';
    html += '<button class="btn btn-sm" id="jttw-back-to-new" style="margin-top:0.75rem">&#9889; Run New Investigation</button>';
    history.innerHTML = html;

    // Wire view buttons
    history.querySelectorAll('.jttw-view-inv').forEach(btn => {
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        btn.textContent = '...';
        try {
          const r = await fetch(`/api/investigations/${btn.dataset.invId}`);
          const inv = await r.json();
          if (inv.report) {
            history.style.display = 'none';
            report.style.display = 'block';
            // Re-render report from stored data
            runJttwRender(inv.report, report);
          }
        } catch (e) { toast('Failed to load investigation', 'error'); }
        btn.disabled = false;
        btn.textContent = 'View';
      });
    });

    // Wire back button
    document.getElementById('jttw-back-to-new')?.addEventListener('click', () => {
      history.style.display = 'none';
      runJttw();
    });
  } catch (err) {
    history.innerHTML = `<div class="empty-state" style="color:var(--sev-critical)">Error: ${escHtml(err.message)}</div>`;
  }
}

function runJttwRender(data, reportEl) {
  let html = `<div class="jttw-meta">
    <span>Alerts: <b>${data.alert_count || 0}</b></span>
    <span>Model: <b>${escHtml(data.model || '?')}</b></span>
    <span>Latency: <b>${data.latency_ms || 0}ms</b></span>
  </div>`;
  html += `<h4>Executive Summary</h4><p class="jttw-summary">${escHtml(data.executive_summary || 'No summary')}</p>`;
  if (data.findings && data.findings.length) {
    html += '<h4>Findings</h4>';
    for (const f of data.findings) {
      html += `<div class="jttw-finding">
        <div class="jttw-finding-title">${escHtml(f.title || 'Untitled')}
          <span class="badge sev-${f.severity || 'medium'}">${f.severity || '?'}</span>
        </div>
        <p>${escHtml(f.narrative || '')}</p>
        ${f.mitre_techniques ? `<small>MITRE: ${f.mitre_techniques.map(escHtml).join(', ')}</small>` : ''}
      </div>`;
    }
  }
  if (data.verdicts && data.verdicts.length) {
    html += `<h4>Verdicts (${data.verdicts.length})</h4><div class="jttw-verdicts">`;
    html += '<table class="mini-table"><tr><th>Alert</th><th>Verdict</th><th>Reasoning</th></tr>';
    for (const v of data.verdicts) {
      html += `<tr>
        <td><code>${escHtml((v.alert_id || '').substring(0, 12))}...</code></td>
        <td><span class="badge verdict-${v.verdict}">${v.verdict}</span></td>
        <td>${escHtml((v.reasoning || '').substring(0, 80))}</td>
      </tr>`;
    }
    html += '</table></div>';
  }
  if (data.recommendations && data.recommendations.length) {
    html += '<h4>Recommendations</h4><ul>';
    for (const r of data.recommendations) html += `<li>${escHtml(r)}</li>`;
    html += '</ul>';
  }
  reportEl.innerHTML = html;
}

// ── AI Autopilot Panel ────────────────────────────────────────────────────────

let _aiAudioCtx = null;

function openAiPanel() {
  const overlay = $('ai-overlay');
  if (overlay) { overlay.style.display = 'flex'; loadAiStatus(); loadAiActivity(); loadAiSuggestions(); loadAiSquawks(); loadAiReports(); }
}

function closeAiPanel() {
  const overlay = $('ai-overlay');
  if (overlay) overlay.style.display = 'none';
}

async function loadAiStatus() {
  try {
    const res = await fetch('/api/ai/status');
    if (!res.ok) return;
    const data = await res.json();
    // Update mode radio
    const radios = document.querySelectorAll('input[name="ai-mode"]');
    radios.forEach(r => { r.checked = r.value === (data.mode || 'off'); });
    // Update stats
    const el = id => { const e = $(id); if (e) e.textContent = data[id.replace('ai-stat-', '')] || '0'; };
    if ($('ai-stat-decisions')) $('ai-stat-decisions').textContent = data.decisions_today || '0';
    if ($('ai-stat-suppressed')) $('ai-stat-suppressed').textContent = data.total_suppressed || '0';
    if ($('ai-stat-squawks')) $('ai-stat-squawks').textContent = data.active_squawks || '0';
    if ($('ai-stat-verdicts')) $('ai-stat-verdicts').textContent = data.verdicts_learned || '0';
    // Update header pill
    updateAiPill(data.mode || 'off');
    // Show/hide suggestions section
    const sugSection = $('ai-suggestions-section');
    if (sugSection) sugSection.style.display = data.mode === 'copilot' ? '' : 'none';
  } catch (e) { console.warn('AI status error:', e); }
}

function updateAiPill(mode) {
  const dot = $('ai-pill-dot');
  const label = $('ai-pill-label');
  if (dot) {
    dot.className = 'ai-pill-dot';
    if (mode === 'copilot') dot.classList.add('copilot');
    else if (mode === 'autopilot') dot.classList.add('autopilot');
  }
  if (label) {
    const labels = { 'off': 'AI Off', 'copilot': 'Copilot', 'autopilot': 'Autopilot' };
    label.textContent = labels[mode] || 'AI Off';
  }
}

async function setAiMode(mode) {
  try {
    const res = await fetch('/api/ai/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    updateAiPill(mode);
    const sugSection = $('ai-suggestions-section');
    if (sugSection) sugSection.style.display = mode === 'copilot' ? '' : 'none';
    showToast(`AI mode set to ${mode}`, 'success');
  } catch (e) { showToast('Failed to set AI mode', 'error'); }
}

async function loadAiActivity() {
  const list = $('ai-activity-list');
  if (!list) return;
  try {
    const res = await fetch('/api/ai/decisions?limit=30');
    if (!res.ok) return;
    const decisions = await res.json();
    if (!decisions.length) { list.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.85rem">No AI activity yet</div>'; return; }
    const icons = { 'suppress': '🔇', 'silence_rule': '🔕', 'escalate': '🚨', 'investigate': '🔍', 'squawk': '⚠️' };
    list.innerHTML = decisions.map(d => {
      const icon = icons[d.action] || '🤖';
      return `<div class="ai-activity-item">
        <span class="ai-activity-icon">${icon}</span>
        <span class="ai-activity-text">${escHtml(d.summary)}</span>
        <span class="ai-activity-time">${fmtRelative(d.ts)}</span>
      </div>`;
    }).join('');
  } catch (e) { console.warn('AI activity error:', e); }
}

async function loadAiSuggestions() {
  const list = $('ai-suggestions-list');
  if (!list) return;
  try {
    const res = await fetch('/api/ai/suggestions');
    if (!res.ok) return;
    const suggestions = await res.json();
    if (!suggestions.length) { list.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.85rem">No pending suggestions</div>'; return; }
    list.innerHTML = suggestions.map(s => `<div class="ai-suggestion-card" data-id="${escHtml(s.id)}">
      <div class="ai-suggestion-summary">${escHtml(s.summary)}</div>
      <div class="ai-suggestion-actions">
        <button class="btn btn-primary ai-approve-btn" data-id="${escHtml(s.id)}">Approve</button>
        <button class="btn ai-reject-btn" data-id="${escHtml(s.id)}">Reject</button>
      </div>
    </div>`).join('');
    // Wire approve/reject buttons
    list.querySelectorAll('.ai-approve-btn').forEach(btn => {
      btn.addEventListener('click', () => handleAiSuggestion(btn.dataset.id, 'approve'));
    });
    list.querySelectorAll('.ai-reject-btn').forEach(btn => {
      btn.addEventListener('click', () => handleAiSuggestion(btn.dataset.id, 'reject'));
    });
  } catch (e) { console.warn('AI suggestions error:', e); }
}

async function handleAiSuggestion(id, action) {
  try {
    const res = await fetch(`/api/ai/suggestions/${id}/${action}`, { method: 'POST' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showToast(`Suggestion ${action}d`, 'success');
    loadAiSuggestions();
    loadAiActivity();
  } catch (e) { showToast(`Failed to ${action} suggestion`, 'error'); }
}

async function loadAiSquawks() {
  const list = $('ai-squawks-list');
  if (!list) return;
  try {
    const res = await fetch('/api/ai/squawks');
    if (!res.ok) return;
    const squawks = await res.json();
    if (!squawks.length) { list.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.85rem">No threats detected</div>'; return; }
    list.innerHTML = squawks.map(s => `<div class="ai-squawk-item${s.dismissed ? ' dismissed' : ''}" data-id="${escHtml(s.id)}">
      <div class="ai-squawk-title">${escHtml(s.title)}</div>
      <div class="ai-squawk-detail">${escHtml(s.detail || '')} - ${fmtRelative(s.ts)}</div>
    </div>`).join('');
  } catch (e) { console.warn('AI squawks error:', e); }
}

async function loadAiReports() {
  const list = $('ai-reports-list');
  if (!list) return;
  try {
    const res = await fetch('/api/ai/reports');
    if (!res.ok) return;
    const reports = await res.json();
    if (!reports.length) { list.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.85rem">No reports yet</div>'; return; }
    list.innerHTML = reports.map(r => `<div class="ai-report-item" data-id="${escHtml(r.id)}">
      <div class="ai-report-period">${escHtml(r.period_start || '')} - ${escHtml(r.period_end || '')}</div>
      <div class="ai-report-summary">${escHtml((r.summary || '').substring(0, 200))}</div>
    </div>`).join('');
  } catch (e) { console.warn('AI reports error:', e); }
}

// ── Squawk Banner ─────────────────────────────────────────────────────────────

function showSquawk(data) {
  const banner = $('squawk-banner');
  const text = $('squawk-text');
  if (!banner || !text) return;
  text.textContent = data.title || 'THREAT DETECTED';
  banner.style.display = '';
  document.body.classList.add('squawk-active');
  banner._squawkId = data.id;
  banner._alertIds = data.alert_ids || '';
  playSquawkSound();
}

function dismissSquawk() {
  const banner = $('squawk-banner');
  if (!banner) return;
  const id = banner._squawkId;
  banner.style.display = 'none';
  document.body.classList.remove('squawk-active');
  if (id) {
    fetch(`/api/ai/squawks/${id}/dismiss`, { method: 'POST' }).catch(() => {});
  }
}

function playSquawkSound() {
  try {
    if (!_aiAudioCtx) _aiAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const ctx = _aiAudioCtx;
    // Play a two-tone alert beep
    for (let i = 0; i < 3; i++) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.frequency.value = i % 2 === 0 ? 880 : 660;
      gain.gain.value = 0.15;
      osc.start(ctx.currentTime + i * 0.25);
      osc.stop(ctx.currentTime + i * 0.25 + 0.2);
    }
  } catch (e) { /* Audio not available */ }
}

function initAiPanel() {
  // AI panel open/close
  const aiPill = $('ai-status-pill');
  if (aiPill) aiPill.addEventListener('click', openAiPanel);
  const aiClose = $('ai-close');
  if (aiClose) aiClose.addEventListener('click', closeAiPanel);
  const aiOverlay = $('ai-overlay');
  if (aiOverlay) aiOverlay.addEventListener('click', e => {
    if (e.target === aiOverlay) closeAiPanel();
  });

  // Mode toggle
  document.querySelectorAll('input[name="ai-mode"]').forEach(radio => {
    radio.addEventListener('change', () => setAiMode(radio.value));
  });

  // Squawk banner
  const squawkDismiss = $('squawk-dismiss');
  if (squawkDismiss) squawkDismiss.addEventListener('click', () => {
    if (confirm('Dismiss this threat alert?')) dismissSquawk();
  });
  const squawkInvestigate = $('squawk-investigate');
  if (squawkInvestigate) squawkInvestigate.addEventListener('click', () => {
    openAiPanel();
  });

  // Load initial AI status for the pill
  loadAiStatus();

  // Check for active squawks on load
  fetch('/api/ai/squawks').then(r => r.json()).then(squawks => {
    if (squawks.length) showSquawk(squawks[0]);
  }).catch(() => {});
}

// ── Incident Timeline & Notes ──────────────────────────────────────────

function switchIncidentTab(btn, tabName, incidentId) {
  const detail = btn.closest('.incident-detail');
  detail.querySelectorAll('.incident-tab').forEach(t => t.classList.remove('active'));
  detail.querySelectorAll('.incident-tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  const panel = detail.querySelector(`#tab-${tabName}-${incidentId}`);
  if (panel) panel.classList.add('active');
}

async function loadIncidentTimeline(id) {
  try {
    const res = await fetch(`/api/incidents/${id}/timeline`);
    const events = await res.json();
    const container = document.getElementById(`tab-timeline-${id}`);
    if (!container) return;

    if (!events.length) {
      container.innerHTML = '<div class="empty-state" style="padding:1rem">No timeline events yet.</div>';
      return;
    }

    container.innerHTML = '<div class="timeline-track">' + events.map(e => {
      const icon = e.event_type === 'created' ? '&#9733;' :
                   e.event_type === 'status_change' ? '&#8635;' :
                   e.event_type === 'decision' ? '&#9998;' :
                   e.event_type === 'note_added' ? '&#128196;' :
                   e.event_type === 'runbook_step' ? '&#9881;' : '&#8226;';
      const time = new Date(e.created_at).toLocaleString();
      return `<div class="timeline-entry ${e.type}">
        <span class="timeline-icon">${icon}</span>
        <div class="timeline-body">
          <div class="timeline-desc">${escHtml(e.description)}</div>
          <div class="timeline-meta">
            <span>${time}</span>
            <span>${e.actor !== 'system' ? e.actor : ''}</span>
          </div>
          ${e.detail ? `<div class="timeline-detail">${escHtml(e.detail)}</div>` : ''}
        </div>
      </div>`;
    }).join('') + '</div>';
  } catch (e) {
    console.error('loadIncidentTimeline error:', e);
  }
}

async function loadIncidentNotes(id) {
  try {
    const res = await fetch(`/api/incidents/${id}/notes`);
    const notes = await res.json();
    const container = document.getElementById(`notes-list-${id}`);
    if (!container) return;

    if (!notes.length) {
      container.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.85rem">No notes yet. Add the first one below.</div>';
      return;
    }

    container.innerHTML = notes.map(n => {
      const time = new Date(n.created_at).toLocaleString();
      return `<div class="incident-note">
        <div class="note-text">${escHtml(n.note)}</div>
        <div class="note-meta">${n.author} &mdash; ${time}</div>
      </div>`;
    }).join('');
  } catch (e) {
    console.error('loadIncidentNotes error:', e);
  }
}

async function addIncidentNote(id) {
  const input = document.getElementById(`note-input-${id}`);
  const note = (input?.value || '').trim();
  if (!note) return;

  try {
    await fetch(`/api/incidents/${id}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note }),
    });
    input.value = '';
    loadIncidentNotes(id);
    loadIncidentTimeline(id);
  } catch (e) {
    console.error('addIncidentNote error:', e);
  }
}

// ── Incident Investigation ─────────────────────────────────────────────

async function loadIncidentIpReputation(ips) {
  for (const ip of ips) {
    const el = document.getElementById(`ip-rep-${ip.replace(/\./g, '-')}`);
    if (!el) continue;
    try {
      const rep = await fetchReputation(ip);
      if (!rep || rep.status === 'not_checked') {
        el.innerHTML = '<span style="color:var(--text-muted)">no data</span>';
        continue;
      }
      const verdictColors = { malicious: 'var(--sev-critical)', suspicious: 'var(--sev-high)', clean: 'var(--sev-low)', unknown: 'var(--text-muted)' };
      const color = verdictColors[rep.verdict] || 'var(--text-muted)';
      let detail = rep.verdict || 'unknown';
      if (rep.country) detail += ` | ${rep.country}`;
      if (rep.isp) detail += ` | ${rep.isp}`;
      if (rep.vt_malicious) detail += ` | VT: ${rep.vt_malicious} detections`;
      if (rep.abuse_score) detail += ` | Abuse: ${rep.abuse_score}%`;
      el.innerHTML = `<span style="color:${color};font-weight:600">${escHtml(detail)}</span>`;
    } catch {
      el.innerHTML = '<span style="color:var(--text-muted)">error</span>';
    }
  }
}

async function expandLinkedAlert(alertId, rowEl) {
  if (!alertId) return;
  // Toggle - if already expanded, collapse
  const existing = rowEl.nextElementSibling;
  if (existing && existing.classList.contains('linked-alert-detail')) {
    existing.remove();
    rowEl.querySelector('.linked-alert-expand').innerHTML = '&#9654;';
    return;
  }

  rowEl.querySelector('.linked-alert-expand').innerHTML = '&#9660;';

  try {
    const res = await fetch(`/api/alerts/${encodeURIComponent(alertId)}`);
    const a = await res.json();

    const detailEl = document.createElement('div');
    detailEl.className = 'linked-alert-detail';

    const fields = [
      ['Time', a.timestamp ? new Date(a.timestamp).toLocaleString() : ''],
      ['Source', a.source || ''],
      ['Severity', a.severity || ''],
      ['Src IP', a.src_ip || ''],
      ['Dst IP', a.dst_ip || ''],
      ['Dst Port', a.dst_port || ''],
      ['Protocol', a.proto || ''],
      ['Category', a.category || ''],
      ['Verdict', a.verdict || ''],
      ['Description', a.description || ''],
    ].filter(([, v]) => v);

    detailEl.innerHTML = `
      <div class="linked-detail-grid">
        ${fields.map(([k, v]) => `<div class="ld-field"><span class="ld-key">${k}:</span> <span class="ld-val">${escHtml(String(v))}</span></div>`).join('')}
      </div>
      <div class="linked-detail-actions">
        <button class="btn-sm" onclick="filterAlertsByIp('${escHtml(a.src_ip || '')}')">Alerts from ${escHtml(a.src_ip || 'src')}</button>
        <button class="btn-sm" onclick="filterAlertsByIp('${escHtml(a.dst_ip || '')}')">Alerts to ${escHtml(a.dst_ip || 'dst')}</button>
      </div>`;

    rowEl.after(detailEl);
  } catch (e) {
    console.error('expandLinkedAlert error:', e);
  }
}

function filterAlertsByIp(ip) {
  if (!ip) return;
  openPivotView([ip]);
}

function filterAlertsByIncident(incidentId, ips) {
  if (!ips || !ips.length) return;
  openPivotView(ips, incidentId);
}

async function openPivotView(ips, incidentId = null) {
  // Close any existing overlays
  document.querySelector('.incident-overlay')?.remove();
  document.querySelector('.pivot-overlay')?.remove();

  const overlay = document.createElement('div');
  overlay.className = 'pivot-overlay';
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  const subtitle = incidentId
    ? 'Alerts and incidents within ±24h of this incident'
    : 'All alerts and incidents involving these IPs';

  overlay.innerHTML = `<div class="pivot-panel">
    <div class="pivot-header">
      <div>
        <h2>Pivot View: ${ips.map(ip => escHtml(ip)).join(', ')}</h2>
        <span class="pivot-subtitle">${subtitle}</span>
      </div>
      <button class="btn btn-close-overlay" onclick="this.closest('.pivot-overlay').remove()">&times;</button>
    </div>
    <div class="pivot-body">
      <div class="pivot-loading"><div class="loading-spinner"></div> Loading...</div>
    </div>
  </div>`;
  document.body.appendChild(overlay);

  try {
    const payload = { ips, limit: 300 };
    if (incidentId) payload.incident_id = incidentId;
    const res = await fetch('/api/pivot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    // Store data on overlay for resolve/fp actions
    overlay._pivotData = data;
    renderPivotView(overlay.querySelector('.pivot-body'), data, ips);
  } catch (err) {
    overlay.querySelector('.pivot-body').innerHTML =
      `<div class="empty-state">Failed to load pivot data: ${escHtml(err.message)}</div>`;
  }
}

function renderPivotView(container, data, ips) {
  const alerts = data.alerts || [];
  const incidents = data.incidents || [];
  const timeScoped = data.time_scoped;
  const sourceIncidentId = data.source_incident_id;

  // Separate linked (directly part of incident) from nearby
  const linkedAlerts = alerts.filter(a => a.linked);
  const nearbyAlerts = alerts.filter(a => !a.linked);

  // Count verdicts across all
  const pending = alerts.filter(a => !a.verdict || a.verdict === 'pending');
  const suppressed = alerts.filter(a => a.verdict === 'suppress');

  // Build incidents section - source incident first
  const sourceInc = incidents.filter(i => i.is_source);
  const otherInc = incidents.filter(i => !i.is_source);
  const sortedIncidents = [...sourceInc, ...otherInc];

  let incidentsHtml = '';
  if (sortedIncidents.length) {
    incidentsHtml = `<div class="pivot-section">
      <h3>Related Incidents (${sortedIncidents.length})</h3>
      <div class="pivot-incidents">${sortedIncidents.map(inc => {
        const statusClass = inc.status === 'resolved' ? 'resolved' : inc.status === 'false_positive' ? 'fp' : '';
        const sourceClass = inc.is_source ? 'pivot-source' : '';
        return `<div class="pivot-incident-card ${statusClass} ${sourceClass}" onclick="document.querySelector('.pivot-overlay')?.remove(); showIncidentDetail('${escHtml(inc.id)}')">
          <div class="pivot-inc-header">
            <span class="severity-dot sev-${escHtml(inc.severity || 'medium')}"></span>
            <strong>${escHtml(inc.title)}</strong>
            ${inc.is_source ? '<span class="pivot-source-badge">SOURCE</span>' : ''}
            <span class="pivot-inc-status">${escHtml(inc.status)}</span>
          </div>
          <div class="pivot-inc-meta">
            ${escHtml(inc.category || '')} &middot; ${inc.alert_count || 0} alerts &middot; ${fmtRelative(inc.created_at)}
          </div>
        </div>`;
      }).join('')}</div>
    </div>`;
  }

  // Build alert rows helper
  function buildAlertRows(alertList) {
    // Group by severity
    const bySev = { critical: [], high: [], medium: [], low: [], info: [] };
    for (const a of alertList) {
      const sev = (a.severity || 'info').toLowerCase();
      (bySev[sev] || bySev.info).push(a);
    }
    let html = '';
    const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
    for (const sev of sevOrder) {
      const group = bySev[sev];
      if (!group.length) continue;
      html += `<div class="pivot-sev-group">
        <div class="pivot-sev-header sev-bg-${sev}">
          <span>${sev.toUpperCase()} (${group.length})</span>
        </div>
        <div class="pivot-alert-list">${group.map(a => `
          <div class="pivot-alert-row${a.linked ? ' pivot-linked' : ''}" data-id="${escHtml(a.id)}">
            <input type="checkbox" class="pivot-cb" data-id="${escHtml(a.id)}" checked>
            <div class="pivot-alert-info">
              <div class="pivot-alert-title">${escHtml(a.title)}</div>
              <div class="pivot-alert-meta">
                ${escHtml(a.src_ip || '')} → ${escHtml(a.dst_ip || '')}${a.dst_port ? ':' + a.dst_port : ''}
                &middot; ${escHtml(a.source || '')} &middot; ${fmtRelative(a.timestamp)}
                ${a.verdict && a.verdict !== 'pending' ? `<span class="pivot-verdict v-${escHtml(a.verdict)}">${escHtml(a.verdict)}</span>` : ''}
              </div>
            </div>
          </div>`).join('')}
        </div>
      </div>`;
    }
    return html;
  }

  // Build linked alerts section (from the incident itself)
  let linkedHtml = '';
  if (linkedAlerts.length) {
    linkedHtml = `<div class="pivot-section">
      <h3>Incident Alerts (${linkedAlerts.length})</h3>
      ${buildAlertRows(linkedAlerts)}
    </div>`;
  }

  // Build nearby alerts section
  let nearbyHtml = '';
  if (nearbyAlerts.length) {
    const label = timeScoped ? 'Other Alerts (±24h window)' : 'All Alerts';
    nearbyHtml = `<div class="pivot-section">
      <h3>${label} (${nearbyAlerts.length})</h3>
      ${buildAlertRows(nearbyAlerts)}
    </div>`;
  }

  const noAlerts = !linkedAlerts.length && !nearbyAlerts.length;
  container.innerHTML = `
    <div class="pivot-summary">
      <div class="pivot-stat"><strong>${alerts.length}</strong> alerts</div>
      <div class="pivot-stat"><strong>${incidents.length}</strong> incidents</div>
      <div class="pivot-stat"><strong>${pending.length}</strong> pending</div>
      <div class="pivot-stat"><strong>${suppressed.length}</strong> suppressed</div>
      ${timeScoped ? '<div class="pivot-stat pivot-time-badge">±24h window</div>' : ''}
    </div>

    <div class="pivot-bulk-bar">
      <button class="btn" onclick="pivotSelectAll(this)">Select All Pending</button>
      <button class="btn" onclick="pivotDeselectAll()">Deselect All</button>
      <span class="pivot-selected-count"></span>
      <div class="pivot-bulk-actions">
        <button class="btn btn-suppress" onclick="pivotBulkVerdict('suppress')">Dismiss Selected</button>
        <button class="btn btn-escalate" onclick="pivotBulkVerdict('escalate')">Escalate Selected</button>
      </div>
    </div>

    <div class="pivot-resolve-bar">
      <button class="btn btn-resolve" onclick="pivotResolveAll()">Resolve All - dismiss alerts &amp; close incidents</button>
      <button class="btn btn-fp" onclick="pivotFalsePositiveAll()">False Positive All</button>
    </div>

    ${incidentsHtml}
    ${linkedHtml}
    ${nearbyHtml}
    ${noAlerts ? '<div class="empty-state">No alerts found for these IPs</div>' : ''}`;

  // Wire up checkbox change listeners
  container.querySelectorAll('.pivot-cb').forEach(cb => {
    cb.addEventListener('change', () => updatePivotSelectedCount());
  });
  updatePivotSelectedCount();
}

function pivotSelectAll(btn) {
  document.querySelectorAll('.pivot-cb').forEach(cb => {
    const row = cb.closest('.pivot-alert-row');
    const id = cb.dataset.id;
    // Only select pending alerts
    if (!row.querySelector('.pivot-verdict')) {
      cb.checked = true;
    }
  });
  updatePivotSelectedCount();
}

function pivotDeselectAll() {
  document.querySelectorAll('.pivot-cb').forEach(cb => cb.checked = false);
  updatePivotSelectedCount();
}

function updatePivotSelectedCount() {
  const checked = document.querySelectorAll('.pivot-cb:checked');
  const el = document.querySelector('.pivot-selected-count');
  if (el) el.textContent = `${checked.length} selected`;
}

async function pivotBulkVerdict(verdict) {
  const ids = [...document.querySelectorAll('.pivot-cb:checked')].map(cb => cb.dataset.id);
  if (!ids.length) return;
  if (!confirm(`Set ${ids.length} alert(s) to "${verdict}"?`)) return;

  try {
    const res = await fetch('/api/alerts/bulk-verdict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_ids: ids, verdict }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    // Update the UI - mark rows as actioned
    for (const id of ids) {
      const row = document.querySelector(`.pivot-alert-row[data-id="${id}"]`);
      if (row) {
        row.style.opacity = '0.5';
        const cb = row.querySelector('.pivot-cb');
        if (cb) { cb.checked = false; cb.disabled = true; }
        const meta = row.querySelector('.pivot-alert-meta');
        if (meta) meta.innerHTML += ` <span class="pivot-verdict v-${escHtml(verdict)}">${escHtml(verdict)}</span>`;
      }
    }
    updatePivotSelectedCount();

    // Refresh main alert list in background
    fetchAlerts(state.page);
  } catch (err) {
    alert('Bulk verdict failed: ' + err.message);
  }
}

async function pivotResolveAll() {
  const overlay = document.querySelector('.pivot-overlay');
  const data = overlay?._pivotData;
  if (!data) return;

  const alertIds = (data.alerts || []).map(a => a.id);
  const incidentIds = (data.incidents || []).map(i => i.id);
  const total = alertIds.length + incidentIds.length;

  if (!confirm(`Resolve everything?\n• ${alertIds.length} alerts → suppress\n• ${incidentIds.length} incidents → resolved`)) return;

  const btn = overlay.querySelector('.btn-resolve');
  if (btn) { btn.disabled = true; btn.textContent = 'Resolving...'; }

  try {
    const promises = [];
    // Suppress all alerts
    if (alertIds.length) {
      promises.push(fetch('/api/alerts/bulk-verdict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_ids: alertIds.slice(0, 500), verdict: 'suppress' }),
      }));
    }
    // Resolve all incidents
    for (const iid of incidentIds) {
      promises.push(fetch(`/api/incidents/${iid}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'resolved', resolved_by: 'pivot-view' }),
      }));
    }
    await Promise.all(promises);

    // Close and refresh
    overlay.remove();
    fetchAlerts(state.page);
    fetchIncidents();
  } catch (err) {
    alert('Resolve failed: ' + err.message);
    if (btn) { btn.disabled = false; btn.textContent = 'Resolve All - dismiss alerts & close incidents'; }
  }
}

async function pivotFalsePositiveAll() {
  const overlay = document.querySelector('.pivot-overlay');
  const data = overlay?._pivotData;
  if (!data) return;

  const alertIds = (data.alerts || []).map(a => a.id);
  const incidentIds = (data.incidents || []).map(i => i.id);

  if (!confirm(`Mark everything as false positive?\n• ${alertIds.length} alerts → suppress\n• ${incidentIds.length} incidents → false_positive`)) return;

  const btn = overlay.querySelector('.btn-fp');
  if (btn) { btn.disabled = true; btn.textContent = 'Processing...'; }

  try {
    const promises = [];
    if (alertIds.length) {
      promises.push(fetch('/api/alerts/bulk-verdict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_ids: alertIds.slice(0, 500), verdict: 'suppress' }),
      }));
    }
    for (const iid of incidentIds) {
      promises.push(fetch(`/api/incidents/${iid}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'false_positive', resolved_by: 'pivot-view' }),
      }));
    }
    await Promise.all(promises);
    overlay.remove();
    fetchAlerts(state.page);
    fetchIncidents();
  } catch (err) {
    alert('False positive failed: ' + err.message);
    if (btn) { btn.disabled = false; btn.textContent = 'False Positive All'; }
  }
}

async function openThreatsOverlay() {
  document.querySelector('.pivot-overlay')?.remove();

  const overlay = document.createElement('div');
  overlay.className = 'pivot-overlay';
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  overlay.innerHTML = `<div class="pivot-panel">
    <div class="pivot-header">
      <div>
        <h2>External Threats</h2>
        <span class="pivot-subtitle">Clusters from outside your network marked as escalated</span>
      </div>
      <button class="btn btn-close-overlay" onclick="this.closest('.pivot-overlay').remove()">&times;</button>
    </div>
    <div class="pivot-body">
      <div class="pivot-loading"><div class="loading-spinner"></div> Loading threat clusters...</div>
    </div>
  </div>`;
  document.body.appendChild(overlay);

  try {
    const res = await fetch('/api/clusters?limit=500');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const clusters = await res.json();

    // Filter to external escalated
    const threats = (Array.isArray(clusters) ? clusters : clusters.clusters || []).filter(c => {
      const src = c.src_ip || '';
      const isHome = src.startsWith('192.168.') || src.startsWith('10.') || src.startsWith('172.16.') || !src;
      return !isHome && c.verdict === 'escalate';
    });

    const body = overlay.querySelector('.pivot-body');
    if (!threats.length) {
      body.innerHTML = '<div class="empty-state" style="padding:2rem">No external threats - all clear!</div>';
      return;
    }

    body.innerHTML = `
      <div class="pivot-summary">
        <div class="pivot-stat"><strong>${threats.length}</strong> threat clusters</div>
        <div class="pivot-stat"><strong>${threats.reduce((s,c) => s + (c.alert_count||0), 0)}</strong> total alerts</div>
      </div>
      <div class="pivot-bulk-bar">
        <button class="btn btn-resolve" onclick="suppressThreatClusters()">Suppress All - these are false positives</button>
      </div>
      <div class="pivot-section">
        <h3>Threat Clusters</h3>
        ${threats.map(c => `
          <div class="pivot-incident-card threat-cluster-row" data-cluster-id="${escHtml(c.id)}">
            <div class="pivot-inc-header">
              <span class="severity-dot sev-high"></span>
              <strong>${escHtml(c.title || c.src_ip)}</strong>
              <span class="pivot-inc-status">${c.alert_count || 0} alerts</span>
            </div>
            <div class="pivot-inc-meta">
              ${escHtml(c.src_ip || 'unknown')} &middot; ${fmtRelative(c.first_seen || c.created_at)}
              ${c.src_ip ? ` &middot; <a href="#" onclick="event.stopPropagation(); openPivotView(['${escHtml(c.src_ip)}']); return false;">Pivot on IP</a>` : ''}
            </div>
          </div>`).join('')}
      </div>`;

    // Store cluster IDs for bulk suppress
    overlay._threatClusterIds = threats.map(c => c.id);
  } catch (err) {
    overlay.querySelector('.pivot-body').innerHTML =
      `<div class="empty-state">Failed: ${escHtml(err.message)}</div>`;
  }
}

async function suppressThreatClusters() {
  const overlay = document.querySelector('.pivot-overlay');
  const ids = overlay?._threatClusterIds;
  if (!ids || !ids.length) return;
  if (!confirm(`Suppress ${ids.length} threat cluster(s)? Their alerts will be marked as dismissed.`)) return;

  const btn = overlay.querySelector('.btn-resolve');
  if (btn) { btn.disabled = true; btn.textContent = 'Suppressing...'; }

  try {
    await Promise.all(ids.map(id =>
      fetch(`/api/clusters/${id}/verdict`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ verdict: 'suppress' }),
      })
    ));
    overlay.remove();
    fetchAlerts(state.page);
    fetchStats();
  } catch (err) {
    alert('Failed: ' + err.message);
    if (btn) { btn.disabled = false; btn.textContent = 'Suppress All - these are false positives'; }
  }
}

// ── Needs Review Overlay ──────────────────────────────────────────────────

async function openNeedsReviewOverlay() {
  document.querySelector('.pivot-overlay')?.remove();

  const overlay = document.createElement('div');
  overlay.className = 'pivot-overlay';
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  overlay.innerHTML = `<div class="pivot-panel">
    <div class="pivot-header">
      <div>
        <h2>Needs Review</h2>
        <span class="pivot-subtitle">External clusters pending investigation or review</span>
      </div>
      <button class="btn btn-close-overlay" onclick="this.closest('.pivot-overlay').remove()">&times;</button>
    </div>
    <div class="pivot-body">
      <div class="pivot-loading"><div class="loading-spinner"></div> Loading clusters...</div>
    </div>
  </div>`;
  document.body.appendChild(overlay);

  try {
    const res = await fetch('/api/clusters?limit=500');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const clusters = await res.json();

    const items = (Array.isArray(clusters) ? clusters : clusters.clusters || []).filter(c => {
      const src = c.src_ip || '';
      const isHome = src.startsWith('192.168.') || src.startsWith('10.') || src.startsWith('172.16.') || !src;
      return !isHome && (c.verdict === 'pending' || c.verdict === 'investigate');
    });

    const body = overlay.querySelector('.pivot-body');
    if (!items.length) {
      body.innerHTML = '<div class="empty-state" style="padding:2rem">Nothing to review - all clear!</div>';
      return;
    }

    body.innerHTML = `
      <div class="pivot-summary">
        <div class="pivot-stat"><strong>${items.length}</strong> clusters needing review</div>
        <div class="pivot-stat"><strong>${items.reduce((s,c) => s + (c.alert_count||0), 0)}</strong> total alerts</div>
      </div>
      <div class="pivot-bulk-bar">
        <button class="btn btn-resolve" onclick="suppressReviewClusters()">Suppress All - bulk dismiss</button>
      </div>
      <div class="pivot-section">
        <h3>Review Clusters</h3>
        ${items.map(c => `
          <div class="pivot-incident-card" data-cluster-id="${escHtml(c.id)}">
            <div class="pivot-inc-header">
              <span class="severity-dot sev-medium"></span>
              <strong>${escHtml(c.title || c.src_ip)}</strong>
              ${verdictBadge(c.verdict)}
              <span class="pivot-inc-status">${c.alert_count || 0} alerts</span>
            </div>
            <div class="pivot-inc-meta">
              ${escHtml(c.src_ip || 'unknown')} &middot; ${fmtRelative(c.first_seen || c.created_at)}
              ${c.src_ip ? ` &middot; <a href="#" onclick="event.stopPropagation(); openPivotView(['${escHtml(c.src_ip)}']); return false;">Pivot on IP</a>` : ''}
            </div>
          </div>`).join('')}
      </div>`;

    overlay._reviewClusterIds = items.map(c => c.id);
  } catch (err) {
    overlay.querySelector('.pivot-body').innerHTML =
      `<div class="empty-state">Failed: ${escHtml(err.message)}</div>`;
  }
}

async function suppressReviewClusters() {
  const overlay = document.querySelector('.pivot-overlay');
  const ids = overlay?._reviewClusterIds;
  if (!ids || !ids.length) return;
  if (!confirm(`Suppress ${ids.length} cluster(s)? Their alerts will be marked as dismissed.`)) return;

  const btn = overlay.querySelector('.btn-resolve');
  if (btn) { btn.disabled = true; btn.textContent = 'Suppressing...'; }

  try {
    await Promise.all(ids.map(id =>
      fetch(`/api/clusters/${id}/verdict`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ verdict: 'suppress' }),
      })
    ));
    overlay.remove();
    fetchAlerts(state.page);
    fetchStats();
    toast('Review clusters suppressed', 'success');
  } catch (err) {
    alert('Failed: ' + err.message);
    if (btn) { btn.disabled = false; btn.textContent = 'Suppress All - bulk dismiss'; }
  }
}

async function openStaleAlertsOverlay() {
  try {
    const res = await fetch('/api/alerts/stale?limit=200');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const alerts = data.alerts || [];

    const overlay = document.createElement('div');
    overlay.className = 'pivot-overlay';
    overlay.innerHTML = `
      <div class="pivot-panel">
        <div class="pivot-header">
          <h2>Stale Alerts (pending &gt; 24h)</h2>
          <span style="color:var(--text-muted);font-size:0.85rem">${alerts.length} alerts</span>
          <button class="btn-close-pivot" onclick="this.closest('.pivot-overlay').remove()">Close</button>
        </div>
        <div class="pivot-body" id="stale-alerts-body"></div>
        ${alerts.length > 0 ? `<div class="pivot-resolve-bar">
          <button class="btn-resolve" onclick="bulkSuppressStale(this)">Suppress All Stale</button>
          <button class="btn-fp" onclick="bulkFpStale(this)">False Positive All</button>
        </div>` : ''}
      </div>`;
    document.body.appendChild(overlay);

    const body = document.getElementById('stale-alerts-body');
    if (alerts.length === 0) {
      body.innerHTML = '<div class="empty-state">No stale alerts - all caught up!</div>';
      return;
    }

    let html = '<table style="width:100%;border-collapse:collapse;font-size:0.85rem"><thead><tr>' +
      '<th style="text-align:left;padding:6px;border-bottom:1px solid var(--border)">Age</th>' +
      '<th style="text-align:left;padding:6px;border-bottom:1px solid var(--border)">Severity</th>' +
      '<th style="text-align:left;padding:6px;border-bottom:1px solid var(--border)">Title</th>' +
      '<th style="text-align:left;padding:6px;border-bottom:1px solid var(--border)">Source IP</th>' +
      '<th style="text-align:left;padding:6px;border-bottom:1px solid var(--border)">Source</th>' +
      '</tr></thead><tbody>';
    for (const a of alerts) {
      const ageStr = a.age_hours > 24 ? `${Math.floor(a.age_hours/24)}d ${Math.floor(a.age_hours%24)}h` : `${Math.round(a.age_hours)}h`;
      const sevClass = a.severity || 'medium';
      html += `<tr style="border-bottom:1px solid var(--border-dim)">` +
        `<td style="padding:6px;white-space:nowrap">${ageStr}</td>` +
        `<td style="padding:6px"><span class="sev-badge ${sevClass}">${sevClass}</span></td>` +
        `<td style="padding:6px;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(a.title || '')}</td>` +
        `<td style="padding:6px">${escHtml(a.src_ip || '')}</td>` +
        `<td style="padding:6px">${escHtml(a.source || '')}</td>` +
        `</tr>`;
    }
    html += '</tbody></table>';
    body.innerHTML = html;
  } catch (err) {
    alert('Failed to load stale alerts: ' + err.message);
  }
}

async function bulkSuppressStale(btn) {
  if (!confirm('Suppress all stale (>24h) pending alerts?')) return;
  btn.disabled = true; btn.textContent = 'Suppressing...';
  try {
    const res = await fetch('/api/alerts/suppress', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verdict: 'pending', since: null }),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const overlay = btn.closest('.pivot-overlay');
    if (overlay) overlay.remove();
    fetchStats(); fetchAlerts(0);
    toast('Stale alerts suppressed', 'success');
  } catch (err) { alert('Failed: ' + err.message); btn.disabled = false; btn.textContent = 'Suppress All Stale'; }
}

async function bulkFpStale(btn) {
  if (!confirm('Mark all stale (>24h) pending alerts as false positive?')) return;
  btn.disabled = true; btn.textContent = 'Marking...';
  try {
    const res = await fetch('/api/alerts/stale', { method: 'GET' });
    const data = await res.json();
    const ids = (data.alerts || []).map(a => a.id);
    if (ids.length === 0) { toast('No stale alerts', 'info'); return; }
    const vRes = await fetch('/api/bulk-verdict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_ids: ids, verdict: 'suppress', reasoning: 'Bulk FP: stale >24h' }),
    });
    if (!vRes.ok) throw new Error('HTTP ' + vRes.status);
    const overlay = btn.closest('.pivot-overlay');
    if (overlay) overlay.remove();
    fetchStats(); fetchAlerts(0);
    toast('Stale alerts marked false positive', 'success');
  } catch (err) { alert('Failed: ' + err.message); btn.disabled = false; btn.textContent = 'False Positive All'; }
}

// ── MITRE ATT&CK Coverage ────────────────────────────────────────────────
let mitreLoaded = false;

function toggleMitre() {
  const body = document.getElementById('mitre-body');
  const toggle = document.getElementById('mitre-toggle');
  if (body.style.display === 'none') {
    body.style.display = 'block';
    toggle.textContent = 'Hide';
    if (!mitreLoaded) fetchMitreCoverage();
  } else {
    body.style.display = 'none';
    toggle.textContent = 'Show';
  }
}

async function fetchMitreCoverage() {
  const body = document.getElementById('mitre-body');
  body.innerHTML = '<div class="empty-state">Loading MITRE coverage...</div>';
  try {
    const res = await fetch('/api/mitre');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    mitreLoaded = true;
    renderMitreGrid(body, data.tactics);
  } catch (err) {
    body.innerHTML = `<div class="empty-state" style="color:var(--sev-critical)">Failed: ${escHtml(err.message)}</div>`;
  }
}

function renderMitreGrid(container, tactics) {
  let html = '<div class="mitre-grid">';
  for (const tac of tactics) {
    html += `<div class="mitre-tactic">`;
    html += `<div class="mitre-tactic-header">${escHtml(tac.tactic)}<span class="mitre-tactic-count">${tac.detected_count}/${tac.total_count}</span></div>`;
    for (const tech of tac.techniques) {
      const cls = tech.detected ? 'mitre-tech detected' : 'mitre-tech';
      const countBadge = tech.count > 0 ? `<span class="mitre-count">${tech.count}</span>` : '';
      html += `<div class="${cls}" title="${tech.id}: ${escHtml(tech.name)}">`
        + `<span class="mitre-tech-id">${tech.id}</span>`
        + `<span class="mitre-tech-name">${escHtml(tech.name)}</span>`
        + countBadge
        + `</div>`;
    }
    html += `</div>`;
  }
  html += '</div>';
  container.innerHTML = html;
}

async function runIncidentJttw(incidentId, btn) {
  btn.disabled = true;
  btn.textContent = 'Running investigation...';
  const container = document.getElementById(`incident-jttw-${incidentId}`);
  if (!container) return;
  container.innerHTML = '<div class="jttw-loading"><div class="loading-spinner"></div> AI is analyzing all related alerts. This may take 30-60 seconds...</div>';

  try {
    const res = await fetch('/api/investigations/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ since: '24h', min_severity: 'low', auto_verdict: false }),
    });
    const data = await res.json();

    if (data.error) {
      container.innerHTML = `<div class="empty-state" style="color:var(--sev-critical)">${escHtml(data.error)}</div>`;
      btn.textContent = 'Retry Investigation';
      btn.disabled = false;
      return;
    }

    const report = data.report || data;

    let html = `<div class="jttw-inline-report">
      <div class="jttw-meta-bar">
        <span>Analyzed <b>${data.alert_count || 0}</b> alerts</span>
        <span>Model: <b>${escHtml(data.model || '?')}</b></span>
        <span>${data.latency_ms ? (data.latency_ms / 1000).toFixed(1) + 's' : ''}</span>
      </div>`;

    if (report.executive_summary) {
      html += `<div class="jttw-section">
        <h4>Executive Summary</h4>
        <p>${escHtml(report.executive_summary)}</p>
      </div>`;
    }

    if (report.findings && report.findings.length) {
      html += `<div class="jttw-section"><h4>Findings</h4>`;
      for (const f of report.findings) {
        const sev = f.severity || 'medium';
        html += `<div class="jttw-finding ${sev}">
          <div class="jttw-finding-title">${escHtml(f.title || f.finding || '')}</div>
          <div class="jttw-finding-detail">${escHtml(f.detail || f.description || '')}</div>
          ${f.recommendation ? `<div class="jttw-finding-rec">Recommendation: ${escHtml(f.recommendation)}</div>` : ''}
        </div>`;
      }
      html += '</div>';
    }

    if (report.recommendations && report.recommendations.length) {
      html += `<div class="jttw-section"><h4>Recommendations</h4><ul>`;
      for (const r of report.recommendations) {
        html += `<li>${escHtml(typeof r === 'string' ? r : r.description || r.recommendation || JSON.stringify(r))}</li>`;
      }
      html += '</ul></div>';
    }

    html += '</div>';
    container.innerHTML = html;
    btn.textContent = 'Investigation Complete';

    // Add timeline event
    try {
      await fetch(`/api/incidents/${incidentId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: `Deep AI investigation completed: ${data.alert_count} alerts analyzed`, author: 'AI' }),
      });
    } catch {}
  } catch (e) {
    container.innerHTML = `<div class="empty-state" style="color:var(--sev-critical)">Investigation failed: ${escHtml(e.message)}</div>`;
    btn.textContent = 'Retry Investigation';
    btn.disabled = false;
  }
}

// ── Asset Inventory ────────────────────────────────────────────────────

async function loadAssets() {
  try {
    const res = await fetch('/api/assets');
    const assets = await res.json();
    const section = $('assets-section');
    const list = $('assets-list');
    if (!section || !list) return;

    if (!assets.length) {
      section.style.display = 'none';
      return;
    }

    section.style.display = '';
    const critColors = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)' };
    list.innerHTML = assets.slice(0, 50).map(a => {
      const critColor = critColors[a.criticality] || 'var(--text-muted)';
      return `<div class="asset-row" onclick="showAssetDetail('${a.id}')">
        <span class="asset-crit-dot" style="background:${critColor}" title="${a.criticality}"></span>
        <span class="asset-ip">${escHtml(a.ip)}</span>
        <span class="asset-hostname">${escHtml(a.hostname || a.mac || '')}</span>
        <span class="asset-type">${a.asset_type || ''}</span>
        <span class="asset-alerts">${a.alert_count} alerts</span>
        <span class="asset-seen">${timeAgo(new Date(a.last_seen))}</span>
      </div>`;
    }).join('');
  } catch (e) {
    console.error('loadAssets error:', e);
  }
}

async function showAssetDetail(id) {
  try {
    const res = await fetch(`/api/assets/${id}`);
    const a = await res.json();

    const overlay = document.createElement('div');
    overlay.className = 'incident-overlay';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

    const critOptions = ['low', 'medium', 'high', 'critical'].map(c =>
      `<option value="${c}" ${a.criticality === c ? 'selected' : ''}>${c}</option>`
    ).join('');

    overlay.innerHTML = `
      <div class="incident-detail" style="max-width:500px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem">
          <h2 style="margin:0">${escHtml(a.ip)}</h2>
          <button class="btn btn-close-overlay" onclick="this.closest('.incident-overlay').remove()">&times;</button>
        </div>
        <div class="asset-detail-grid">
          <div><strong>Hostname:</strong> ${escHtml(a.hostname || 'unknown')}</div>
          <div><strong>MAC:</strong> ${escHtml(a.mac || 'unknown')}</div>
          <div><strong>OS:</strong> ${escHtml(a.os || 'unknown')}</div>
          <div><strong>Type:</strong> ${escHtml(a.asset_type || 'unknown')}</div>
          <div><strong>Segment:</strong> ${escHtml(a.network_segment || '')}</div>
          <div><strong>First seen:</strong> ${new Date(a.first_seen).toLocaleString()}</div>
          <div><strong>Last seen:</strong> ${new Date(a.last_seen).toLocaleString()}</div>
          <div><strong>Alerts:</strong> ${a.alert_count}</div>
        </div>
        <div style="margin-top:0.75rem">
          <label style="font-size:0.8rem;color:var(--text-secondary)">Criticality</label>
          <select class="filter-select" style="margin-left:0.5rem" onchange="updateAssetField('${id}', 'criticality', this.value)">
            ${critOptions}
          </select>
        </div>
        <div style="margin-top:0.5rem">
          <label style="font-size:0.8rem;color:var(--text-secondary)">Notes</label>
          <textarea id="asset-notes-${id}" rows="2" style="width:100%;margin-top:0.25rem;background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:var(--radius);padding:0.5rem">${escHtml(a.notes || '')}</textarea>
          <button class="btn" style="margin-top:0.25rem" onclick="updateAssetField('${id}', 'notes', document.getElementById('asset-notes-${id}').value)">Save Notes</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
  } catch (e) {
    console.error('showAssetDetail error:', e);
  }
}

async function createAsset() {
  const ip = document.getElementById('new-asset-ip')?.value?.trim();
  if (!ip) { toast('IP required'); return; }
  const hostname = document.getElementById('new-asset-hostname')?.value?.trim() || '';
  const asset_type = document.getElementById('new-asset-type')?.value || 'unknown';
  const criticality = document.getElementById('new-asset-crit')?.value || 'medium';
  try {
    await fetch('/api/assets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, hostname, asset_type, criticality }),
    });
    document.getElementById('new-asset-ip').value = '';
    document.getElementById('new-asset-hostname').value = '';
    document.getElementById('add-asset-form').style.display = 'none';
    loadAssets();
    toast('Asset added');
  } catch (e) {
    console.error('createAsset error:', e);
  }
}

async function updateAssetField(id, field, value) {
  try {
    await fetch(`/api/assets/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [field]: value }),
    });
    toast(`Asset updated: ${field}`);
  } catch (e) {
    console.error('updateAssetField error:', e);
  }
}

// ── Audit Log ──────────────────────────────────────────────────────────

async function loadAuditLog() {
  try {
    const res = await fetch('/api/audit-log?limit=50');
    const data = await res.json();
    const container = $('audit-list');
    if (!container) return;

    if (!data.entries?.length) {
      container.innerHTML = '<div class="empty-state" style="padding:0.5rem">No audit entries yet.</div>';
      return;
    }

    container.innerHTML = data.entries.map(e => {
      const time = new Date(e.ts).toLocaleString();
      return `<div class="audit-row">
        <span class="audit-time">${time}</span>
        <span class="audit-action">${escHtml(e.action)}</span>
        <span class="audit-target">${escHtml(e.target_type)} ${escHtml(e.target_id ? e.target_id.slice(0, 8) : '')}</span>
        <span class="audit-detail">${escHtml((e.detail || '').slice(0, 80))}</span>
      </div>`;
    }).join('');
  } catch (e) {
    console.error('loadAuditLog error:', e);
  }
}

// ── System Health ──────────────────────────────────────────────────────

async function loadSystemHealth() {
  try {
    const res = await fetch('/api/system/health');
    const data = await res.json();
    const container = $('system-health-content');
    if (!container) return;

    let html = '<div class="sys-health-grid">';

    // DB stats
    if (data.db) {
      html += `<div class="sys-health-card">
        <h4>Database</h4>
        <div>${data.db.db_size_mb} MB (WAL: ${data.db.wal_size_mb} MB)</div>
        <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem">`;
      for (const [table, count] of Object.entries(data.db.tables || {})) {
        html += `${table}: ${count.toLocaleString()} &nbsp; `;
      }
      html += '</div></div>';
    }

    // Disk
    if (data.disk) {
      const diskClass = data.disk.percent > 90 ? 'critical' : data.disk.percent > 75 ? 'high' : '';
      html += `<div class="sys-health-card ${diskClass}">
        <h4>Disk</h4>
        <div>${data.disk.free_gb} GB free of ${data.disk.total_gb} GB (${data.disk.percent}% used)</div>
      </div>`;
    }

    // Memory
    if (data.memory) {
      const memClass = data.memory.percent > 90 ? 'critical' : data.memory.percent > 75 ? 'high' : '';
      html += `<div class="sys-health-card ${memClass}">
        <h4>Memory</h4>
        <div>${data.memory.used_gb} GB / ${data.memory.total_gb} GB (${data.memory.percent}%)</div>
      </div>`;
    }

    // Queue + WS
    html += `<div class="sys-health-card">
      <h4>Pipeline</h4>
      <div>Queue depth: ${data.queue_depth} &nbsp; WS clients: ${data.ws_clients}</div>
    </div>`;

    html += '</div>';

    const fleet = Array.isArray(data.fleet) ? data.fleet : [];
    if (fleet.length) {
      html += '<div class="sys-fleet-grid">';
      html += fleet.map(systemFleetCard).join('');
      html += '</div>';
    }

    // Backup button
    html += `<div style="margin-top:0.75rem">
      <button class="btn" onclick="triggerBackup()">Create Backup</button>
      <span id="backup-status" style="margin-left:0.5rem;font-size:0.8rem;color:var(--text-muted)"></span>
    </div>`;

    container.innerHTML = html;
  } catch (e) {
    console.error('loadSystemHealth error:', e);
  }
}

function systemMetric(label, value, status = '') {
  return `<div class="sys-machine-metric ${status}"><span>${escHtml(label)}</span><strong>${escHtml(value)}</strong></div>`;
}

function systemFleetCard(agent) {
  const name = String(agent.agent || '-');
  const isThisBox = name === 'host01';
  const title = isThisBox ? `This box: ${name}` : name;
  const gpus = Array.isArray(agent.gpus) ? agent.gpus : [];
  const cpu = agent.cpu_util_pct !== undefined && agent.cpu_util_pct !== '' ? fmtPercent(agent.cpu_util_pct) : '-';
  const temp = agent.cpu_temp_c !== undefined && agent.cpu_temp_c !== '' ? `${Math.round(firstNumber(agent.cpu_temp_c))}C` : '-';
  const mem = agent.mem_used_pct !== undefined && agent.mem_used_pct !== '' ? fmtPercent(agent.mem_used_pct) : '-';
  const disk = agent.disk_used_pct !== undefined && agent.disk_used_pct !== '' ? fmtPercent(agent.disk_used_pct) : '-';
  const load = agent.load_per_core !== undefined && agent.load_per_core !== '' ? firstNumber(agent.load_per_core).toFixed(2) : '-';
  const statusClass = String(agent.state || '').startsWith('OFFLINE')
    ? 'critical'
    : String(agent.state || '').startsWith('STALE') ? 'high' : '';
  const gpuHtml = gpus.length ? gpus.map(gpu => {
    const power = gpu.power_w !== undefined && gpu.power_limit_w !== undefined
      ? `${gpu.power_w}/${gpu.power_limit_w}W`
      : gpu.power_w !== undefined ? `${gpu.power_w}W` : '-';
    return `
      <div class="sys-gpu-tile">
        <div class="sys-gpu-title">GPU${gpu.index} ${escHtml(gpu.name || '')}</div>
        <div class="sys-gpu-metrics">
          ${systemMetric('Util', fmtPercent(gpu.util_pct), firstNumber(gpu.util_pct) >= 90 ? 'warn' : '')}
          ${systemMetric('VRAM', `${fmtGbFromMb(gpu.mem_used_mb)}/${fmtGbFromMb(gpu.mem_total_mb)}`, firstNumber(gpu.mem_used_pct) >= 90 ? 'warn' : '')}
          ${systemMetric('Temp', gpu.temp_c !== undefined ? `${Math.round(firstNumber(gpu.temp_c))}C` : '-', firstNumber(gpu.temp_c) >= 80 ? 'warn' : '')}
          ${systemMetric('Power', power)}
        </div>
      </div>
    `;
  }).join('') : '<div class="sys-gpu-empty">CPU-only or no NVIDIA telemetry</div>';
  return `
    <section class="sys-machine-card ${statusClass}">
      <div class="sys-machine-head">
        <div>
          <h4>${escHtml(title)}</h4>
          <div>${escHtml(agent.ip || '-')} · ${escHtml(agent.state || '-')} · ${fmtSecurityAge(agent.age_sec)}</div>
        </div>
        <span>${escHtml(agent.cpu_count || '-')} cores</span>
      </div>
      <div class="sys-machine-metrics">
        ${systemMetric('CPU', cpu, firstNumber(agent.cpu_util_pct) >= 85 ? 'warn' : '')}
        ${systemMetric('Temp', temp, firstNumber(agent.cpu_temp_c) >= 80 ? 'warn' : '')}
        ${systemMetric('RAM', mem, firstNumber(agent.mem_used_pct) >= 85 ? 'warn' : '')}
        ${systemMetric('Disk', disk, firstNumber(agent.disk_used_pct) >= 80 ? 'warn' : '')}
        ${systemMetric('Load/core', load, firstNumber(agent.load_per_core) >= 1 ? 'warn' : '')}
        ${systemMetric('Uptime', fmtDuration(agent.uptime_seconds))}
      </div>
      <div class="sys-gpu-list">${gpuHtml}</div>
    </section>
  `;
}

async function triggerBackup() {
  const status = $('backup-status');
  if (status) status.textContent = 'Creating backup...';
  try {
    const res = await fetch('/api/system/backup', { method: 'POST' });
    const data = await res.json();
    if (data.ok) {
      if (status) status.textContent = `Backup created: ${data.path}`;
      toast('Database backup created');
    } else {
      if (status) status.textContent = `Error: ${data.error}`;
    }
  } catch (e) {
    if (status) status.textContent = 'Backup failed';
  }
}

// ── Network Analytics Panel ───────────────────────────────────────────────

function toggleAnalytics() {
  const body = document.getElementById('analytics-body');
  const toggle = document.getElementById('analytics-toggle');
  if (!body) return;
  if (body.style.display === 'none') {
    body.style.display = '';
    if (toggle) toggle.textContent = 'Hide';
    loadAnalytics();
  } else {
    body.style.display = 'none';
    if (toggle) toggle.textContent = 'Show';
  }
}

async function loadAnalytics() {
  const grid = document.getElementById('analytics-grid');
  if (!grid) return;

  const period = document.getElementById('analytics-period')?.value || '';
  let since = '';
  if (period === '24h') since = new Date(Date.now() - 86400000).toISOString();
  else if (period === '7d') since = new Date(Date.now() - 7*86400000).toISOString();
  else if (period === '30d') since = new Date(Date.now() - 30*86400000).toISOString();

  const qs = since ? `?since=${encodeURIComponent(since)}` : '';

  try {
    const [protoRes, dnsRes] = await Promise.all([
      fetch(`/api/analytics/protocols${qs}`),
      fetch(`/api/analytics/dns${qs}`),
    ]);
    const proto = await protoRes.json();
    const dns = await dnsRes.json();

    let html = '<div class="analytics-grid-inner">';

    // Protocol distribution
    html += '<div class="analytics-card"><h4>Protocols</h4>';
    if (proto.protocols?.length) {
      html += '<div class="analytics-bars">';
      const maxP = proto.protocols[0]?.count || 1;
      for (const p of proto.protocols.slice(0, 8)) {
        const pct = Math.round((p.count / maxP) * 100);
        html += `<div class="analytics-bar-row"><span class="analytics-bar-label">${escHtml(p.proto || '?')}</span><div class="analytics-bar-track"><div class="analytics-bar-fill" style="width:${pct}%"></div></div><span class="analytics-bar-count">${p.count}</span></div>`;
      }
      html += '</div>';
    } else { html += '<div class="empty-state" style="font-size:0.8rem">No protocol data</div>'; }
    html += '</div>';

    // Top ports
    html += '<div class="analytics-card"><h4>Top Ports</h4>';
    if (proto.ports?.length) {
      html += '<div class="analytics-bars">';
      const maxPt = proto.ports[0]?.count || 1;
      for (const p of proto.ports.slice(0, 8)) {
        const pct = Math.round((p.count / maxPt) * 100);
        html += `<div class="analytics-bar-row"><span class="analytics-bar-label">${p.dst_port}</span><div class="analytics-bar-track"><div class="analytics-bar-fill" style="width:${pct}%"></div></div><span class="analytics-bar-count">${p.count}</span></div>`;
      }
      html += '</div>';
    } else { html += '<div class="empty-state" style="font-size:0.8rem">No port data</div>'; }
    html += '</div>';

    // Categories
    html += '<div class="analytics-card"><h4>Categories</h4>';
    if (proto.categories?.length) {
      html += '<div class="analytics-bars">';
      const maxC = proto.categories[0]?.count || 1;
      for (const c of proto.categories.slice(0, 8)) {
        const pct = Math.round((c.count / maxC) * 100);
        html += `<div class="analytics-bar-row"><span class="analytics-bar-label">${escHtml(c.category || '?')}</span><div class="analytics-bar-track"><div class="analytics-bar-fill" style="width:${pct}%"></div></div><span class="analytics-bar-count">${c.count}</span></div>`;
      }
      html += '</div>';
    } else { html += '<div class="empty-state" style="font-size:0.8rem">No category data</div>'; }
    html += '</div>';

    // Sources
    html += '<div class="analytics-card"><h4>Alert Sources</h4>';
    if (proto.sources?.length) {
      html += '<div class="analytics-bars">';
      const maxS = proto.sources[0]?.count || 1;
      for (const s of proto.sources) {
        const pct = Math.round((s.count / maxS) * 100);
        html += `<div class="analytics-bar-row"><span class="analytics-bar-label">${escHtml(s.source || '?')}</span><div class="analytics-bar-track"><div class="analytics-bar-fill" style="width:${pct}%"></div></div><span class="analytics-bar-count">${s.count}</span></div>`;
      }
      html += '</div>';
    } else { html += '<div class="empty-state" style="font-size:0.8rem">No source data</div>'; }
    html += '</div>';

    // DNS analytics
    html += '<div class="analytics-card" style="grid-column: span 2"><h4>DNS Analytics</h4>';
    html += `<div style="display:flex;gap:1.5rem;margin-bottom:0.5rem;font-size:0.85rem">
      <span>DNS alerts: <strong>${dns.dns_alert_count}</strong></span>
      <span>DGA suspects: <strong>${dns.dga_suspect_count}</strong></span>
    </div>`;
    if (dns.top_dns_alerts?.length) {
      html += '<table class="analytics-table"><thead><tr><th>Alert</th><th>Count</th></tr></thead><tbody>';
      for (const d of dns.top_dns_alerts.slice(0, 10)) {
        html += `<tr><td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(d.title || '')}</td><td>${d.count}</td></tr>`;
      }
      html += '</tbody></table>';
    }
    html += '</div>';

    html += '</div>';
    grid.innerHTML = html;
  } catch (err) {
    grid.innerHTML = `<div class="empty-state" style="padding:0.5rem">Failed: ${escHtml(err.message)}</div>`;
  }
}

// ── DHCP Lease History Panel ─────────────────────────────────────────────

function toggleDhcp() {
  const body = document.getElementById('dhcp-body');
  const toggle = document.getElementById('dhcp-toggle');
  if (!body) return;
  if (body.style.display === 'none') {
    body.style.display = '';
    if (toggle) toggle.textContent = 'Hide';
  } else {
    body.style.display = 'none';
    if (toggle) toggle.textContent = 'Show';
  }
}

async function loadDhcpHistory() {
  const content = document.getElementById('dhcp-content');
  if (!content) return;
  const ip = document.getElementById('dhcp-filter-ip')?.value.trim() || '';
  const mac = document.getElementById('dhcp-filter-mac')?.value.trim() || '';
  let qs = '?limit=100';
  if (ip) qs += `&ip=${encodeURIComponent(ip)}`;
  if (mac) qs += `&mac=${encodeURIComponent(mac)}`;

  content.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.85rem">Loading...</div>';

  try {
    const res = await fetch(`/api/dhcp${qs}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const leases = data.leases || [];

    if (!leases.length) {
      content.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.85rem">No DHCP lease history found.</div>';
      return;
    }

    let html = `<table class="analytics-table"><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Interface</th><th>Type</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody>`;
    for (const l of leases) {
      html += `<tr>
        <td>${escHtml(l.ip)}</td>
        <td style="font-family:monospace;font-size:0.75rem">${escHtml(l.mac)}</td>
        <td>${escHtml(l.hostname || '-')}</td>
        <td>${escHtml(l.interface || '-')}</td>
        <td>${escHtml(l.lease_type || '-')}</td>
        <td>${fmtRelative(l.first_seen)}</td>
        <td>${fmtRelative(l.last_seen)}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    content.innerHTML = html;
  } catch (err) {
    content.innerHTML = `<div class="empty-state" style="padding:0.5rem">Failed: ${escHtml(err.message)}</div>`;
  }
}

async function loadDhcpChanges() {
  const content = document.getElementById('dhcp-content');
  if (!content) return;
  content.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.85rem">Checking for IP address changes...</div>';

  try {
    const res = await fetch('/api/dhcp/changes?days=7');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const changes = data.changes || [];

    if (!changes.length) {
      content.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.85rem">No IP-to-MAC changes detected in the last 7 days. All clear.</div>';
      return;
    }

    let html = `<div style="margin-bottom:0.5rem;font-size:0.8rem;color:var(--danger)">Warning: ${changes.length} IP(s) have had multiple MAC addresses - possible IP spoofing or DHCP conflicts.</div>`;
    html += `<table class="analytics-table"><thead><tr><th>IP</th><th>MAC Count</th><th>MAC Addresses</th><th>Hostnames</th></tr></thead><tbody>`;
    for (const c of changes) {
      html += `<tr>
        <td>${escHtml(c.ip)}</td>
        <td style="color:var(--danger);font-weight:600">${c.mac_count}</td>
        <td style="font-family:monospace;font-size:0.75rem">${escHtml(c.macs || '')}</td>
        <td>${escHtml(c.hostnames || '-')}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    content.innerHTML = html;
  } catch (err) {
    content.innerHTML = `<div class="empty-state" style="padding:0.5rem">Failed: ${escHtml(err.message)}</div>`;
  }
}

// ── IP Blocking (pfSense) ────────────────────────────────────────────────

async function blockIp(ip, reason) {
  if (!ip) return;
  if (!confirm(`Block IP ${ip} on the firewall?\n\nReason: ${reason || 'Manual block'}\n\nThis will add the IP to the pfSense blocklist.`)) return;

  try {
    const res = await fetch('/api/firewall/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason: reason || 'Blocked from Shallots dashboard' }),
    });
    const data = await res.json();
    if (data.ok) {
      toast(`IP ${ip} blocked on firewall`, 'success');
    } else {
      toast(`Block failed: ${data.error}`, 'error');
    }
  } catch (err) {
    toast(`Block failed: ${err.message}`, 'error');
  }
}

// ── TLS Certificate Monitor ──────────────────────────────────────────────

function toggleTls() {
  const body = document.getElementById('tls-body');
  const toggle = document.getElementById('tls-toggle');
  if (!body) return;
  if (body.style.display === 'none') {
    body.style.display = '';
    if (toggle) toggle.textContent = 'Hide';
    loadTlsCerts();
  } else {
    body.style.display = 'none';
    if (toggle) toggle.textContent = 'Show';
  }
}

async function loadTlsCerts() {
  const content = document.getElementById('tls-content');
  if (!content) return;
  try {
    const res = await fetch('/api/tls-certs');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const certs = data.certs || [];
    if (!certs.length) {
      content.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.85rem">No TLS certificates monitored. Configure targets in config.yaml under tls_monitor.targets.</div>';
      return;
    }
    let html = '<table class="analytics-table"><thead><tr><th>Host</th><th>Port</th><th>Subject</th><th>Issuer</th><th>Expires</th><th>Days Left</th><th>Status</th></tr></thead><tbody>';
    for (const c of certs) {
      const statusClass = c.days_remaining <= 7 ? 'color:var(--danger);font-weight:700' :
                          c.days_remaining <= 30 ? 'color:var(--warning, orange);font-weight:600' :
                          'color:var(--success, #4caf50)';
      const statusLabel = c.days_remaining <= 0 ? 'EXPIRED' :
                          c.days_remaining <= 7 ? 'CRITICAL' :
                          c.days_remaining <= 30 ? 'WARNING' : 'OK';
      html += `<tr>
        <td>${escHtml(c.host)}</td>
        <td>${c.port}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${escHtml(c.subject || '')}</td>
        <td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;font-size:0.75rem">${escHtml(c.issuer || '')}</td>
        <td style="font-size:0.75rem">${c.not_after || '-'}</td>
        <td style="${statusClass}">${c.days_remaining}</td>
        <td><span class="sev-pill sev-${statusLabel === 'OK' ? 'low' : statusLabel === 'WARNING' ? 'medium' : 'critical'}" style="font-size:0.65rem">${statusLabel}</span></td>
      </tr>`;
    }
    html += '</tbody></table>';
    content.innerHTML = html;
  } catch (err) {
    content.innerHTML = `<div class="empty-state" style="padding:0.5rem">Failed: ${escHtml(err.message)}</div>`;
  }
}

// ── IoC Feed Panel ──────────────────────────────────────────────────────

function toggleIoc() {
  const body = document.getElementById('ioc-body');
  const toggle = document.getElementById('ioc-toggle');
  if (!body) return;
  if (body.style.display === 'none') {
    body.style.display = '';
    if (toggle) toggle.textContent = 'Hide';
    loadIocStats();
  } else {
    body.style.display = 'none';
    if (toggle) toggle.textContent = 'Show';
  }
}

async function loadIocStats() {
  const content = document.getElementById('ioc-content');
  if (!content) return;
  try {
    const res = await fetch('/api/ioc/stats');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const feeds = data.feeds || [];
    if (!feeds.length) {
      content.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.85rem">No IoC feeds loaded. Enable ioc_feeds in config.yaml.</div>';
      return;
    }
    let html = '<table class="analytics-table"><thead><tr><th>Feed</th><th>Type</th><th>Indicators</th></tr></thead><tbody>';
    let total = 0;
    for (const f of feeds) {
      html += `<tr><td>${escHtml(f.feed_name)}</td><td>${escHtml(f.indicator_type || '')}</td><td>${f.count}</td></tr>`;
      total += f.count || 0;
    }
    html += '</tbody></table>';
    html += `<div style="margin-top:0.5rem;font-size:0.8rem;color:var(--text-muted)">Total indicators: ${total}</div>`;
    content.innerHTML = html;
  } catch (err) {
    content.innerHTML = `<div class="empty-state" style="padding:0.5rem">Failed: ${escHtml(err.message)}</div>`;
  }
}

async function checkIoc() {
  const input = document.getElementById('ioc-check-input');
  const resultDiv = document.getElementById('ioc-check-result');
  if (!input || !resultDiv) return;
  const value = input.value.trim();
  if (!value) { toast('Enter an IP or domain to check', 'error'); return; }

  resultDiv.style.display = 'block';
  resultDiv.textContent = 'Checking...';

  try {
    const res = await fetch(`/api/ioc/check/${encodeURIComponent(value)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const matches = data.matches || [];
    if (!matches.length) {
      resultDiv.innerHTML = `<span style="color:var(--success, #4caf50)">Clean - "${escHtml(value)}" not found in any threat feed.</span>`;
    } else {
      resultDiv.innerHTML = `<span style="color:var(--danger);font-weight:600">MATCH - "${escHtml(value)}" found in ${matches.length} feed(s): ${matches.map(m => escHtml(m.feed_name)).join(', ')}</span>`;
    }
  } catch (err) {
    resultDiv.innerHTML = `<span style="color:var(--danger)">Check failed: ${escHtml(err.message)}</span>`;
  }
}

async function refreshIocFeeds() {
  try {
    const res = await fetch('/api/ioc/refresh', { method: 'POST' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    toast(`Feeds refreshed: ${data.total_indicators || 0} indicators loaded`, 'success');
    loadIocStats();
  } catch (err) {
    toast(`Refresh failed: ${err.message}`, 'error');
  }
}

// ── Vulnerability-Exploit Correlation Panel ─────────────────────────────

function toggleVulnCorr() {
  const body = document.getElementById('vuln-corr-body');
  const toggle = document.getElementById('vuln-corr-toggle');
  if (!body) return;
  if (body.style.display === 'none') {
    body.style.display = '';
    if (toggle) toggle.textContent = 'Hide';
    loadVulnCorrelation();
  } else {
    body.style.display = 'none';
    if (toggle) toggle.textContent = 'Show';
  }
}

async function loadVulnCorrelation() {
  const content = document.getElementById('vuln-corr-content');
  if (!content) return;
  try {
    const res = await fetch('/api/vulnerabilities/correlation');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const corrs = data.correlations || [];
    if (!corrs.length) {
      content.innerHTML = '<div class="empty-state" style="padding:0.5rem;font-size:0.85rem">No vulnerability-exploit correlations found. This compares Wazuh CVE data with Suricata exploit alerts.</div>';
      return;
    }
    let html = `<div style="margin-bottom:0.5rem;font-size:0.8rem;color:var(--text-muted)">${data.total} correlation(s), ${data.hosts_with_active_exploits} host(s) with active exploits</div>`;
    html += '<table class="analytics-table"><thead><tr><th>Host</th><th>CVE</th><th>Vuln Alerts</th><th>Exploit Alerts</th><th>Severity</th><th>Risk</th><th>Last Seen</th></tr></thead><tbody>';
    for (const c of corrs) {
      const riskStyle = c.risk_level === 'critical' ? 'color:var(--danger);font-weight:700' :
                        c.risk_level === 'high' ? 'color:var(--warning, orange);font-weight:600' :
                        'color:var(--text-muted)';
      html += `<tr>
        <td>${escHtml(c.host_ip || '')}</td>
        <td style="font-family:monospace;font-size:0.75rem">${escHtml(c.cve_id || '')}</td>
        <td>${c.wazuh_alert_count || 0}</td>
        <td>${c.suricata_alert_count || 0}</td>
        <td><span class="sev-pill sev-${c.severity || 'medium'}" style="font-size:0.65rem">${c.severity || '?'}</span></td>
        <td style="${riskStyle}">${(c.risk_level || '').toUpperCase()}</td>
        <td style="font-size:0.75rem">${c.last_seen ? fmtRelative(c.last_seen) : '-'}</td>
      </tr>`;
    }
    html += '</tbody></table>';
    content.innerHTML = html;
  } catch (err) {
    content.innerHTML = `<div class="empty-state" style="padding:0.5rem">Failed: ${escHtml(err.message)}</div>`;
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  // Fetch server capabilities before init - adapts UI to hardware tier
  try {
    const resp = await fetch('/api/health');
    const health = await resp.json();
    state.capabilities = health.threat_engine || {};
    state.capabilities.profile = health.profile || '';
    state.aiTier = health.ai_tier || 'none';
  } catch {
    state.capabilities = {};
  }
  adaptUiToCapabilities();

  init();
  initJttw();
  initAiPanel();
  // Load new panels
  loadAssets();
  setInterval(loadAssets, 120000);
});

/**
 * Hide UI panels for features that are disabled on this server.
 * Called once at boot after fetching /api/health.
 */
function adaptUiToCapabilities() {
  const cap = state.capabilities || {};
  const tier = cap.tier || 'mid';

  // Threat engine panels - hide if module is off
  if (!cap.baselines && !cap.graph && !cap.ml_detector && !cap.killchain) {
    // Entire threat engine is off - hide ML card, MITRE, topology link
    const mlCard = document.querySelector('[onclick*="/ml"]');
    if (mlCard) mlCard.style.display = 'none';
    const topoCard = document.querySelector('[onclick*="/topology"]');
    if (topoCard) topoCard.style.display = 'none';
    const mitreSection = $('mitre-section');
    if (mitreSection) mitreSection.style.display = 'none';
  }

  // Hide agent panels if no agents configured
  // (they auto-show when agents connect, so just leave as-is)

  // On pi tier, reduce polling frequency to save CPU
  if (tier === 'pi') {
    // Stats every 30s instead of 10s
    if (state.statsInterval) clearInterval(state.statsInterval);
    state.statsInterval = setInterval(fetchStats, 30000);
  }
}
