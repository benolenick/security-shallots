/**
 * Security Shallots - Setup Guide
 * Tab-based onboarding overlay: Get Started, Agents, Manage, Troubleshoot.
 * Pattern: standalone overlay module (matches wiki.js).
 */

'use strict';

// ── State ────────────────────────────────────────────────────────────────────

const setupState = {
  activeTab: 'start',
  platform: null,   // 'linux' | 'windows' | null
  agents: [],
};

const SETUP_TABS = [
  { id: 'start',        label: 'Get Started',   icon: '&#9889;' },
  { id: 'agents',       label: 'Agents',        icon: '&#128737;' },
  { id: 'manage',       label: 'Manage',        icon: '&#128736;' },
  { id: 'troubleshoot', label: 'Troubleshoot',  icon: '&#128269;' },
];

// ── Helpers ──────────────────────────────────────────────────────────────────

function getServerIP() {
  return location.hostname || 'YOUR_SERVER_IP';
}

// Capabilities fetched from /api/health on page load (set by app.js)
function getCapabilities() {
  return (window.state && window.state.capabilities) || {};
}

function isWazuhEnabled() {
  // Check if the server has Wazuh component enabled
  const cap = getCapabilities();
  const profile = cap.profile || '';
  // Wazuh is only enabled on standard/full profiles
  return profile === 'standard' || profile === 'full' || !profile;
}

function getRepoUrl() {
  // Base URL for agent installer downloads - override via config if forked
  return '${getRepoUrl()}';
}

function setupCopyBtnRaw() {
  return `<button class="setup-copy" onclick="setupCopyCode(this)">Copy</button>`;
}

window.setupCopyCode = function(btn) {
  const code = btn.parentElement.querySelector('code');
  if (!code) return;
  const text = code.textContent.replace(/YOUR_SERVER_IP/g, getServerIP());
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  });
};

// ── Open / Close ─────────────────────────────────────────────────────────────

function openSetup(tab) {
  if (tab) setupState.activeTab = tab;
  const overlay = document.getElementById('setup-overlay');
  overlay.style.display = 'block';
  document.body.style.overflow = 'hidden';
  renderSetupTab(setupState.activeTab);
}

function closeSetup() {
  const overlay = document.getElementById('setup-overlay');
  overlay.style.display = 'none';
  document.body.style.overflow = '';
}

// ── Tab Navigation ───────────────────────────────────────────────────────────

function setupSwitchTab(tabId) {
  setupState.activeTab = tabId;
  renderSetupTab(tabId);
}

// ── Render ───────────────────────────────────────────────────────────────────

function renderSetupTab(tabId) {
  // Tab bar
  const tabBar = document.getElementById('setup-tabs');
  tabBar.innerHTML = SETUP_TABS.map(t => {
    const cls = t.id === tabId ? 'active' : '';
    return `<button class="setup-tab ${cls}" onclick="setupSwitchTab('${t.id}')">
      <span class="setup-tab-icon">${t.icon}</span>
      <span class="setup-tab-label">${t.label}</span>
    </button>`;
  }).join('');

  // Body
  const body = document.getElementById('setup-body');
  const renderers = {
    'start': renderTabStart,
    'agents': renderTabAgents,
    'manage': renderTabManage,
    'troubleshoot': renderTabTroubleshoot,
  };
  body.innerHTML = (renderers[tabId] || renderTabStart)();
  body.scrollTop = 0;

  // If agents tab, kick off fetch
  if (tabId === 'agents') fetchSetupAgents();
}

// ── Tab: Get Started ─────────────────────────────────────────────────────────

function renderTabStart() {
  return `
    <h3 class="setup-title">Welcome to Security Shallots</h3>
    <p class="setup-text">
      Security Shallots watches your network and endpoints for threats, then uses AI
      to triage what it finds so you only deal with what matters.
    </p>

    <div class="setup-features">
      <div class="setup-feature-card">
        <div class="setup-feature-icon">&#128737;</div>
        <div class="setup-feature-title">Agents Watch</div>
        <div class="setup-feature-desc">Small agents run on your machines, monitoring logs, logins, file changes, and network traffic.</div>
      </div>
      <div class="setup-feature-card">
        <div class="setup-feature-icon">&#128680;</div>
        <div class="setup-feature-title">Alerts Flow In</div>
        <div class="setup-feature-desc">When something suspicious happens, the agent sends an alert to this dashboard in real time.</div>
      </div>
      <div class="setup-feature-card">
        <div class="setup-feature-icon">&#129302;</div>
        <div class="setup-feature-title">AI Triages</div>
        <div class="setup-feature-desc">AI reviews each alert automatically &mdash; classifying severity, filtering noise, and flagging real threats.</div>
      </div>
      <div class="setup-feature-card">
        <div class="setup-feature-icon">&#9989;</div>
        <div class="setup-feature-title">You Handle It</div>
        <div class="setup-feature-desc">You review the important stuff. Suppress noise, investigate suspicious activity, or escalate threats.</div>
      </div>
    </div>

    <div class="setup-callout info">
      <strong>~5 minutes per machine.</strong> That's all it takes to install an agent and start seeing alerts.
    </div>

    <div style="margin-top:1rem">
      <button class="btn btn-primary" onclick="setupSwitchTab('agents')">Deploy Your First Agent &rarr;</button>
    </div>

    <div class="setup-section-divider"></div>

    <h4 class="setup-subtitle">What gets installed?</h4>
    <table class="help-table">
      <tr>
        <td></td>
        <td style="text-align:center"><strong>Clove</strong></td>
        <td style="text-align:center"><strong>Argus</strong></td>
      </tr>
      <tr><td>Log analysis</td><td style="text-align:center;color:var(--sev-low)">&#10003;</td><td style="text-align:center;color:var(--sev-low)">&#10003;</td></tr>
      <tr><td>File integrity monitoring</td><td style="text-align:center;color:var(--sev-low)">&#10003;</td><td style="text-align:center;color:var(--sev-low)">&#10003;</td></tr>
      <tr><td>Rootkit detection</td><td style="text-align:center;color:var(--sev-low)">&#10003;</td><td style="text-align:center;color:var(--text-muted)">&mdash;</td></tr>
      <tr><td>Credential monitoring</td><td style="text-align:center;color:var(--text-muted)">&mdash;</td><td style="text-align:center;color:var(--sev-low)">&#10003;</td></tr>
      <tr><td>RDP / session tracking</td><td style="text-align:center;color:var(--text-muted)">&mdash;</td><td style="text-align:center;color:var(--sev-low)">&#10003;</td></tr>
      <tr><td>Evidence capture &amp; USB</td><td style="text-align:center;color:var(--text-muted)">&mdash;</td><td style="text-align:center;color:var(--sev-low)">&#10003;</td></tr>
      <tr><td>Linux</td><td style="text-align:center;color:var(--sev-low)">&#10003;</td><td style="text-align:center;color:var(--text-muted)">&mdash;</td></tr>
      <tr><td>Windows</td><td style="text-align:center;color:var(--sev-low)">&#10003;</td><td style="text-align:center;color:var(--sev-low)">&#10003;</td></tr>
    </table>
    <p class="setup-text" style="margin-top:0.5rem;color:var(--text-muted);font-size:0.8rem">
      Linux gets <strong>Clove</strong> (Wazuh-based). Windows gets <strong>Argus</strong> by default &mdash;
      a state-machine sentinel with file integrity monitoring, session tracking,
      persistence detection, and forensic evidence capture. Add optional Clove for maximum coverage.
    </p>
  `;
}

// ── Tab: Agents (hub - fleet status + install) ───────────────────────────────

function renderTabAgents() {
  const ip = getServerIP();
  const linuxActive = setupState.platform === 'linux' ? 'active' : '';
  const windowsActive = setupState.platform === 'windows' ? 'active' : '';

  let installSection = '';
  if (setupState.platform === 'linux') {
    installSection = renderInstallLinux(ip);
  } else if (setupState.platform === 'windows') {
    installSection = renderInstallWindows(ip);
  }

  return `
    <div class="setup-agents-top">
      <h3 class="setup-title" style="margin-bottom:0.25rem">Your Agents</h3>
      <button class="btn" onclick="fetchSetupAgents()" style="font-size:0.75rem;padding:0.25rem 0.6rem">Refresh</button>
    </div>
    <div id="setup-agents-list">
      <div class="empty-state" style="padding:1rem"><span class="loading-spinner"></span> Loading&hellip;</div>
    </div>

    <div class="setup-section-divider"></div>

    <h3 class="setup-title">Deploy a New Agent</h3>
    <p class="setup-text">
      Pick the OS of the machine you want to protect.
    </p>

    <div class="setup-platform-grid">
      <button class="setup-platform-card ${linuxActive}" onclick="setupSelectPlatform('linux')">
        <div class="setup-platform-icon">&#128039;</div>
        <div class="setup-platform-name">Linux</div>
        <div class="setup-platform-desc">Ubuntu, Debian, CentOS, RHEL, Fedora, Rocky, Alma</div>
        <div class="setup-platform-agents">Installs: <strong>Clove</strong> (Wazuh agent)</div>
      </button>
      <button class="setup-platform-card ${windowsActive}" onclick="setupSelectPlatform('windows')">
        <div class="setup-platform-icon">&#128187;</div>
        <div class="setup-platform-name">Windows</div>
        <div class="setup-platform-desc">Windows 10, 11, Server 2016+</div>
        <div class="setup-platform-agents">Installs: <strong>Argus</strong> sentinel (+ optional Clove)</div>
      </button>
    </div>

    ${installSection}

    ${setupState.platform ? renderVerifySection() : ''}
  `;
}

function renderInstallLinux(ip) {
  const repo = getRepoUrl();
  const wazuh = isWazuhEnabled();

  if (!wazuh) {
    return `
    <div class="setup-install-block" id="setup-install-block">
      <h4 class="setup-subtitle">Install on Linux</h4>

      <div class="setup-callout warning">
        <strong>Wazuh is not enabled on this server</strong> (profile: ${getCapabilities().profile || 'lite/micro'}).
        The Linux agent (Clove) requires Wazuh Manager. To use Clove, switch to the <code>standard</code> or <code>full</code> profile and install Wazuh Manager.
      </div>

      <p class="setup-text">
        Without Wazuh, Linux machines can still send alerts via <strong>syslog</strong>.
        Configure rsyslog on each machine to forward to this server:
      </p>

      <div class="setup-cmd-label">On each Linux machine, add to /etc/rsyslog.d/shallots.conf:</div>
      <div class="setup-cmd">
        <code>*.* @${ip}:5514</code>
        ${setupCopyBtnRaw()}
      </div>
      <div class="setup-cmd-label">Then restart rsyslog:</div>
      <div class="setup-cmd">
        <code>sudo systemctl restart rsyslog</code>
        ${setupCopyBtnRaw()}
      </div>

      <div class="setup-callout info" style="margin-top:0.75rem">
        Make sure <code>syslog.enabled: true</code> is set in your config.yaml on the server.
      </div>
    </div>`;
  }

  return `
    <div class="setup-install-block" id="setup-install-block">
      <h4 class="setup-subtitle">Install on Linux</h4>

      <div class="setup-callout info">
        <strong>Prerequisites:</strong> root/sudo access, supported distro (Ubuntu 18+, Debian 10+, CentOS 7+, RHEL 7+, Fedora 33+, Rocky/Alma 8+), network access to ${ip}.
      </div>

      <div class="setup-cmd-label">One-line install (run as root on the endpoint):</div>
      <div class="setup-cmd">
        <code>curl -fsSL ${repo}/setup/endpoint/clove | sudo bash -s -- --manager ${ip}</code>
        ${setupCopyBtnRaw()}
      </div>

      <details class="setup-faq" style="margin-top:0.75rem">
        <summary>What happens after you run this?</summary>
        <div class="setup-faq-body">
          <div class="setup-timeline">
            <div class="setup-timeline-item">
              <div class="setup-timeline-dot"></div>
              <div class="setup-timeline-content"><strong>Downloads installer</strong><span>Fetches the Clove bash script (~25 KB) from GitHub</span></div>
            </div>
            <div class="setup-timeline-item">
              <div class="setup-timeline-dot"></div>
              <div class="setup-timeline-content"><strong>Installs Wazuh agent</strong><span>Adds the Wazuh APT/YUM repo and installs the agent package (~15 MB)</span></div>
            </div>
            <div class="setup-timeline-item">
              <div class="setup-timeline-dot"></div>
              <div class="setup-timeline-content"><strong>Configures &amp; registers</strong><span>Points the agent at ${ip}, enrolls with the Wazuh Manager</span></div>
            </div>
            <div class="setup-timeline-item">
              <div class="setup-timeline-dot"></div>
              <div class="setup-timeline-content"><strong>Deploys watchdog</strong><span>Installs clove-watchdog for SSH brute force detection, baseline monitoring, suspicious process alerts</span></div>
            </div>
            <div class="setup-timeline-item">
              <div class="setup-timeline-dot"></div>
              <div class="setup-timeline-content"><strong>Starts as systemd service</strong><span>wazuh-agent runs at boot &mdash; alerts flow to this dashboard within minutes</span></div>
            </div>
          </div>
        </div>
      </details>

      <details class="setup-faq">
        <summary>Install options</summary>
        <div class="setup-faq-body">
          <table class="help-table">
            <tr><td><code>--manager IP</code></td><td>Server IP (required, auto-filled above)</td></tr>
            <tr><td><code>--name NAME</code></td><td>Agent display name (defaults to hostname)</td></tr>
            <tr><td><code>--group GROUP</code></td><td>Wazuh agent group (default: <code>default</code>)</td></tr>
            <tr><td><code>--password PW</code></td><td>Wazuh registration password</td></tr>
            <tr><td><code>--crowdsec</code></td><td>Also install CrowdSec + iptables bouncer</td></tr>
            <tr><td><code>--uninstall</code></td><td>Remove the agent completely</td></tr>
          </table>
        </div>
      </details>
    </div>
  `;
}

function renderInstallWindows(ip) {
  return `
    <div class="setup-install-block" id="setup-install-block">
      <h4 class="setup-subtitle">Install on Windows</h4>

      <div class="setup-callout info">
        <strong>Prerequisites:</strong> Administrator PowerShell, Windows 10/11/Server 2016+, network access to ${ip}.
      </div>

      <div class="setup-cmd-label">One-liner (downloads and runs everything):</div>
      <div class="setup-cmd">
        <code>irm ${getRepoUrl()}/setup/endpoint/clove.ps1 | iex</code>
        ${setupCopyBtnRaw()}
      </div>

      <div class="setup-cmd-label">Or download first, then run:</div>
      <div class="setup-cmd">
        <code>.\\clove.ps1 -Manager ${ip}</code>
        ${setupCopyBtnRaw()}
      </div>

      <div class="setup-cmd-label">With both Argus + Clove (maximum protection):</div>
      <div class="setup-cmd">
        <code>.\\clove.ps1 -Manager ${ip} -Wazuh</code>
        ${setupCopyBtnRaw()}
      </div>

      <details class="setup-faq" style="margin-top:0.75rem">
        <summary>What happens after you run this?</summary>
        <div class="setup-faq-body">
          <div class="setup-timeline">
            <div class="setup-timeline-item">
              <div class="setup-timeline-dot"></div>
              <div class="setup-timeline-content"><strong>Installs Python 3.12 (if needed)</strong><span>~25 MB download, silent install &mdash; skipped if already present</span></div>
            </div>
            <div class="setup-timeline-item">
              <div class="setup-timeline-dot"></div>
              <div class="setup-timeline-content"><strong>Downloads Argus source</strong><span>Clones from GitHub (~50 MB) or downloads as zip if git is unavailable</span></div>
            </div>
            <div class="setup-timeline-item">
              <div class="setup-timeline-dot"></div>
              <div class="setup-timeline-content"><strong>Installs &amp; configures</strong><span>pip install, writes config pointing at ${ip}:8855</span></div>
            </div>
            <div class="setup-timeline-item">
              <div class="setup-timeline-dot"></div>
              <div class="setup-timeline-content"><strong>Registers scheduled tasks</strong><span>Argus-AutoStart (runs at logon) + Argus-Watchdog (restarts if crashed, every 2 min)</span></div>
            </div>
            <div class="setup-timeline-item">
              <div class="setup-timeline-dot"></div>
              <div class="setup-timeline-content"><strong>Starts monitoring</strong><span>Event logs, logins, USB, DNS, file integrity, credential files &mdash; alerts flow here within minutes</span></div>
            </div>
          </div>
        </div>
      </details>

      <details class="setup-faq">
        <summary>Install options</summary>
        <div class="setup-faq-body">
          <table class="help-table">
            <tr><td><code>-Manager IP</code></td><td>Server IP (required)</td></tr>
            <tr><td><code>-Name NAME</code></td><td>Agent display name (defaults to hostname)</td></tr>
            <tr><td><code>-Wazuh</code></td><td>Also install Clove (Wazuh agent)</td></tr>
            <tr><td><code>-WebhookPort 8855</code></td><td>Argus webhook port on server</td></tr>
            <tr><td><code>-WebhookSecret "..."</code></td><td>Shared secret for Argus auth</td></tr>
            <tr><td><code>-WazuhGroup GROUP</code></td><td>Wazuh agent group</td></tr>
            <tr><td><code>-WazuhPassword PW</code></td><td>Wazuh registration password</td></tr>
            <tr><td><code>-Uninstall</code></td><td>Remove everything</td></tr>
          </table>
        </div>
      </details>
    </div>
  `;
}

function renderVerifySection() {
  return `
    <div class="setup-section-divider"></div>
    <h4 class="setup-subtitle">Verify Installation</h4>
    <div class="setup-callout success">
      <strong>After install, you should see:</strong> agent status pill turns green, a new card in Agent Health, and alerts start appearing within a few minutes.
    </div>

    ${setupState.platform === 'linux' ? `
    <div class="setup-cmd-label">On the endpoint &mdash; verify Clove is running:</div>
    <div class="setup-cmd"><code>systemctl status wazuh-agent</code>${setupCopyBtnRaw()}</div>
    <div class="setup-cmd"><code>cat /var/ossec/etc/client.keys</code>${setupCopyBtnRaw()}</div>
    ` : `
    <div class="setup-cmd-label">On the endpoint &mdash; verify agents are running:</div>
    <div class="setup-cmd"><code>Get-Service ArgusAgent</code>${setupCopyBtnRaw()}</div>
    <div class="setup-cmd"><code>Get-Service WazuhSvc</code>${setupCopyBtnRaw()}</div>
    `}

    <div style="margin-top:0.75rem">
      <button class="btn btn-primary" onclick="setupCheckAgents()">Check Now</button>
      <span id="setup-check-result" style="margin-left:0.75rem;font-size:0.8rem;color:var(--text-muted)"></span>
    </div>
  `;
}

// ── Tab: Manage ──────────────────────────────────────────────────────────────

function renderTabManage() {
  return `
    <h3 class="setup-title">Manage Your Agents</h3>
    <p class="setup-text">
      Common commands for managing agents after installation.
    </p>

    <h4 class="setup-subtitle">Linux (Clove / Wazuh Agent)</h4>
    <div class="setup-cmd-label">Check status:</div>
    <div class="setup-cmd"><code>systemctl status wazuh-agent</code>${setupCopyBtnRaw()}</div>
    <div class="setup-cmd-label">Restart agent:</div>
    <div class="setup-cmd"><code>sudo systemctl restart wazuh-agent</code>${setupCopyBtnRaw()}</div>
    <div class="setup-cmd-label">Update agent (re-run installer):</div>
    <div class="setup-cmd">
      <code>curl -fsSL ${getRepoUrl()}/setup/endpoint/clove | sudo bash -s -- --manager ${getServerIP()}</code>
      ${setupCopyBtnRaw()}
    </div>
    <div class="setup-cmd-label">Uninstall:</div>
    <div class="setup-callout warning">This removes the agent and all its data from this endpoint.</div>
    <div class="setup-cmd">
      <code>curl -fsSL ${getRepoUrl()}/setup/endpoint/clove | sudo bash -s -- --uninstall</code>
      ${setupCopyBtnRaw()}
    </div>

    <div class="setup-section-divider"></div>

    <h4 class="setup-subtitle">Windows (Argus + Clove)</h4>
    <div class="setup-cmd-label">Check status:</div>
    <div class="setup-cmd"><code>Get-Service ArgusAgent, WazuhSvc</code>${setupCopyBtnRaw()}</div>
    <div class="setup-cmd-label">Restart agents:</div>
    <div class="setup-cmd"><code>Restart-Service ArgusAgent; Restart-Service WazuhSvc</code>${setupCopyBtnRaw()}</div>
    <div class="setup-cmd-label">Uninstall:</div>
    <div class="setup-callout warning">This removes all agents and their data from this endpoint.</div>
    <div class="setup-cmd"><code>.\\clove.ps1 -Uninstall</code>${setupCopyBtnRaw()}</div>

    <div class="setup-section-divider"></div>

    <h4 class="setup-subtitle">Server-Side</h4>
    <div class="setup-cmd-label">Restart shallotd:</div>
    <div class="setup-cmd"><code>sudo systemctl restart shallotd</code>${setupCopyBtnRaw()}</div>
    <div class="setup-cmd-label">Check health:</div>
    <div class="setup-cmd"><code>sudo bash setup/shallot-doctor check</code>${setupCopyBtnRaw()}</div>
    <div class="setup-cmd-label">Watch live logs:</div>
    <div class="setup-cmd"><code>journalctl -u shallotd -f</code>${setupCopyBtnRaw()}</div>
  `;
}

// ── Tab: Troubleshoot ────────────────────────────────────────────────────────

function renderTabTroubleshoot() {
  return `
    <h3 class="setup-title">Troubleshoot</h3>
    <p class="setup-text">Common issues and how to fix them.</p>

    <details class="setup-faq">
      <summary>Agent not showing up on dashboard</summary>
      <div class="setup-faq-body">
        <ol>
          <li>Wait 2&ndash;3 minutes &mdash; agents check in periodically, not instantly</li>
          <li>Verify the agent is running on the endpoint:
            <br>Linux: <code>systemctl status wazuh-agent</code>
            <br>Windows: <code>Get-Service ArgusAgent</code></li>
          <li>Check the manager IP is correct:
            <br>Linux: <code>grep '&lt;address&gt;' /var/ossec/etc/ossec.conf</code></li>
          <li>Make sure ports <strong>1514</strong> and <strong>1515</strong> are open on this server</li>
          <li>Re-run the installer (it's safe to re-run)</li>
        </ol>
      </div>
    </details>

    <details class="setup-faq">
      <summary>Agent shows "offline" status</summary>
      <div class="setup-faq-body">
        <ol>
          <li>Check if the agent service is still running on the endpoint</li>
          <li>Restart the agent: <code>sudo systemctl restart wazuh-agent</code></li>
          <li>Check network connectivity: <code>nc -z ${getServerIP()} 1514</code></li>
          <li>Check for firewall rules blocking the connection</li>
          <li>Look at agent logs: <code>tail -20 /var/ossec/logs/ossec.log</code></li>
        </ol>
      </div>
    </details>

    <details class="setup-faq">
      <summary>Connection refused errors</summary>
      <div class="setup-faq-body">
        <ol>
          <li>Verify the Wazuh manager is running: <code>systemctl status wazuh-manager</code></li>
          <li>Check that ports are listening: <code>ss -tlnp | grep -E '1514|1515|8855'</code></li>
          <li>Check server firewall: <code>sudo ufw status</code> or <code>sudo iptables -L</code></li>
          <li>For Argus, verify port <strong>8855</strong> is open</li>
        </ol>
      </div>
    </details>

    <details class="setup-faq">
      <summary>No alerts appearing after install</summary>
      <div class="setup-faq-body">
        <ol>
          <li>Agents need something to detect &mdash; try a failed SSH login to trigger an alert</li>
          <li>Check if the "Needs Attention" filter is hiding suppressed alerts (try "All Verdicts")</li>
          <li>Verify ingestion on server: <code>journalctl -u shallotd -f | grep -i ingest</code></li>
          <li>Check enrollment: <code>cat /var/ossec/etc/client.keys</code></li>
          <li>Run diagnostics: <code>sudo bash setup/shallot-doctor check</code></li>
        </ol>
      </div>
    </details>

    <details class="setup-faq">
      <summary>What ports need to be open?</summary>
      <div class="setup-faq-body">
        <table class="help-table">
          <tr><td><strong>8844</strong></td><td>Dashboard (this page)</td><td>Browser &rarr; server</td></tr>
          <tr><td><strong>8855</strong></td><td>Argus webhook</td><td>Windows endpoint &rarr; server</td></tr>
          <tr><td><strong>1514</strong></td><td>Wazuh events</td><td>Clove agent &rarr; server</td></tr>
          <tr><td><strong>1515</strong></td><td>Wazuh enrollment</td><td>Agent registration</td></tr>
        </table>
        <p style="margin-top:0.5rem;font-size:0.8rem;color:var(--text-muted)">
          Only open ports for the agents you're using. Linux (Clove) needs 1514+1515.
          Windows (Argus) needs 8855.
        </p>
      </div>
    </details>

    <details class="setup-faq">
      <summary>TLS certificate expired</summary>
      <div class="setup-faq-body">
        <div class="setup-cmd"><code>sudo bash setup/shallot-doctor fix-tls</code>${setupCopyBtnRaw()}</div>
        <div class="setup-cmd"><code>sudo systemctl restart shallotd</code>${setupCopyBtnRaw()}</div>
      </div>
    </details>

    <details class="setup-faq">
      <summary>Dashboard not loading</summary>
      <div class="setup-faq-body">
        <ol>
          <li>Confirm service: <code>systemctl is-active shallotd</code></li>
          <li>Confirm port: <code>ss -tlnp | grep 8844</code></li>
          <li>If HTTPS, must use <code>https://</code> and accept self-signed cert</li>
          <li>Check auth: credentials in <code>config.yaml</code> under <code>web:</code></li>
        </ol>
      </div>
    </details>
  `;
}

// ── Agent Fetching ───────────────────────────────────────────────────────────

async function fetchSetupAgents() {
  try {
    const res = await fetch('/api/agents');
    const data = await res.json();
    setupState.agents = data.agents || [];
    renderSetupAgentsList();
  } catch (e) {
    const el = document.getElementById('setup-agents-list');
    if (el) el.innerHTML = '<div class="setup-callout warning">Failed to load agents. Check your connection.</div>';
  }
}

function renderSetupAgentsList() {
  const el = document.getElementById('setup-agents-list');
  if (!el) return;

  if (!setupState.agents.length) {
    el.innerHTML = `
      <div class="setup-empty-agents">
        <span style="font-size:1.25rem;opacity:0.4">&#128737;</span>
        <span>No agents deployed yet.</span>
        <span style="color:var(--text-muted)">Pick a platform below to install your first one.</span>
      </div>
    `;
    return;
  }

  el.innerHTML = setupState.agents.map(a => {
    const online = a.status === 'online';
    const dotCls = online ? 'green' : 'red';
    const statusText = online ? 'Online' : 'Offline';
    const statusCls = online ? 'color:var(--sev-low)' : 'color:var(--sev-critical)';
    return `
      <div class="setup-agent-card">
        <div class="setup-agent-header">
          <span class="agent-pill-dot ${dotCls}" style="width:10px;height:10px"></span>
          <strong>${escapeHtml(a.name || a.agent_id || 'Unknown')}</strong>
          <span style="margin-left:auto;font-size:0.78rem;${statusCls}">${statusText}</span>
        </div>
        <div class="setup-agent-meta">
          ${a.agent_type ? `<span>Type: ${escapeHtml(a.agent_type)}</span>` : ''}
          ${a.os ? `<span>OS: ${escapeHtml(a.os)}</span>` : ''}
          ${a.ip ? `<span>IP: ${escapeHtml(a.ip)}</span>` : ''}
          ${a.last_seen ? `<span>Last seen: ${new Date(a.last_seen).toLocaleString()}</span>` : ''}
        </div>
      </div>
    `;
  }).join('');
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Check Now ────────────────────────────────────────────────────────────────

window.setupCheckAgents = async function() {
  const el = document.getElementById('setup-check-result');
  if (el) el.innerHTML = '<span class="loading-spinner"></span> Checking...';
  try {
    const res = await fetch('/api/agents');
    const data = await res.json();
    const agents = data.agents || [];
    const online = agents.filter(a => a.status === 'online').length;
    if (el) {
      if (agents.length === 0) {
        el.innerHTML = '<span style="color:var(--sev-medium)">No agents found yet. Install one first!</span>';
      } else {
        el.innerHTML = `<span style="color:var(--sev-low)">${online} of ${agents.length} agent(s) online</span>`;
      }
    }
  } catch {
    if (el) el.innerHTML = '<span style="color:var(--sev-critical)">Failed to check. Is the server running?</span>';
  }
};

// ── Platform Selection ───────────────────────────────────────────────────────

window.setupSelectPlatform = function(platform) {
  setupState.platform = platform;
  renderSetupTab('agents');
  // Scroll to install block
  setTimeout(() => {
    const block = document.getElementById('setup-install-block');
    if (block) block.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 50);
};

// ── Expose globals (like wiki.js pattern) ────────────────────────────────────

window.openSetup = openSetup;
window.closeSetup = closeSetup;
window.setupSwitchTab = setupSwitchTab;
