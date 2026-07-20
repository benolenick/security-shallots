#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Clove - Security Shallots Windows Endpoint Installer
.DESCRIPTION
    One-command deployment of Argus (Python endpoint monitor) + optional Wazuh agent (Clove).
    Configures webhook reporting to a central shallotd server.
.EXAMPLE
    # Minimal - Argus only:
    .\clove.ps1 -Manager <manager-ip>

    # Full - Argus + Clove (Wazuh agent):
    .\clove.ps1 -Manager <manager-ip> -Wazuh

    # Or via IEX one-liner (run as admin):
    irm https://raw.githubusercontent.com/benolenick/security-shallots/main/setup/endpoint/clove.ps1 | iex
.PARAMETER Manager
    IP address of the shallotd/Wazuh manager server (required).
.PARAMETER Name
    Agent display name. Defaults to hostname.
.PARAMETER WebhookPort
    Port for Argus webhook on the manager. Default: 8855.
.PARAMETER WebhookSecret
    Shared secret for Argus webhook auth (optional).
.PARAMETER Wazuh
    Also install Wazuh agent MSI.
.PARAMETER WazuhGroup
    Wazuh agent group. Default: "default".
.PARAMETER WazuhPassword
    Wazuh authd registration password (optional).
.PARAMETER Uninstall
    Remove all endpoint agents.
.PARAMETER SkipHealthcheck
    Skip post-install connectivity checks.
#>
[CmdletBinding()]
param(
    [string]$Manager,
    [string]$Name = $env:COMPUTERNAME,
    [int]$WebhookPort = 8855,
    [string]$WebhookSecret = "",
    [switch]$Wazuh,
    [string]$WazuhGroup = "default",
    [string]$WazuhPassword = "",
    [switch]$Uninstall,
    [switch]$SkipHealthcheck
)

$ErrorActionPreference = "Stop"

# ── Colors ────────────────────────────────────────────────────
function Write-Ok   { param($m) Write-Host "  [OK]  $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "  [!!]  $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "  [XX]  $m" -ForegroundColor Red }
function Write-Info { param($m) Write-Host "  [>>]  $m" -ForegroundColor Cyan }
function Write-Step { param($m) Write-Host "`n━━━ $m" -ForegroundColor Cyan }

# ── Banner ────────────────────────────────────────────────────
function Show-Banner {
    Write-Host @"

    ____ _
   / ___| | _____   _____
  | |   | |/ _ \ \ / / _ \
  | |___| | (_) \ V /  __/
   \____|_|\___/ \_/ \___|
   Security Shallots - Windows Endpoint

"@ -ForegroundColor Yellow
}

# ── Resolve manager IP ────────────────────────────────────────
function Resolve-Manager {
    if ($Manager) { return $Manager }
    if ($env:SHALLOTS_MANAGER_IP) { return $env:SHALLOTS_MANAGER_IP }
    $ip = Read-Host "Enter shallotd manager IP"
    if (-not $ip) { Write-Err "Manager IP is required"; exit 1 }
    return $ip
}

# ── Find Python ───────────────────────────────────────────────
function Find-Python {
    # Try common locations
    $candidates = @(
        (Get-Command python -ErrorAction SilentlyContinue).Source,
        (Get-Command python3 -ErrorAction SilentlyContinue).Source,
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "C:\Python313\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($py in $candidates) {
        $ver = & $py --version 2>&1
        if ($ver -match "Python 3\.1[0-9]") {
            return $py
        }
    }
    return $null
}

# ── Install Python if missing ─────────────────────────────────
function Install-Python {
    Write-Step "Installing Python 3.12"
    $installerUrl = "https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe"
    $installer = "$env:TEMP\python-installer.exe"

    Write-Info "Downloading Python installer..."
    Invoke-WebRequest -Uri $installerUrl -OutFile $installer -UseBasicParsing

    Write-Info "Installing Python (this may take a minute)..."
    Start-Process -FilePath $installer -ArgumentList '/quiet', 'InstallAllUsers=0', 'PrependPath=1', 'Include_pip=1' -Wait -NoNewWindow
    Remove-Item $installer -Force -ErrorAction SilentlyContinue

    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "User") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "Machine")

    $py = Find-Python
    if (-not $py) {
        Write-Err "Python installation failed. Install Python 3.10+ manually and re-run."
        exit 1
    }
    Write-Ok "Python installed: $py"
    return $py
}

# ── Clone/update repo ─────────────────────────────────────────
function Get-ArgusSource {
    param([string]$InstallDir)

    if (Test-Path "$InstallDir\argus\pyproject.toml") {
        Write-Info "Argus source exists, updating..."
        $gitExe = (Get-Command git -ErrorAction SilentlyContinue).Source
        if ($gitExe) {
            Push-Location $InstallDir
            & git pull --ff-only 2>$null
            Pop-Location
        }
        return
    }

    $gitExe = (Get-Command git -ErrorAction SilentlyContinue).Source
    if ($gitExe) {
        Write-Info "Cloning security-shallots repository..."
        & git clone --depth 1 https://github.com/benolenick/security-shallots.git $InstallDir
    } else {
        Write-Info "Git not found, downloading as zip..."
        $zip = "$env:TEMP\shallots.zip"
        Invoke-WebRequest -Uri "https://github.com/benolenick/security-shallots/archive/refs/heads/main.zip" -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $env:TEMP -Force
        if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
        Move-Item "$env:TEMP\security-shallots-main" $InstallDir
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "Source downloaded to $InstallDir"
}

# ── Configure Argus ───────────────────────────────────────────
function Set-ArgusConfig {
    param([string]$ArgusDir, [string]$ManagerIP, [int]$Port, [string]$Secret, [string]$AgentName)

    $configPath = Join-Path $ArgusDir "config.toml"
    $templatePath = Join-Path $ArgusDir "config.example.toml"

    # Start from template if no config exists
    if (-not (Test-Path $configPath) -and (Test-Path $templatePath)) {
        Copy-Item $templatePath $configPath
    }

    $webhookUrl = "https://${ManagerIP}:${Port}/api/ingest/argus"

    $config = @"
[argus]
hostname = "$AgentName"

[argus.guard]
inactivity_timeout_seconds = 600
heartbeat_seconds = 120

[argus.windows_events]
enabled = true
poll_seconds = 15
watch_event_ids = [4625, 4720, 4728, 4732, 4740, 1102, 4648, 4672, 4688, 4698, 4702, 4719, 4624, 4756, 4757, 4769]

[argus.jsonl]
enabled = true
directory = ".argus/events"

[argus.webhook]
enabled = true
url = "$webhookUrl"
secret = "$Secret"
timeout_seconds = 5

[argus.file_sentinel]
enabled = true
poll_seconds = 5
paths = [
  "%USERPROFILE%\\Documents\\credentials.kdbx",
  "%USERPROFILE%\\.ssh\\id_ed25519",
]

[argus.session_monitor]
enabled = true
poll_seconds = 10
logon_types = [3, 10]

[argus.process_monitor]
enabled = false
poll_seconds = 10
allowlist = [
  "C:\\Windows\\*",
  "C:\\Program Files\\*",
  "C:\\Program Files (x86)\\*",
  "%USERPROFILE%\\AppData\\Local\\Programs\\*",
]
denylist = ["*mimikatz*", "*procdump*", "*rundll32* comsvcs.dll*"]
alert_on_unknown = true

[argus.persistence_monitor]
enabled = false
poll_seconds = 30
watch_paths = []

[argus.anti_tamper]
enabled = true
poll_seconds = 15
watch_files = [".argus/state.json", "config.toml"]
required_tasks = ["Argus-OnLock", "Argus-OnUnlock"]

[argus.usb_monitor]
enabled = true
poll_seconds = 10

[argus.dns_monitor]
enabled = true
poll_seconds = 30
suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".buzz", ".club"]
entropy_threshold = 3.5

[argus.registry_monitor]
enabled = true
poll_seconds = 30

[argus.service_monitor]
enabled = true
poll_seconds = 60

[argus.audit_policy]
enabled = true
poll_seconds = 300

[argus.firewall_monitor]
enabled = true
poll_seconds = 300
suspicious_ports = [4444, 5555, 8888, 9001, 1234, 6666]

[argus.posture_monitor]
enabled = true
poll_seconds = 3600

[argus.browser_extensions]
enabled = true
poll_seconds = 300

[argus.wmi_subs]
enabled = true
poll_seconds = 120

[argus.ads_monitor]
enabled = true
poll_seconds = 300

[argus.sms]
enabled = false
twilio_account_sid = ""
twilio_auth_token = ""
from_number = ""
to_number = ""

[argus.syslog]
enabled = false
host = "127.0.0.1"
port = 5514
protocol = "udp"

[argus.evidence]
enabled = true
output_dir = ".argus/evidence"
recent_file_window_minutes = 5

[argus.timelock]
enabled = true
lockdown_mode = "reactive"  # "reactive" = kill network + lock | "passive" = alert only (safe for servers)
duration_minutes = 15
network_isolation = true
extend_on_failed_disarm_minutes = 5

[argus.threat_response]
lockdown_min_severity = "high"
lockdown_min_confidence = 0.9
"@

    Set-Content -Path $configPath -Value $config -Encoding UTF8
    Write-Ok "Config written: $configPath"
    Write-Ok "Webhook target: $webhookUrl"
}

# ── Install Argus package ─────────────────────────────────────
function Install-Argus {
    param([string]$Python, [string]$ArgusDir)

    Write-Step "Installing Argus package"
    $result = & $Python -m pip install $ArgusDir 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Err "pip install failed: $result"
        exit 1
    }
    Write-Ok "Argus package installed"

    # Validate config
    $configPath = Join-Path $ArgusDir "config.toml"
    $result = & $Python -m argus --config $configPath check-config 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Config validation failed: $result"
        exit 1
    }
    Write-Ok "Config validated"
}

# ── Create auto-start scheduled task ──────────────────────────
function Set-ArgusAutoStart {
    param([string]$Python, [string]$ArgusDir)

    $configPath = Join-Path $ArgusDir "config.toml"

    $action = New-ScheduledTaskAction `
        -Execute $Python `
        -Argument "-m argus --config `"$configPath`" on" `
        -WorkingDirectory $ArgusDir

    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 1)

    Register-ScheduledTask `
        -TaskName 'Argus-AutoStart' `
        -Description 'Start Argus security monitor on logon' `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Force | Out-Null

    Write-Ok "Scheduled task 'Argus-AutoStart' registered (runs at logon)"

    # ── Argus-Watchdog: restart if process dies ──
    $watchdogScript = @"
`$statePath = "`$env:USERPROFILE\.argus\state.json"
if (!(Test-Path `$statePath)) { exit }
`$state = Get-Content `$statePath -Raw | ConvertFrom-Json
if (-not `$state.enabled) { exit }

# Check for updates (every 10th run ~ every 20 min)
`$counterFile = "`$env:USERPROFILE\.argus\watchdog_counter"
`$counter = 0
if (Test-Path `$counterFile) { `$counter = [int](Get-Content `$counterFile -Raw) }
`$counter++
Set-Content -Path `$counterFile -Value `$counter -Force
if (`$counter % 10 -eq 0) {
    `$repoDir = "$($ArgusDir.Replace('\argus',''))"
    if (Test-Path "`$repoDir\.git") {
        Push-Location `$repoDir
        `$fetchResult = & git fetch --dry-run 2>&1
        if (`$fetchResult) {
            & git pull --ff-only 2>`$null
            & $Python -m pip install -e "`$repoDir\argus" --quiet 2>`$null
            # Restart Argus with new code
            & $Python -m argus --config "$ArgusDir\config.toml" off 2>`$null
            Start-Sleep -Seconds 2
            & $Python -m argus --config "$ArgusDir\config.toml" on 2>`$null
        }
        Pop-Location
    }
}

# Check if process is alive
`$pid = `$state.monitor_pid
if (`$pid -and (Get-Process -Id `$pid -ErrorAction SilentlyContinue)) { exit }
# Process dead - restart
& $Python -m argus --config "$ArgusDir\config.toml" on 2>`$null
"@
    $watchdogPath = Join-Path $ArgusDir "watchdog.ps1"
    Set-Content -Path $watchdogPath -Value $watchdogScript -Force

    $wdAction = New-ScheduledTaskAction `
        -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$watchdogPath`""

    $wdTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 2) `
        -RepetitionDuration ([TimeSpan]::MaxValue)

    $wdSettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Seconds 30)

    Register-ScheduledTask `
        -TaskName 'Argus-Watchdog' `
        -Description 'Restart Argus if process dies (every 2 min)' `
        -Action $wdAction `
        -Trigger $wdTrigger `
        -Settings $wdSettings `
        -Force | Out-Null

    Write-Ok "Scheduled task 'Argus-Watchdog' registered (checks every 2 min)"
}

# ── Start Argus ───────────────────────────────────────────────
function Start-Argus {
    param([string]$Python, [string]$ArgusDir)

    $configPath = Join-Path $ArgusDir "config.toml"

    # Stop if already running
    & $Python -m argus --config $configPath off 2>$null

    # Start
    $result = & $Python -m argus --config $configPath on 2>&1
    Write-Ok $result
}

# ── Install Wazuh agent ───────────────────────────────────────
function Install-WazuhAgent {
    param([string]$ManagerIP, [string]$AgentName, [string]$Group, [string]$Password)

    Write-Step "Installing Wazuh agent"

    # Check if already installed
    $wazuhSvc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($wazuhSvc) {
        Write-Warn "Wazuh agent already installed (status: $($wazuhSvc.Status))"
        if ($wazuhSvc.Status -ne "Running") {
            Start-Service WazuhSvc
            Write-Ok "Wazuh agent started"
        }
        return
    }

    # Download latest MSI
    Write-Info "Downloading Wazuh agent MSI..."
    $msiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.10.2-1.msi"
    $msiPath = "$env:TEMP\wazuh-agent.msi"
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing

    # Install with auto-enrollment
    Write-Info "Installing Wazuh agent..."
    $msiArgs = @(
        "/i", $msiPath,
        "/q",
        "WAZUH_MANAGER=$ManagerIP",
        "WAZUH_AGENT_NAME=$AgentName",
        "WAZUH_AGENT_GROUP=$Group"
    )
    if ($Password) {
        $msiArgs += "WAZUH_REGISTRATION_PASSWORD=$Password"
    }

    Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -NoNewWindow

    # Start service
    Start-Sleep -Seconds 3
    Start-Service WazuhSvc -ErrorAction SilentlyContinue
    Write-Ok "Wazuh agent installed and started"

    # Clean up
    Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
}

# ── Health check ──────────────────────────────────────────────
function Test-Health {
    param([string]$Python, [string]$ArgusDir, [string]$ManagerIP, [int]$Port)

    Write-Step "Health check"

    # Argus daemon alive?
    $configPath = Join-Path $ArgusDir "config.toml"
    $status = & $Python -m argus --config $configPath status 2>&1
    if ($status -match "monitor_alive=True") {
        Write-Ok "Argus daemon: running"
    } else {
        Write-Warn "Argus daemon: not running"
    }

    # Webhook reachable?
    try {
        $resp = Invoke-RestMethod -Uri "http://${ManagerIP}:${Port}/api/ingest/argus" -Method Get -TimeoutSec 5
        if ($resp.status -eq "ok") {
            Write-Ok "Webhook endpoint: reachable"
        }
    } catch {
        Write-Warn "Webhook endpoint: unreachable (${ManagerIP}:${Port})"
    }

    # Wazuh agent?
    $wazuhSvc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($wazuhSvc) {
        if ($wazuhSvc.Status -eq "Running") {
            Write-Ok "Wazuh agent: running"
        } else {
            Write-Warn "Wazuh agent: $($wazuhSvc.Status)"
        }
    }
}

# ── Uninstall ─────────────────────────────────────────────────
function Invoke-Uninstall {
    Write-Step "Uninstalling endpoint agents"

    # Stop and remove Argus
    $py = Find-Python
    if ($py) {
        & $py -m argus --config "$env:USERPROFILE\security-shallots\argus\config.toml" off 2>$null
    }
    Unregister-ScheduledTask -TaskName 'Argus-AutoStart' -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'Argus-Watchdog' -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'Argus-OnLock' -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'Argus-OnUnlock' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Ok "Argus scheduled tasks removed"

    # Remove Argus data
    if (Test-Path "$env:USERPROFILE\.argus") {
        Remove-Item "$env:USERPROFILE\.argus" -Recurse -Force
        Write-Ok "Argus data directory removed"
    }

    # Uninstall Wazuh
    $wazuhSvc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($wazuhSvc) {
        Stop-Service WazuhSvc -Force -ErrorAction SilentlyContinue
        $uninstall = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
            Where-Object { $_.DisplayName -like "*Wazuh*" } |
            Select-Object -First 1
        if ($uninstall) {
            Start-Process msiexec.exe -ArgumentList "/x", $uninstall.PSChildName, "/q" -Wait -NoNewWindow
            Write-Ok "Wazuh agent uninstalled"
        }
    }

    Write-Ok "Uninstall complete"
    exit 0
}

# ── Print summary ─────────────────────────────────────────────
function Show-Summary {
    param([string]$ManagerIP, [int]$Port, [string]$AgentName, [string]$ArgusDir)

    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
    Write-Host "  Clove endpoint deployment complete!" -ForegroundColor Green
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Agent name:     $AgentName" -ForegroundColor White
    Write-Host "  Manager:        $ManagerIP" -ForegroundColor White
    Write-Host "  Webhook:        http://${ManagerIP}:${Port}/api/ingest/argus" -ForegroundColor White
    Write-Host "  Config:         $ArgusDir\config.toml" -ForegroundColor White
    Write-Host "  Events log:     $env:USERPROFILE\.argus\events\" -ForegroundColor White
    Write-Host "  Dashboard:      http://${ManagerIP}:8844" -ForegroundColor White
    Write-Host ""
    Write-Host "  Commands:" -ForegroundColor Yellow
    Write-Host "    argus --config config.toml status   # Check status" -ForegroundColor DarkGray
    Write-Host "    argus --config config.toml off      # Stop monitoring" -ForegroundColor DarkGray
    Write-Host "    argus --config config.toml on       # Start monitoring" -ForegroundColor DarkGray
    Write-Host ""
}

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

Show-Banner

if ($Uninstall) {
    Invoke-Uninstall
}

$ManagerIP = Resolve-Manager

Write-Step "Pre-flight checks"
Write-Info "Manager: $ManagerIP"
Write-Info "Agent name: $Name"

# Find or install Python
$Python = Find-Python
if (-not $Python) {
    Write-Warn "Python 3.10+ not found"
    Install-Python
    $Python = Find-Python
}
Write-Ok "Python: $Python"

# Get Argus source
Write-Step "Setting up Argus"
$InstallDir = "$env:USERPROFILE\security-shallots"
$ArgusDir = "$InstallDir\argus"
Get-ArgusSource -InstallDir $InstallDir

# Configure
Set-ArgusConfig -ArgusDir $ArgusDir -ManagerIP $ManagerIP -Port $WebhookPort -Secret $WebhookSecret -AgentName $Name

# Install package
Install-Argus -Python $Python -ArgusDir $ArgusDir

# Auto-start
Write-Step "Configuring auto-start"
Set-ArgusAutoStart -Python $Python -ArgusDir $ArgusDir

# Start Argus now
Write-Step "Starting Argus"
Start-Argus -Python $Python -ArgusDir $ArgusDir

# Optional Wazuh
if ($Wazuh) {
    Install-WazuhAgent -ManagerIP $ManagerIP -AgentName $Name -Group $WazuhGroup -Password $WazuhPassword
}

# Health check
if (-not $SkipHealthcheck) {
    Test-Health -Python $Python -ArgusDir $ArgusDir -ManagerIP $ManagerIP -Port $WebhookPort
}

# Summary
Show-Summary -ManagerIP $ManagerIP -Port $WebhookPort -AgentName $Name -ArgusDir $ArgusDir
