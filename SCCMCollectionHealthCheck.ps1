<#
.SYNOPSIS
    SCCM Collection Health Check - Runs client diagnostics across a ConfigMgr collection
    and generates a modern HTML dashboard report.

.DESCRIPTION
    Connects to a ConfigMgr site server, enumerates devices in a target collection,
    runs WMI-based health checks remotely on each device, and produces a self-contained
    HTML report with per-device results and a summary dashboard.

    Checks performed on each device:
      1. WMI Repository integrity
      2. CcmExec service status
      3. State message queue backlog
      4. Policy age (last download > 48 hrs)

.PARAMETER SiteServer
    FQDN of the ConfigMgr site server (SMS Provider).
    Default: CHANGE_ME.yourdomain.com

.PARAMETER SiteCode
    ConfigMgr site code.
    Default: P01

.PARAMETER CollectionID
    Target collection ID.
    Default: P010039C

.PARAMETER CollectionName
    Optional friendly name override for the report title. Auto-discovered if omitted.

.PARAMETER MaxConcurrent
    Number of devices to check in parallel (runspaces). Default: 10.

.PARAMETER OutputPath
    Full path for the HTML report. Defaults to Desktop\SCCMHealthReport_<timestamp>.html

.PARAMETER Credential
    PSCredential to use for remote WMI connections. Uses current session if omitted.

.EXAMPLE
    .\Invoke-SCCMCollectionHealthCheck.ps1 -SiteServer "sccm.contoso.com" -CollectionID "P010039C"

.EXAMPLE
    $cred = Get-Credential
    .\Invoke-SCCMCollectionHealthCheck.ps1 -SiteServer "sccm.contoso.com" -CollectionID "P010039C" -Credential $cred -MaxConcurrent 20

.NOTES
    Requires:
      - ConfigurationManager PowerShell module (installed with the ConfigMgr console)
      - WinRM / DCOM access to target devices (for remote WMI)
      - Read permissions on the target collection in ConfigMgr
    
    Can also be run directly on the site server where the CM console is installed.
#>

[CmdletBinding()]
param(
    [string]$SiteServer    = "CHANGE_ME.yourdomain.com",   # <-- Fill in your site server FQDN
    [string]$SiteCode      = "P01",
    [string]$CollectionID  = "P010039C",
    [string]$CollectionName = "",
    [int]   $MaxConcurrent = 10,
    [string]$OutputPath    = "",
    [System.Management.Automation.PSCredential]$Credential = $null
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"
$StartTime = Get-Date

# ── Output path ───────────────────────────────────────────────────────────────
if (-not $OutputPath) {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "SCCMHealthReport_${CollectionID}_${ts}.html"
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 – Load ConfigMgr module and enumerate collection members
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n[1/3] Connecting to ConfigMgr site $SiteCode on $SiteServer..." -ForegroundColor Cyan

# Locate and import the ConfigMgr module
$CMModulePath = $null
$possiblePaths = @(
    "C:\Program Files (x86)\Microsoft Endpoint Manager\AdminConsole\bin\ConfigurationManager.psd1",
    "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1",
    "C:\Program Files (x86)\Microsoft System Center 2012 R2 Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1"
)
foreach ($p in $possiblePaths) {
    if (Test-Path $p) { $CMModulePath = $p; break }
}

if (-not $CMModulePath) {
    # Try registry
    $consolePath = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\ConfigMgr10\Setup" -ErrorAction SilentlyContinue)."UI Installation Directory"
    if ($consolePath) {
        $CMModulePath = Join-Path $consolePath "bin\ConfigurationManager.psd1"
    }
}

if (-not $CMModulePath -or -not (Test-Path $CMModulePath)) {
    Write-Error "ConfigurationManager module not found. Ensure the ConfigMgr console is installed on this machine."
    exit 2
}

Import-Module $CMModulePath -Force
$originalLocation = Get-Location

# Connect to the site
if (-not (Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $SiteServer | Out-Null
}
Set-Location "${SiteCode}:\"

# Resolve collection name
if (-not $CollectionName) {
    $col = Get-CMCollection -Id $CollectionID -ErrorAction Stop
    $CollectionName = if ($col) { $col.Name } else { $CollectionID }
}

Write-Host "  Collection : $CollectionName ($CollectionID)" -ForegroundColor Gray

# Get all device members
Write-Host "[2/3] Enumerating collection members..." -ForegroundColor Cyan
$DeviceList = Get-CMCollectionMember -CollectionId $CollectionID | Select-Object -ExpandProperty Name | Sort-Object

Set-Location $originalLocation

if (-not $DeviceList -or $DeviceList.Count -eq 0) {
    Write-Error "No devices found in collection $CollectionID. Check the collection ID and your permissions."
    exit 2
}

Write-Host "  Found $($DeviceList.Count) device(s)" -ForegroundColor Gray

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 – Run health checks in parallel via runspace pool
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "[3/3] Running health checks (parallel, max $MaxConcurrent)..." -ForegroundColor Cyan

$CheckScriptBlock = {
    param($ComputerName, $Credential)

    $result = [PSCustomObject]@{
        ComputerName = $ComputerName
        Reachable    = $false
        WMI          = "SKIPPED"
        WMIDetail    = ""
        Service      = "SKIPPED"
        ServiceDetail= ""
        StateMsg     = "SKIPPED"
        StateMsgDetail=""
        PolicyAge    = "SKIPPED"
        PolicyAgeDetail=""
        Issues       = @()
        CheckedAt    = (Get-Date -Format "HH:mm:ss")
        Error        = ""
    }

    # WMI connection params
    $wmiArgs = @{ ComputerName = $ComputerName; ErrorAction = "Stop" }
    if ($Credential) { $wmiArgs.Credential = $Credential }

    # Ping / reachability
    if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        $result.Error = "Unreachable (ping failed)"
        return $result
    }
    $result.Reachable = $true

    # 1. WMI Repository
    try {
        $wmi = Invoke-Command -ComputerName $ComputerName -ScriptBlock { winmgmt /verifyrepository } `
               -ErrorAction Stop $(if ($Credential) { "-Credential $Credential" })
        if ($wmi -like "*inconsistent*") {
            $result.WMI       = "FAILED"
            $result.WMIDetail = "Repository inconsistent"
            $result.Issues   += "WMI Repository Inconsistent"
        } else {
            $result.WMI       = "OK"
            $result.WMIDetail = "Consistent"
        }
    } catch {
        # Fallback: try remote WMI directly
        try {
            $wmiObj = Get-WmiObject @wmiArgs -Namespace root -Class __Namespace -List | Select-Object -First 1
            $result.WMI       = "OK"
            $result.WMIDetail = "Accessible (remote verification limited)"
        } catch {
            $result.WMI       = "SKIPPED"
            $result.WMIDetail = "Cannot verify remotely: $_"
        }
    }

    # 2. CcmExec Service
    try {
        $svc = Get-WmiObject @wmiArgs -Class Win32_Service -Filter "Name='CcmExec'"
        if (-not $svc) {
            $result.Service       = "FAILED"
            $result.ServiceDetail = "Service not found – client may not be installed"
            $result.Issues       += "CcmExec Not Found"
        } elseif ($svc.State -ne "Running") {
            $result.Service       = "FAILED"
            $result.ServiceDetail = "State: $($svc.State)"
            $result.Issues       += "CcmExec Not Running ($($svc.State))"
        } else {
            $result.Service       = "OK"
            $result.ServiceDetail = "Running"
        }
    } catch {
        $result.Service       = "SKIPPED"
        $result.ServiceDetail = "WMI error: $_"
    }

    # 3. State Message Queue
    try {
        $msgs = Get-WmiObject @wmiArgs -Namespace "root\ccm\StateMsg" -Class CCM_StateMsg
        $count = @($msgs).Count
        if ($count -gt 100) {
            $result.StateMsg       = "WARNING"
            $result.StateMsgDetail = "$count messages"
            $result.Issues        += "State Message Backlog: $count"
        } else {
            $result.StateMsg       = "OK"
            $result.StateMsgDetail = "$count messages"
        }
    } catch {
        $result.StateMsg       = "SKIPPED"
        $result.StateMsgDetail = "Namespace inaccessible"
    }

    # 4. Policy Age
    try {
        $policy = Get-WmiObject @wmiArgs -Namespace "root\ccm\Policy\Machine\ActualConfig" `
                                -Class CCM_Policy | Sort-Object PolicyDownloadTime -Descending | Select-Object -First 1
        if ($policy) {
            $age   = (Get-Date) - $policy.PolicyDownloadTime
            $hours = [int]$age.TotalHours
            if ($age.TotalHours -gt 48) {
                $result.PolicyAge       = "WARNING"
                $result.PolicyAgeDetail = "$hours hrs ago"
                $result.Issues         += "Policy Age: ${hours}hrs (>48)"
            } else {
                $result.PolicyAge       = "OK"
                $result.PolicyAgeDetail = "$hours hrs ago"
            }
        } else {
            $result.PolicyAge       = "SKIPPED"
            $result.PolicyAgeDetail = "No policy objects"
        }
    } catch {
        $result.PolicyAge       = "SKIPPED"
        $result.PolicyAgeDetail = "Namespace inaccessible"
    }

    return $result
}

# Runspace pool
$Pool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrent)
$Pool.Open()
$Jobs = @()

foreach ($device in $DeviceList) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $Pool
    [void]$ps.AddScript($CheckScriptBlock)
    [void]$ps.AddArgument($device)
    [void]$ps.AddArgument($Credential)
    $Jobs += [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Device = $device }
}

# Collect results with progress
$Results = @()
$done = 0
foreach ($job in $Jobs) {
    $res = $job.PS.EndInvoke($job.Handle)
    $job.PS.Dispose()
    $Results += $res
    $done++
    $pct = [int](($done / $DeviceList.Count) * 100)
    Write-Progress -Activity "SCCM Health Check" -Status "$done/$($DeviceList.Count) – $($job.Device)" -PercentComplete $pct
}
Write-Progress -Activity "SCCM Health Check" -Completed
$Pool.Close()

$Duration = [int]((Get-Date) - $StartTime).TotalSeconds

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 – Build HTML Report
# ══════════════════════════════════════════════════════════════════════════════

# Summary counts
$TotalDevices    = $Results.Count
$Reachable       = ($Results | Where-Object Reachable).Count
$Unreachable     = $TotalDevices - $Reachable
$Compliant       = ($Results | Where-Object { $_.Reachable -and $_.Issues.Count -eq 0 }).Count
$NonCompliant    = ($Results | Where-Object { $_.Reachable -and $_.Issues.Count -gt 0 }).Count
$CompliancePct   = if ($Reachable -gt 0) { [int](($Compliant / $Reachable) * 100) } else { 0 }

$OverallStatus   = if ($NonCompliant -eq 0 -and $Unreachable -eq 0) { "COMPLIANT" } elseif ($NonCompliant -gt 0) { "NON-COMPLIANT" } else { "PARTIAL" }
$StatusHex       = switch ($OverallStatus) { "COMPLIANT" { "#22c55e" } "NON-COMPLIANT" { "#ef4444" } default { "#f59e0b" } }

# Device rows
function Get-StatusBadge($s) {
    switch ($s) {
        "OK"      { return '<span class="badge ok-b">OK</span>' }
        "WARNING" { return '<span class="badge warn-b">WARN</span>' }
        "FAILED"  { return '<span class="badge fail-b">FAIL</span>' }
        "SKIPPED" { return '<span class="badge skip-b">SKIP</span>' }
        default   { return '<span class="badge skip-b">–</span>' }
    }
}

function Get-RowClass($result) {
    if (-not $result.Reachable) { return "row-unreachable" }
    if ($result.Issues.Count -gt 0) { return "row-issues" }
    return ""
}

$DeviceRows = foreach ($r in ($Results | Sort-Object ComputerName)) {
    $rc = Get-RowClass $r
    if (-not $r.Reachable) {
        @"
        <tr class="$rc">
          <td class="dev-name">$($r.ComputerName)</td>
          <td colspan="5" class="unreachable-msg">Unreachable — $($r.Error)</td>
          <td>$($r.CheckedAt)</td>
        </tr>
"@
    } else {
        $issueCount = $r.Issues.Count
        $compBadge  = if ($issueCount -eq 0) { '<span class="badge ok-b">Compliant</span>' } else { "<span class='badge fail-b'>$issueCount issue(s)</span>" }
        @"
        <tr class="$rc" onclick="toggleDetail('d_$($r.ComputerName.Replace('-','_').Replace('.','_'))')" style="cursor:pointer">
          <td class="dev-name">$($r.ComputerName)</td>
          <td>$(Get-StatusBadge $r.WMI)<div class="cell-detail">$($r.WMIDetail)</div></td>
          <td>$(Get-StatusBadge $r.Service)<div class="cell-detail">$($r.ServiceDetail)</div></td>
          <td>$(Get-StatusBadge $r.StateMsg)<div class="cell-detail">$($r.StateMsgDetail)</div></td>
          <td>$(Get-StatusBadge $r.PolicyAge)<div class="cell-detail">$($r.PolicyAgeDetail)</div></td>
          <td>$compBadge</td>
          <td class="time-col">$($r.CheckedAt)</td>
        </tr>
"@
    }
}

# Donut chart data
$DonutCompliant    = $Compliant
$DonutNonCompliant = $NonCompliant
$DonutUnreachable  = $Unreachable

$ReportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$RunBy      = $env:USERNAME
$RunFrom    = $env:COMPUTERNAME

$Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SCCM Health – $CollectionName</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:      #0b0e18;
    --bg2:     #111827;
    --bg3:     #1a2235;
    --bg4:     #1e293b;
    --border:  #253048;
    --text:    #e2e8f0;
    --muted:   #64748b;
    --ok:      #22c55e;
    --warn:    #f59e0b;
    --fail:    #ef4444;
    --skip:    #6366f1;
    --accent:  #38bdf8;
    --orange:  #fb923c;
    --font:    'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono:    'Cascadia Code', 'Consolas', 'Courier New', monospace;
  }

  body { font-family: var(--font); background: var(--bg); color: var(--text); min-height: 100vh; }

  /* ── Top bar ── */
  .topbar {
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 0.9rem 2rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .brand { display: flex; align-items: center; gap: 10px; }
  .brand-icon {
    width: 34px; height: 34px;
    background: linear-gradient(135deg, #1d4ed8, #0ea5e9);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
  }
  .brand-icon svg { width: 18px; height: 18px; color: #fff; }
  .brand-title { font-size: 0.95rem; font-weight: 600; }
  .brand-col {
    font-size: 0.72rem;
    color: var(--accent);
    font-family: var(--mono);
    background: #0ea5e910;
    border: 1px solid #0ea5e930;
    padding: 2px 8px;
    border-radius: 4px;
    margin-left: 6px;
  }

  .topbar-meta {
    font-size: 0.72rem;
    color: var(--muted);
    font-family: var(--mono);
    text-align: right;
    line-height: 1.7;
  }
  .topbar-meta span { color: var(--accent); }

  /* ── Main layout ── */
  .main { padding: 1.75rem 2rem; max-width: 1400px; margin: 0 auto; }

  /* ── Status hero ── */
  .hero {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 1.5rem;
    margin-bottom: 1.5rem;
    align-items: center;
  }

  .hero-status {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 1.1rem 1.4rem;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-left: 5px solid $StatusHex;
    border-radius: 10px;
  }

  .status-pulse {
    width: 14px; height: 14px;
    border-radius: 50%;
    background: $StatusHex;
    flex-shrink: 0;
    box-shadow: 0 0 0 3px ${StatusHex}30, 0 0 12px ${StatusHex}60;
  }

  .status-txt { font-size: 1.2rem; font-weight: 700; color: $StatusHex; letter-spacing: .1em; text-transform: uppercase; }
  .status-sub { font-size: 0.8rem; color: var(--muted); margin-top: 2px; }

  .hero-timing {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.85rem 1.2rem;
    text-align: center;
    white-space: nowrap;
  }
  .timing-num { font-size: 1.6rem; font-weight: 700; color: var(--accent); line-height: 1; }
  .timing-lbl { font-size: 0.68rem; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; margin-top: 3px; }

  /* ── Stat cards ── */
  .stats {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 10px;
    margin-bottom: 1.5rem;
  }

  .stat-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 1rem;
    position: relative;
    overflow: hidden;
  }

  .stat-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
  }

  .stat-card.s-total::before  { background: var(--accent); }
  .stat-card.s-reach::before  { background: var(--ok); }
  .stat-card.s-comply::before { background: var(--ok); }
  .stat-card.s-issues::before { background: var(--fail); }
  .stat-card.s-unreach::before{ background: var(--orange); }

  .stat-num { font-size: 2rem; font-weight: 700; line-height: 1; margin-bottom: 4px; }
  .stat-lbl { font-size: 0.7rem; color: var(--muted); text-transform: uppercase; letter-spacing: .07em; }
  .stat-sub { font-size: 0.72rem; color: var(--muted); margin-top: 6px; font-family: var(--mono); }

  .c-accent { color: var(--accent); }
  .c-ok     { color: var(--ok); }
  .c-fail   { color: var(--fail); }
  .c-warn   { color: var(--warn); }
  .c-orange { color: var(--orange); }

  /* ── Compliance bar ── */
  .compliance-row {
    display: grid;
    grid-template-columns: 1fr 280px;
    gap: 10px;
    margin-bottom: 1.5rem;
  }

  .compliance-bar-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 1.1rem 1.4rem;
  }

  .bar-header {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 0.7rem;
  }

  .bar-title { font-size: 0.72rem; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); }
  .bar-pct   { font-size: 1.6rem; font-weight: 700; color: var(--ok); }

  .bar-track {
    height: 8px;
    background: var(--bg4);
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 0.6rem;
  }

  .bar-fill-ok      { height: 100%; background: var(--ok);     display: inline-block; }
  .bar-fill-fail    { height: 100%; background: var(--fail);   display: inline-block; }
  .bar-fill-unreach { height: 100%; background: var(--orange); display: inline-block; }

  .bar-legend { display: flex; gap: 14px; font-size: 0.72rem; color: var(--muted); }
  .leg-dot    { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }

  /* ── Donut ── */
  .donut-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 1.1rem;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 1rem;
  }

  .donut-legend { display: flex; flex-direction: column; gap: 8px; font-size: 0.78rem; }
  .dleg-row { display: flex; align-items: center; gap: 8px; }
  .dleg-color { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }
  .dleg-lbl { color: var(--muted); }
  .dleg-num { font-weight: 600; color: var(--text); margin-left: auto; padding-left: 12px; }

  /* ── Search / filter ── */
  .toolbar {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 0.75rem;
    flex-wrap: wrap;
  }

  .search-box {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 0.45rem 0.85rem;
    color: var(--text);
    font-size: 0.82rem;
    font-family: var(--mono);
    flex: 1;
    min-width: 220px;
    outline: none;
    transition: border-color .2s;
  }
  .search-box:focus { border-color: var(--accent); }
  .search-box::placeholder { color: var(--muted); }

  .filter-btn {
    background: var(--bg2);
    border: 1px solid var(--border);
    color: var(--muted);
    padding: 0.45rem 0.9rem;
    border-radius: 7px;
    font-size: 0.75rem;
    cursor: pointer;
    font-family: var(--font);
    text-transform: uppercase;
    letter-spacing: .06em;
    transition: all .15s;
  }
  .filter-btn:hover, .filter-btn.active { background: var(--bg4); color: var(--text); border-color: var(--accent); }
  .filter-btn.f-fail.active  { color: var(--fail);   border-color: var(--fail);   background: #7f1d1d20; }
  .filter-btn.f-warn.active  { color: var(--warn);   border-color: var(--warn);   background: #78350f20; }
  .filter-btn.f-ok.active    { color: var(--ok);     border-color: var(--ok);     background: #14532d20; }
  .filter-btn.f-unr.active   { color: var(--orange); border-color: var(--orange); background: #43160220; }

  .row-count { font-size: 0.72rem; color: var(--muted); margin-left: auto; font-family: var(--mono); }

  /* ── Table ── */
  .sec-title {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: .1em;
    color: var(--muted);
    margin-bottom: .55rem;
    padding-left: 2px;
  }

  .table-wrap {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    overflow-x: auto;
  }

  table { width: 100%; border-collapse: collapse; min-width: 700px; }

  thead tr { background: var(--bg3); border-bottom: 1px solid var(--border); }
  th {
    padding: 0.6rem 0.9rem;
    font-size: 0.67rem;
    text-transform: uppercase;
    letter-spacing: .09em;
    color: var(--muted);
    text-align: left;
    font-weight: 500;
    white-space: nowrap;
  }

  tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background .12s;
  }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: var(--bg3); }
  tbody tr.row-issues { background: #7f1d1d0a; }
  tbody tr.row-unreachable { background: #43160210; opacity: .7; }

  td {
    padding: 0.6rem 0.9rem;
    font-size: 0.82rem;
    vertical-align: top;
  }

  .dev-name {
    font-family: var(--mono);
    font-size: 0.8rem;
    font-weight: 500;
    white-space: nowrap;
    color: var(--text);
  }

  .cell-detail { font-size: 0.7rem; color: var(--muted); font-family: var(--mono); margin-top: 2px; }
  .unreachable-msg { color: var(--orange); font-size: 0.8rem; font-family: var(--mono); }
  .time-col { font-size: 0.72rem; color: var(--muted); font-family: var(--mono); white-space: nowrap; }

  .badge {
    display: inline-block;
    font-size: 0.63rem;
    font-weight: 600;
    letter-spacing: .06em;
    text-transform: uppercase;
    padding: 2px 6px;
    border-radius: 4px;
    white-space: nowrap;
  }
  .ok-b   { background: #14532d40; color: #22c55e; border: 1px solid #15803d50; }
  .warn-b { background: #78350f40; color: #f59e0b; border: 1px solid #d9770650; }
  .fail-b { background: #7f1d1d40; color: #ef4444; border: 1px solid #dc262650; }
  .skip-b { background: #3730a340; color: #6366f1; border: 1px solid #4f46e550; }
  .unr-b  { background: #43160240; color: #fb923c; border: 1px solid #c2410c50; }

  /* ── Footer ── */
  .footer {
    margin-top: 2rem;
    padding: 1rem 2rem;
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    font-size: 0.72rem;
    color: var(--muted);
    font-family: var(--mono);
    flex-wrap: wrap;
    gap: 6px;
  }

  @media (max-width: 900px) {
    .stats { grid-template-columns: repeat(3, 1fr); }
    .compliance-row { grid-template-columns: 1fr; }
    .hero { grid-template-columns: 1fr; }
    .main { padding: 1rem; }
    .topbar { padding: 0.75rem 1rem; }
    .cell-detail { display: none; }
  }
</style>
</head>
<body>

<!-- Top bar -->
<div class="topbar">
  <div class="brand">
    <div class="brand-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>
      </svg>
    </div>
    <span class="brand-title">SCCM Collection Health Check</span>
    <span class="brand-col">$CollectionName</span>
    <span class="brand-col" style="color:var(--muted); border-color:var(--border);">$CollectionID</span>
  </div>
  <div class="topbar-meta">
    <div>Site &nbsp;<span>${SiteCode}:\ on $SiteServer</span></div>
    <div>Run &nbsp;<span>$ReportTime</span>&nbsp;&nbsp;by <span>$RunBy</span> from <span>$RunFrom</span></div>
  </div>
</div>

<div class="main">

  <!-- Hero -->
  <div class="hero">
    <div class="hero-status">
      <div class="status-pulse"></div>
      <div>
        <div class="status-txt">$OverallStatus</div>
        <div class="status-sub">$NonCompliant non-compliant &bull; $Unreachable unreachable &bull; $Compliant clean devices</div>
      </div>
    </div>
    <div class="hero-timing">
      <div class="timing-num">${Duration}s</div>
      <div class="timing-lbl">Scan Duration</div>
    </div>
  </div>

  <!-- Stat cards -->
  <div class="stats">
    <div class="stat-card s-total">
      <div class="stat-num c-accent">$TotalDevices</div>
      <div class="stat-lbl">Total Devices</div>
      <div class="stat-sub">in collection</div>
    </div>
    <div class="stat-card s-reach">
      <div class="stat-num c-ok">$Reachable</div>
      <div class="stat-lbl">Reachable</div>
      <div class="stat-sub">responded to ping</div>
    </div>
    <div class="stat-card s-comply">
      <div class="stat-num c-ok">$Compliant</div>
      <div class="stat-lbl">Compliant</div>
      <div class="stat-sub">no issues found</div>
    </div>
    <div class="stat-card s-issues">
      <div class="stat-num c-fail">$NonCompliant</div>
      <div class="stat-lbl">Non-Compliant</div>
      <div class="stat-sub">have issues</div>
    </div>
    <div class="stat-card s-unreach">
      <div class="stat-num c-orange">$Unreachable</div>
      <div class="stat-lbl">Unreachable</div>
      <div class="stat-sub">ping failed</div>
    </div>
  </div>

  <!-- Compliance bar + donut -->
  <div class="compliance-row">
    <div class="compliance-bar-card">
      <div class="bar-header">
        <span class="bar-title">Compliance Rate (of reachable devices)</span>
        <span class="bar-pct">${CompliancePct}%</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill-ok"   style="width:$(if($Reachable -gt 0){[int](($Compliant/$Reachable)*100)}else{0})%"></div><div class="bar-fill-fail" style="width:$(if($Reachable -gt 0){[int](($NonCompliant/$Reachable)*100)}else{0})%"></div>
      </div>
      <div class="bar-legend">
        <span><span class="leg-dot" style="background:var(--ok)"></span>Compliant ($Compliant)</span>
        <span><span class="leg-dot" style="background:var(--fail)"></span>Non-Compliant ($NonCompliant)</span>
        <span><span class="leg-dot" style="background:var(--orange)"></span>Unreachable ($Unreachable)</span>
      </div>
    </div>
    <div class="donut-card">
      <canvas id="donut" width="110" height="110"></canvas>
      <div class="donut-legend">
        <div class="dleg-row"><div class="dleg-color" style="background:#22c55e"></div><span class="dleg-lbl">Compliant</span><span class="dleg-num">$Compliant</span></div>
        <div class="dleg-row"><div class="dleg-color" style="background:#ef4444"></div><span class="dleg-lbl">Non-Compliant</span><span class="dleg-num">$NonCompliant</span></div>
        <div class="dleg-row"><div class="dleg-color" style="background:#fb923c"></div><span class="dleg-lbl">Unreachable</span><span class="dleg-num">$Unreachable</span></div>
      </div>
    </div>
  </div>

  <!-- Device table -->
  <div class="toolbar">
    <input class="search-box" type="text" id="search" placeholder="Search hostname..." oninput="filterTable()">
    <button class="filter-btn" onclick="setFilter('all')">All</button>
    <button class="filter-btn f-fail" onclick="setFilter('fail')">Issues Only</button>
    <button class="filter-btn f-warn" onclick="setFilter('warn')">Warnings</button>
    <button class="filter-btn f-ok"   onclick="setFilter('ok')">Clean</button>
    <button class="filter-btn f-unr"  onclick="setFilter('unr')">Unreachable</button>
    <span class="row-count" id="row-count">$TotalDevices devices</span>
  </div>

  <p class="sec-title">Device Results</p>
  <div class="table-wrap">
    <table id="dev-table">
      <thead>
        <tr>
          <th>Device</th>
          <th>WMI Repo</th>
          <th>CcmExec</th>
          <th>State Queue</th>
          <th>Policy Age</th>
          <th>Overall</th>
          <th>Checked</th>
        </tr>
      </thead>
      <tbody id="dev-body">
        $($DeviceRows -join "`n")
      </tbody>
    </table>
  </div>

</div>

<!-- Footer -->
<div class="footer">
  <span>Invoke-SCCMCollectionHealthCheck.ps1 &bull; Site: ${SiteCode} &bull; Collection: $CollectionID ($CollectionName)</span>
  <span>$TotalDevices devices &bull; ${Duration}s &bull; $ReportTime</span>
</div>

<script>
  // ── Donut chart ───────────────────────────────────────────────────────────
  (function() {
    var c = document.getElementById('donut');
    var ctx = c.getContext('2d');
    var data = [$DonutCompliant, $DonutNonCompliant, $DonutUnreachable];
    var colors = ['#22c55e','#ef4444','#fb923c'];
    var total = data.reduce(function(a,b){return a+b;},0);
    if (total === 0) return;
    var start = -Math.PI/2, cx=55, cy=55, r=42, ri=28;
    ctx.clearRect(0,0,110,110);
    data.forEach(function(v,i){
      if(v===0) return;
      var sweep = (v/total)*(2*Math.PI);
      ctx.beginPath();
      ctx.moveTo(cx,cy);
      ctx.arc(cx,cy,r,start,start+sweep);
      ctx.closePath();
      ctx.fillStyle = colors[i];
      ctx.fill();
      start += sweep;
    });
    ctx.beginPath();
    ctx.arc(cx,cy,ri,0,2*Math.PI);
    ctx.fillStyle = '#111827';
    ctx.fill();
    ctx.fillStyle = '#e2e8f0';
    ctx.font = 'bold 16px Segoe UI, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    var pct = total > 0 ? Math.round(($DonutCompliant/total)*100) : 0;
    ctx.fillText(pct+'%', cx, cy);
  })();

  // ── Filter & search ───────────────────────────────────────────────────────
  var activeFilter = 'all';

  function setFilter(f) {
    activeFilter = f;
    document.querySelectorAll('.filter-btn').forEach(function(b){ b.classList.remove('active'); });
    var map = {all:'',fail:'f-fail',warn:'f-warn',ok:'f-ok',unr:'f-unr'};
    if(f!=='all'){
      document.querySelector('.filter-btn.'+map[f]).classList.add('active');
    } else {
      document.querySelector('.filter-btn:first-of-type').classList.add('active');
    }
    filterTable();
  }

  function rowMatchesFilter(tr) {
    if (activeFilter === 'all') return true;
    var cls = tr.className || '';
    if (activeFilter === 'unr')  return cls.indexOf('row-unreachable') >= 0;
    if (activeFilter === 'fail') return cls.indexOf('row-issues') >= 0;
    if (activeFilter === 'ok')   return cls === '' || cls.trim() === '';
    if (activeFilter === 'warn') {
      var badges = tr.querySelectorAll('.badge.warn-b');
      return badges.length > 0 && cls.indexOf('row-issues') < 0 && cls.indexOf('row-unreachable') < 0;
    }
    return true;
  }

  function filterTable() {
    var q = document.getElementById('search').value.toLowerCase();
    var rows = document.querySelectorAll('#dev-body tr');
    var vis = 0;
    rows.forEach(function(tr){
      var name = tr.querySelector('.dev-name');
      var nameMatch = !name || name.textContent.toLowerCase().indexOf(q) >= 0;
      var show = nameMatch && rowMatchesFilter(tr);
      tr.style.display = show ? '' : 'none';
      if(show) vis++;
    });
    document.getElementById('row-count').textContent = vis + ' device' + (vis !== 1 ? 's' : '');
  }

  // Init: show all
  setFilter('all');
</script>
</body>
</html>
"@

$Html | Out-File -FilePath $OutputPath -Encoding UTF8

# ── Console summary ───────────────────────────────────────────────────────────
Write-Host "`n── Summary ────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host "  Collection : $CollectionName ($CollectionID)" -ForegroundColor Gray
Write-Host "  Total      : $TotalDevices devices" -ForegroundColor Gray
Write-Host "  Reachable  : $Reachable" -ForegroundColor Gray
Write-Host "  Compliant  : $Compliant" -ForegroundColor Green
Write-Host "  Issues     : $NonCompliant" -ForegroundColor $(if($NonCompliant -gt 0){'Red'}else{'Green'})
Write-Host "  Unreachable: $Unreachable" -ForegroundColor $(if($Unreachable -gt 0){'Yellow'}else{'Gray'})
Write-Host "  Duration   : ${Duration}s" -ForegroundColor Gray
Write-Host "`n  Report saved to:`n  $OutputPath" -ForegroundColor Cyan

try { Start-Process $OutputPath } catch {}

if ($NonCompliant -gt 0 -or $Unreachable -gt 0) { Exit 1 } else { Exit 0 }
