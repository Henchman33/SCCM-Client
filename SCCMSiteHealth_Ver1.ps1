<#
.SYNOPSIS
    SCCM Client Health Check and Remediation Script with Export Capabilities
.DESCRIPTION
    This script checks various SCCM client components, exports results to multiple formats,
    and can target specific device collections or Windows Servers
.NOTES
    Author: IT Administrator
    Version: 2.0
    Requires: Administrative privileges, SCCM Module, ImportExcel module for Excel export
#>

# Import Required Modules
try {
    Import-Module ImportExcel -ErrorAction SilentlyContinue
    Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "Some modules could not be loaded. Excel export may not be available."
}

# Script Configuration
$LogPath = "C:\Windows\Logs\SCCM_Client_Health.log"
$ExportPath = "C:\Temp\ClientHealth"
$MaxLogSize = 10MB
$SiteCode = "YOUR_SITE_CODE"  # Change to your site code
$SCCMServer = "YOUR_SCCM_SERVER"  # Change to your SCCM server

# Target Configuration
$TargetDeviceCollection = "All Windows Servers"  # Change to your target collection
$TargetOnlyWindowsServers = $true  # Set to $false to include workstations
$ComputerList = @()  # Leave empty to use collection, or specify computers

# Function to write logs
function Write-Log {
    param(
        [string]$Message,
        [string]$Type = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Type] $Message"
    
    # Write to console
    Write-Host $LogEntry -ForegroundColor $(if ($Type -eq "ERROR") { "Red" } elseif ($Type -eq "WARNING") { "Yellow" } else { "White" })
    
    # Write to log file
    try {
        if (Test-Path $LogPath) {
            $LogFile = Get-Item $LogPath
            if ($LogFile.Length -gt $MaxLogSize) {
                $BackupPath = $LogPath -replace '\.log$', '_backup.log'
                Move-Item $LogPath $BackupPath -Force
            }
        }
        Add-Content -Path $LogPath -Value $LogEntry -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to ensure export directory exists
function Initialize-ExportDirectory {
    if (-not (Test-Path $ExportPath)) {
        try {
            New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
            Write-Log "Created export directory: $ExportPath"
        }
        catch {
            Write-Log "Failed to create export directory: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    return $true
}

# Function to get computers from SCCM collection
function Get-ComputersFromCollection {
    param(
        [string]$CollectionName,
        [bool]$WindowsServersOnly = $true
    )
    
    Write-Log "Retrieving computers from collection: $CollectionName"
    
    try {
        # Connect to SCCM site if not already connected
        if (-not (Get-PSDrive -Name $SiteCode -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name $SiteCode -PSProvider "AdminUI.PS.Provider\CMSite" -Root $SCCMServer -ErrorAction Stop
        }
        
        Set-Location "$($SiteCode):\" -ErrorAction Stop
        
        # Get collection members
        $Collection = Get-CMDeviceCollection -Name $CollectionName -ErrorAction Stop
        if (-not $Collection) {
            Write-Log "Collection '$CollectionName' not found" "ERROR"
            return $null
        }
        
        $CollectionMembers = Get-CMCollectionMember -CollectionId $Collection.CollectionId -ErrorAction Stop
        
        if ($WindowsServersOnly) {
            $FilteredComputers = $CollectionMembers | Where-Object {
                $_.OperatingSystem -like "*Server*" -or 
                $_.OperatingSystem -like "*Windows Server*"
            }
            Write-Log "Found $($FilteredComputers.Count) Windows Servers in collection"
            return $FilteredComputers
        } else {
            Write-Log "Found $($CollectionMembers.Count) computers in collection"
            return $CollectionMembers
        }
    }
    catch {
        Write-Log "Error retrieving computers from collection: $($_.Exception.Message)" "ERROR"
        return $null
    }
    finally {
        Set-Location "C:" -ErrorAction SilentlyContinue
    }
}

# Function to test computer connectivity
function Test-ComputerConnectivity {
    param([string]$ComputerName)
    
    try {
        if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop) {
            return $true
        } else {
            return $false
        }
    }
    catch {
        return $false
    }
}

# Enhanced SCCM health check function for remote computers
function Invoke-RemoteSCCMHealthCheck {
    param([string]$ComputerName)
    
    $HealthResult = [PSCustomObject]@{
        ComputerName = $ComputerName
        CheckDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Online = $false
        SCCMService = "Not Checked"
        ClientVersion = "Unknown"
        SiteAssignment = "Unknown"
        CacheHealthy = "Not Checked"
        ComponentsHealthy = "Not Checked"
        LastHardwareScan = "Unknown"
        LastSoftwareScan = "Unknown"
        ClientInstalled = $false
        RemediationAttempted = $false
        RemediationSuccess = $false
        OverallHealth = "Unknown"
    }
    
    # Test connectivity
    $IsOnline = Test-ComputerConnectivity -ComputerName $ComputerName
    $HealthResult.Online = $IsOnline
    
    if (-not $IsOnline) {
        $HealthResult.OverallHealth = "Offline"
        return $HealthResult
    }
    
    try {
        # Check if SCCM client is installed
        $Service = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-Service -Name "ccmexec" -ErrorAction SilentlyContinue
        } -ErrorAction Stop
        
        if ($Service) {
            $HealthResult.ClientInstalled = $true
            $HealthResult.SCCMService = $Service.Status.ToString()
            
            # Get detailed client information
            $ClientInfo = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                try {
                    $Client = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction Stop
                    $CacheInfo = Get-WmiObject -Namespace "root\ccm\SoftMgmtAgent" -Class "CacheConfig" -ErrorAction SilentlyContinue
                    $Components = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" | Select-Object -ExpandProperty ClientComponents -ErrorAction SilentlyContinue
                    
                    return @{
                        ClientVersion = $Client.ClientVersion
                        ClientSite = $Client.ClientSite
                        CacheSize = if ($CacheInfo) { [math]::Round($CacheInfo.Size / 1024, 2) } else { 0 }
                        CacheUsed = if ($CacheInfo) { [math]::Round($CacheInfo.Used / 1024, 2) } else { 0 }
                        Components = $Components
                    }
                }
                catch {
                    return $null
                }
            } -ErrorAction Stop
            
            if ($ClientInfo) {
                $HealthResult.ClientVersion = $ClientInfo.ClientVersion
                $HealthResult.SiteAssignment = $ClientInfo.ClientSite
                
                # Check cache health
                if ($ClientInfo.CacheSize -gt 0) {
                    $CacheUsagePercent = ($ClientInfo.CacheUsed / $ClientInfo.CacheSize) * 100
                    $HealthResult.CacheHealthy = if ($CacheUsagePercent -lt 90) { "Healthy" } else { "Critical" }
                }
                
                # Check components health
                if ($ClientInfo.Components) {
                    $DegradedComponents = $ClientInfo.Components | Where-Object { $_.Status -ne "Enabled" }
                    $HealthResult.ComponentsHealthy = if ($DegradedComponents.Count -eq 0) { "Healthy" } else { "Degraded" }
                }
                
                # Determine overall health
                $HealthScore = 0
                if ($Service.Status -eq "Running") { $HealthScore++ }
                if ($HealthResult.CacheHealthy -eq "Healthy") { $HealthScore++ }
                if ($HealthResult.ComponentsHealthy -eq "Healthy") { $HealthScore++ }
                if (-not [string]::IsNullOrEmpty($HealthResult.SiteAssignment)) { $HealthScore++ }
                
                $HealthResult.OverallHealth = switch ($HealthScore) {
                    { $_ -ge 3 } { "Healthy" }
                    { $_ -ge 2 } { "Warning" }
                    default { "Critical" }
                }
            }
        } else {
            $HealthResult.OverallHealth = "Client Not Installed"
        }
    }
    catch {
        Write-Log "Error checking health for $ComputerName : $($_.Exception.Message)" "WARNING"
        $HealthResult.OverallHealth = "Check Failed"
    }
    
    return $HealthResult
}

# Function to export results to multiple formats
function Export-HealthResults {
    param(
        [array]$HealthResults,
        [string]$ExportPath
    )
    
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $BaseFileName = "SCCM_ClientHealth_$Timestamp"
    
    # CSV Export
    $CsvPath = Join-Path $ExportPath "$BaseFileName.csv"
    try {
        $HealthResults | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Log "Results exported to CSV: $CsvPath"
    }
    catch {
        Write-Log "Failed to export CSV: $($_.Exception.Message)" "ERROR"
    }
    
    # HTML Export
    $HtmlPath = Join-Path $ExportPath "$BaseFileName.html"
    try {
        $HtmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>SCCM Client Health Report - $(Get-Date)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .healthy { background-color: #d4edda; }
        .warning { background-color: #fff3cd; }
        .critical { background-color: #f8d7da; }
        .offline { background-color: #e2e3e5; }
        .summary { margin-bottom: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>SCCM Client Health Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Generated: $(Get-Date)</p>
        <p>Total Computers: $($HealthResults.Count)</p>
        <p>Online: $(($HealthResults | Where-Object { $_.Online }).Count)</p>
        <p>Healthy: $(($HealthResults | Where-Object { $_.OverallHealth -eq 'Healthy' }).Count)</p>
        <p>Warning: $(($HealthResults | Where-Object { $_.OverallHealth -eq 'Warning' }).Count)</p>
        <p>Critical: $(($HealthResults | Where-Object { $_.OverallHealth -eq 'Critical' }).Count)</p>
    </div>
    <table>
        <thead>
            <tr>
                <th>Computer Name</th>
                <th>Online</th>
                <th>Client Installed</th>
                <th>SCCM Service</th>
                <th>Client Version</th>
                <th>Site Assignment</th>
                <th>Cache Health</th>
                <th>Components Health</th>
                <th>Overall Health</th>
            </tr>
        </thead>
        <tbody>
"@

        foreach ($Result in $HealthResults) {
            $RowClass = switch ($Result.OverallHealth) {
                "Healthy" { "healthy" }
                "Warning" { "warning" }
                "Critical" { "critical" }
                "Offline" { "offline" }
                default { "" }
            }
            
            $HtmlReport += @"
            <tr class="$RowClass">
                <td>$($Result.ComputerName)</td>
                <td>$($Result.Online)</td>
                <td>$($Result.ClientInstalled)</td>
                <td>$($Result.SCCMService)</td>
                <td>$($Result.ClientVersion)</td>
                <td>$($Result.SiteAssignment)</td>
                <td>$($Result.CacheHealthy)</td>
                <td>$($Result.ComponentsHealthy)</td>
                <td>$($Result.OverallHealth)</td>
            </tr>
"@
        }

        $HtmlReport += @"
        </tbody>
    </table>
</body>
</html>
"@
        $HtmlReport | Out-File -FilePath $HtmlPath -Encoding UTF8
        Write-Log "Results exported to HTML: $HtmlPath"
    }
    catch {
        Write-Log "Failed to export HTML: $($_.Exception.Message)" "ERROR"
    }
    
    # Excel Export (requires ImportExcel module)
    $ExcelPath = Join-Path $ExportPath "$BaseFileName.xlsx"
    try {
        if (Get-Module -ListAvailable -Name ImportExcel) {
            $HealthResults | Export-Excel -Path $ExcelPath -WorksheetName "ClientHealth" -AutoSize -AutoFilter -BoldTopRow -FreezeTopRow
            Write-Log "Results exported to Excel: $ExcelPath"
        } else {
            Write-Log "ImportExcel module not available. Skipping Excel export." "WARNING"
        }
    }
    catch {
        Write-Log "Failed to export Excel: $($_.Exception.Message)" "ERROR"
    }
    
    return @{
        CSV = $CsvPath
        HTML = $HtmlPath
        Excel = $ExcelPath
    }
}

# Function to generate summary report
function Get-HealthSummary {
    param([array]$HealthResults)
    
    $TotalComputers = $HealthResults.Count
    $OnlineComputers = ($HealthResults | Where-Object { $_.Online }).Count
    $HealthyComputers = ($HealthResults | Where-Object { $_.OverallHealth -eq "Healthy" }).Count
    $WarningComputers = ($HealthResults | Where-Object { $_.OverallHealth -eq "Warning" }).Count
    $CriticalComputers = ($HealthResults | Where-Object { $_.OverallHealth -eq "Critical" }).Count
    $OfflineComputers = ($HealthResults | Where-Object { -not $_.Online }).Count
    
    $Summary = [PSCustomObject]@{
        ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalComputers = $TotalComputers
        OnlineComputers = $OnlineComputers
        OfflineComputers = $OfflineComputers
        HealthyComputers = $HealthyComputers
        WarningComputers = $WarningComputers
        CriticalComputers = $CriticalComputers
        HealthPercentage = if ($OnlineComputers -gt 0) { [math]::Round(($HealthyComputers / $OnlineComputers) * 100, 2) } else { 0 }
    }
    
    return $Summary
}

# Main execution function
function Main {
    Write-Log "=== SCCM Client Health Check Started ===" "INFO"
    
    # Check administrative privileges
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "This script requires administrative privileges. Please run as Administrator." "ERROR"
        return
    }
    
    # Initialize export directory
    if (-not (Initialize-ExportDirectory)) {
        Write-Log "Failed to initialize export directory. Exiting." "ERROR"
        return
    }
    
    # Get computer list
    $Computers = @()
    
    if ($ComputerList.Count -gt 0) {
        Write-Log "Using manually specified computer list with $($ComputerList.Count) computers"
        $Computers = $ComputerList
    } else {
        Write-Log "Retrieving computers from SCCM collection: $TargetDeviceCollection"
        $CollectionComputers = Get-ComputersFromCollection -CollectionName $TargetDeviceCollection -WindowsServersOnly $TargetOnlyWindowsServers
        
        if ($CollectionComputers) {
            $Computers = $CollectionComputers.Name
            Write-Log "Retrieved $($Computers.Count) computers from collection"
        } else {
            Write-Log "No computers found in collection. Using local computer only." "WARNING"
            $Computers = @($env:COMPUTERNAME)
        }
    }
    
    if ($Computers.Count -eq 0) {
        Write-Log "No computers to check. Exiting." "ERROR"
        return
    }
    
    # Perform health checks
    Write-Log "Starting health checks for $($Computers.Count) computers..."
    $HealthResults = @()
    $Counter = 0
    
    foreach ($Computer in $Computers) {
        $Counter++
        Write-Log "Checking $Computer ($Counter of $($Computers.Count))..."
        
        $HealthResult = Invoke-RemoteSCCMHealthCheck -ComputerName $Computer
        $HealthResults += $HealthResult
        
        # Small delay to avoid overwhelming systems
        Start-Sleep -Milliseconds 100
    }
    
    # Generate summary and export results
    Write-Log "Generating reports and exporting results..."
    $Summary = Get-HealthSummary -HealthResults $HealthResults
    $ExportFiles = Export-HealthResults -HealthResults $HealthResults -ExportPath $ExportPath
    
    # Display summary
    Write-Log "=== SCCM Client Health Summary ===" "INFO"
    Write-Log "Total Computers: $($Summary.TotalComputers)" "INFO"
    Write-Log "Online: $($Summary.OnlineComputers)" "INFO"
    Write-Log "Offline: $($Summary.OfflineComputers)" "INFO"
    Write-Log "Healthy: $($Summary.HealthyComputers)" "INFO"
    Write-Log "Warning: $($Summary.WarningComputers)" "INFO"
    Write-Log "Critical: $($Summary.CriticalComputers)" "INFO"
    Write-Log "Health Percentage: $($Summary.HealthPercentage)%" "INFO"
    
    Write-Log "=== Export Files Created ===" "INFO"
    foreach ($Format in $ExportFiles.Keys) {
        if (Test-Path $ExportFiles[$Format]) {
            Write-Log "$($Format.ToUpper()): $($ExportFiles[$Format])" "INFO"
        }
    }
    
    Write-Log "=== SCCM Client Health Check Completed ===" "INFO"
}

# Execute main function
Main
