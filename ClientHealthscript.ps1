<#
.SYNOPSIS
    SCCM Client Health Check and Remediation Script
.DESCRIPTION
    This script checks various SCCM client components and attempts to fix common issues
.NOTES
    Author: IT Administrator
    Version: 1.2
    Requires: Administrative privileges
#>

# Script Configuration
$LogPath = "C:\Windows\Logs\SCCM_Client_Health.log"
$MaxLogSize = 10MB

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
        # Check if log file exists and its size
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

# Function to check if running as administrator
function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to check SCCM client service
function Test-SCCMService {
    Write-Log "Checking SCCM Client Service..."
    
    $Service = Get-Service -Name "ccmexec" -ErrorAction SilentlyContinue
    
    if ($Service) {
        if ($Service.Status -eq "Running") {
            Write-Log "SCCM Client Service is running" "INFO"
            return $true
        } else {
            Write-Log "SCCM Client Service is not running. Current status: $($Service.Status)" "WARNING"
            return $false
        }
    } else {
        Write-Log "SCCM Client Service (ccmexec) not found" "ERROR"
        return $false
    }
}

# Function to start SCCM client service
function Start-SCCMService {
    Write-Log "Attempting to start SCCM Client Service..."
    
    try {
        Start-Service -Name "ccmexec" -ErrorAction Stop
        Start-Sleep -Seconds 5
        
        $Service = Get-Service -Name "ccmexec"
        if ($Service.Status -eq "Running") {
            Write-Log "SCCM Client Service started successfully" "INFO"
            return $true
        } else {
            Write-Log "Failed to start SCCM Client Service" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error starting SCCM Client Service: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to check client components
function Test-ClientComponents {
    Write-Log "Checking SCCM Client Components..."
    
    try {
        $Components = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" | 
                     Select-Object -ExpandProperty ClientComponents -ErrorAction Stop
        
        if ($Components) {
            Write-Log "Client components retrieved successfully" "INFO"
            
            # Check for any components in degraded state
            $DegradedComponents = $Components | Where-Object { $_.Status -ne "Enabled" }
            
            if ($DegradedComponents) {
                Write-Log "Found degraded components:" "WARNING"
                foreach ($Component in $DegradedComponents) {
                    Write-Log "  - $($Component.Name): $($Component.Status)" "WARNING"
                }
                return $false
            } else {
                Write-Log "All client components are healthy" "INFO"
                return $true
            }
        } else {
            Write-Log "Unable to retrieve client components" "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Error checking client components: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to trigger client component remediation
function Repair-ClientComponents {
    Write-Log "Initiating client component repair..."
    
    try {
        # Reset client policy
        Write-Log "Resetting client policy..."
        Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name ResetPolicy -ArgumentList 1 -ErrorAction Stop
        
        # Repair client
        Write-Log "Starting client repair..."
        $Service = Get-WmiObject -Class "Win32_Service" -Filter "Name='ccmexec'"
        $Service.InvokeMethod("StopService", $null) | Out-Null
        Start-Sleep -Seconds 10
        
        # Start the service
        $Service.InvokeMethod("StartService", $null) | Out-Null
        Start-Sleep -Seconds 10
        
        Write-Log "Client component repair completed" "INFO"
        return $true
    }
    catch {
        Write-Log "Error repairing client components: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to check client cache
function Test-ClientCache {
    Write-Log "Checking client cache..."
    
    try {
        $CacheInfo = Get-WmiObject -Namespace "root\ccm\SoftMgmtAgent" -Class "CacheConfig" -ErrorAction Stop
        
        if ($CacheInfo) {
            $CacheSizeMB = [math]::Round($CacheInfo.Size / 1024, 2)
            $CacheUsedMB = [math]::Round($CacheInfo.Used / 1024, 2)
            $CacheFreeMB = [math]::Round($CacheInfo.Free / 1024, 2)
            
            Write-Log "Cache Size: ${CacheSizeMB}MB, Used: ${CacheUsedMB}MB, Free: ${CacheFreeMB}MB" "INFO"
            
            # Check if cache is nearly full (above 90%)
            if ($CacheUsedMB / $CacheSizeMB -gt 0.9) {
                Write-Log "Client cache is nearly full (above 90%)" "WARNING"
                return $false
            } else {
                Write-Log "Client cache is healthy" "INFO"
                return $true
            }
        } else {
            Write-Log "Unable to retrieve cache information" "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Error checking client cache: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to clear client cache
function Clear-ClientCache {
    Write-Log "Clearing client cache..."
    
    try {
        $CacheElements = Get-WmiObject -Namespace "root\ccm\SoftMgmtAgent" -Class "CacheInfo" -ErrorAction Stop
        
        if ($CacheElements) {
            foreach ($Element in $CacheElements) {
                $Element.Delete() | Out-Null
            }
            Write-Log "Client cache cleared successfully" "INFO"
            return $true
        } else {
            Write-Log "No cache elements found to clear" "INFO"
            return $true
        }
    }
    catch {
        Write-Log "Error clearing client cache: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to check client assignments
function Test-ClientAssignment {
    Write-Log "Checking client site assignment..."
    
    try {
        $Client = Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client" -ErrorAction Stop
        
        if ($Client) {
            Write-Log "Client assigned to site: $($Client.ClientSite)" "INFO"
            
            if ([string]::IsNullOrEmpty($Client.ClientSite)) {
                Write-Log "Client is not assigned to any site" "WARNING"
                return $false
            } else {
                Write-Log "Client site assignment is valid" "INFO"
                return $true
            }
        } else {
            Write-Log "Unable to retrieve client information" "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Error checking client assignment: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to trigger client actions
function Invoke-ClientActions {
    Write-Log "Triggering SCCM client actions..."
    
    try {
        # Get client instance
        $Client = Get-WmiObject -Namespace "root\ccm" -Class "SMS_CLIENT"
        
        # Define actions to trigger
        $Actions = @(
            "RequestMachinePolicy",
            "EvaluateMachinePolicy",
            "RequestUserPolicy",
            "EvaluateUserPolicy",
            "SoftwareInventoryCycle",
            "HardwareInventoryCycle",
            "DiscoveryDataCollectionCycle"
        )
        
        foreach ($Action in $Actions) {
            Write-Log "Triggering action: $Action"
            try {
                $Client.TriggerSchedule("{" + $Action + "}") | Out-Null
                Start-Sleep -Seconds 2
            }
            catch {
                Write-Log "Failed to trigger action $Action : $($_.Exception.Message)" "WARNING"
            }
        }
        
        Write-Log "All client actions triggered successfully" "INFO"
        return $true
    }
    catch {
        Write-Log "Error triggering client actions: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to check client version
function Test-ClientVersion {
    Write-Log "Checking client version..."
    
    try {
        $ClientVersion = (Get-WmiObject -Namespace "root\ccm" -Class "SMS_Client").ClientVersion
        
        if ($ClientVersion) {
            Write-Log "Current client version: $ClientVersion" "INFO"
            return $true
        } else {
            Write-Log "Unable to determine client version" "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Error checking client version: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to perform full client remediation
function Start-FullClientRemediation {
    Write-Log "Starting full SCCM client remediation..." "INFO"
    
    # Stop SCCM service
    Write-Log "Stopping SCCM services..."
    Stop-Service -Name "ccmexec" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "CmRcService" -Force -ErrorAction SilentlyContinue
    
    # Wait for services to stop
    Start-Sleep -Seconds 10
    
    # Rename problematic folders
    $ProblemFolders = @(
        "$env:windir\ccm",
        "$env:windir\ccmsetup",
        "$env:windir\SMSCFG.ini",
        "$env:windir\SMS*.mif"
    )
    
    foreach ($Folder in $ProblemFolders) {
        if (Test-Path $Folder) {
            $BackupPath = $Folder + ".backup"
            try {
                Rename-Item -Path $Folder -NewName $BackupPath -Force -ErrorAction Stop
                Write-Log "Renamed $Folder to $BackupPath" "INFO"
            }
            catch {
                Write-Log "Failed to rename $Folder : $($_.Exception.Message)" "WARNING"
            }
        }
    }
    
    # Reinstall client (this would need to be customized for your environment)
    Write-Log "Note: Automatic reinstallation requires manual configuration" "INFO"
    Write-Log "Please run client installation manually if needed" "INFO"
    
    return $true
}

# Main execution block
function Main {
    Write-Log "=== SCCM Client Health Check Started ===" "INFO"
    
    # Check if running as administrator
    if (-not (Test-Administrator)) {
        Write-Log "This script requires administrative privileges. Please run as Administrator." "ERROR"
        return
    }
    
    # Array to track remediation results
    $RemediationResults = @()
    
    # Perform health checks
    Write-Log "Performing SCCM client health checks..." "INFO"
    
    # Check 1: Client Service
    $ServiceHealthy = Test-SCCMService
    if (-not $ServiceHealthy) {
        Write-Log "Attempting to start SCCM service..." "INFO"
        $ServiceRemediated = Start-SCCMService
        $RemediationResults += @{ Check = "Service"; Healthy = $ServiceHealthy; Remediated = $ServiceRemediated }
    } else {
        $RemediationResults += @{ Check = "Service"; Healthy = $true; Remediated = $true }
    }
    
    # Check 2: Client Components
    $ComponentsHealthy = Test-ClientComponents
    if (-not $ComponentsHealthy) {
        Write-Log "Attempting to repair client components..." "INFO"
        $ComponentsRemediated = Repair-ClientComponents
        $RemediationResults += @{ Check = "Components"; Healthy = $ComponentsHealthy; Remediated = $ComponentsRemediated }
    } else {
        $RemediationResults += @{ Check = "Components"; Healthy = $true; Remediated = $true }
    }
    
    # Check 3: Client Cache
    $CacheHealthy = Test-ClientCache
    if (-not $CacheHealthy) {
        Write-Log "Attempting to clear client cache..." "INFO"
        $CacheRemediated = Clear-ClientCache
        $RemediationResults += @{ Check = "Cache"; Healthy = $CacheHealthy; Remediated = $CacheRemediated }
    } else {
        $RemediationResults += @{ Check = "Cache"; Healthy = $true; Remediated = $true }
    }
    
    # Check 4: Client Assignment
    $AssignmentHealthy = Test-ClientAssignment
    $RemediationResults += @{ Check = "Assignment"; Healthy = $AssignmentHealthy; Remediated = $AssignmentHealthy }
    
    # Check 5: Client Version
    $VersionHealthy = Test-ClientVersion
    $RemediationResults += @{ Check = "Version"; Healthy = $VersionHealthy; Remediated = $VersionHealthy }
    
    # Trigger client actions
    Write-Log "Triggering client actions for synchronization..." "INFO"
    $ActionsTriggered = Invoke-ClientActions
    $RemediationResults += @{ Check = "Actions"; Healthy = $ActionsTriggered; Remediated = $ActionsTriggered }
    
    # Summary report
    Write-Log "=== SCCM Client Health Check Summary ===" "INFO"
    $HealthyCount = ($RemediationResults | Where-Object { $_.Healthy }).Count
    $TotalCount = $RemediationResults.Count
    
    Write-Log "Health Score: $HealthyCount/$TotalCount checks passed" "INFO"
    
    foreach ($Result in $RemediationResults) {
        $Status = if ($Result.Healthy) { "HEALTHY" } else { if ($Result.Remediated) { "REMEDIATED" } else { "FAILED" } }
        Write-Log "  - $($Result.Check): $Status" "INFO"
    }
    
    # Final recommendation
    if ($HealthyCount -eq $TotalCount) {
        Write-Log "All SCCM client components are healthy. No further action required." "INFO"
    } else {
        Write-Log "Some issues were detected. Consider running full remediation if problems persist." "WARNING"
        Write-Log "To run full remediation, uncomment the Start-FullClientRemediation call in the script." "INFO"
        # Uncomment the line below for full remediation
        # Start-FullClientRemediation
    }
    
    Write-Log "=== SCCM Client Health Check Completed ===" "INFO"
}

# Execute main function
Mainwdw
