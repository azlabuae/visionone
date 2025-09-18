# --- Admin Privilege Check ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "$(Get-Date -format T) You are not running as an Administrator. Please try again with admin privileges." -ForegroundColor Red
    exit 1
}

# ==========================================
# Trend Micro SWP Re-Activation Script. -ed
# ==========================================

# --- EDIT THESE VALUES BEFORE RUNNING ---
$UnloadPw   = "MySecretUnloadPw123"   # Change this before running. Skip edit if you have Deactivated the agent from DSM Console prior
$TenantID   = "xxxxx-xxxxx-xxxxx"     # Change this before running
$Token      = "aaaaaa-aaaaaa-aaaaaa"  # Change this before running
$ACTIVATIONURL = "dsm://agents.deepsecurity.trendmicro.com:443/"  # Change this if needed

# --- Derived Values ---
$SWPTenant = @("tenantID:$TenantID", "token:$Token")
$AgentControl = Join-Path $Env:ProgramFiles "Trend Micro\Deep Security Agent\dsa_control"

# --- Prepare Log Path ---
$LogFolder = Join-Path $env:APPDATA "Trend Micro\Deep Security Agent\installer"
if (-not (Test-Path $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
}
$LogFile = Join-Path $LogFolder ("dsa_swp_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

# --- Logging Function ---
function Write-Log {
    param([string]$Message)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "$timestamp - $Message"
    try {
        $logEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8
    } catch {
        Write-Host "WARNING: Failed to write log file. $_"
    }
    Write-Host $logEntry
}

Write-Log "===== SWP Activation Script Started ====="
Write-Log "TenantID: $TenantID"
Write-Log "Activation URL: $ACTIVATIONURL"
Write-Log "Using dsa_control.exe path: $AgentControl"

# --- Execute Commands ---
try {
    # 1. Unload Agent
    Write-Log "Executing: $AgentControl -s=0 -p ********"
    & $AgentControl -s=0 -p "$UnloadPw" # <---- Comment this line by adding # if you have Deactivated the agent from DSM Console prior
    Write-Log "Unload command completed."

    # 2. Reset Agent
    Write-Log "Executing: $AgentControl -r"
    & $AgentControl -r
    Write-Log "Reset command completed."

    # Get machine FQDN
    $FQDN = [System.Net.Dns]::GetHostEntry('').HostName
    Write-Log "Machine FQDN detected: $FQDN"

    # 3. Activate Agent with FQDN
    Write-Log "Executing: $AgentControl -a $ACTIVATIONURL $($SWPTenant -join ' ') hostname $FQDN"
    & $AgentControl -a $ACTIVATIONURL @SWPTenant "displayname:$FQDN"
    #& $AgentControl -a $ACTIVATIONURL @SWPTenant "hostname:$FQDN" # <---- Use this sample format if you prefer changing hostname
    #& $AgentControl -a $ACTIVATIONURL @SWPTenant "policyid:1" # <---- Use this sample format if you prefer assigning policy
    Write-Log "Activation command completed."

    Write-Log "===== SWP Activation Script Completed Successfully ====="
}
catch {
    Write-Log "ERROR: Command execution failed. $_"
    Write-Log "===== Script Exiting Due to Error ====="
    exit 1
}

exit 0
