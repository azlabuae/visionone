# --- Admin Privilege Check ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "$(Get-Date -format T) You are not running as an Administrator. Please try again with admin privileges." -ForegroundColor Red
    exit 1
}

# ==========================================
# Trend Micro A1/SEP IPXfer Script. -ed
# ==========================================

# --- EDIT THESE VALUES BEFORE RUNNING ---
$BaseUrl  = "https://url.com:443/"   # <---- CHANGE THIS TO YOUR SERVER URL (include port if needed)
$UnloadPw = "MySecretUnloadpw123"   # <---- CHANGE THIS TO YOUR PASSWORD

# --- Setup Paths ---
$TempFolder = Join-Path $env:TEMP "xfer_tool"
$LogFile    = Join-Path $env:TEMP ("xfer_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

# --- Clean Up Old Folder ---
if (Test-Path $TempFolder) {
    try {
        Remove-Item -Path $TempFolder -Recurse -Force
        Write-Host "Old xfer_tool folder deleted from TEMP."
    }
    catch {
        Write-Host "WARNING: Failed to delete old xfer_tool folder. $_"
    }
}

# --- Create Fresh Folder ---
New-Item -ItemType Directory -Path $TempFolder -Force | Out-Null

# --- Ensure log file exists (create new if missing) ---
try {
    if (-not (Test-Path $LogFile)) {
        New-Item -ItemType File -Path $LogFile -Force | Out-Null
    }
}
catch {
    Write-Host "WARNING: Could not create log file. Logging disabled."
    $LogFile = $null
}

# --- Logging Helper ---
function Write-Log {
    param([string]$Message)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "$timestamp - $Message"

    if ($null -ne $LogFile) {
        try {
            $logEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            Write-Host "WARNING: Cannot write to log file. Disabling logging for remainder of run."
            $GLOBALS:LogFile = $null
        }
    }

    Write-Host $logEntry
}

Write-Log "Starting xfer tool setup..."
Write-Log "Base URL: $BaseUrl"
Write-Log "Password is set (hidden in log)."

# --- Extract Hostname from BaseUrl ---
try {
    $uri = [System.Uri]$BaseUrl
    $HostName = $uri.Host   # e.g., url.com
    Write-Log "Extracted Hostname: $HostName"
}
catch {
    Write-Log "ERROR: Failed to parse BaseUrl. $_"
    throw
}

# --- Detect System Architecture ---
$is64bit = $env:PROCESSOR_ARCHITECTURE -eq "AMD64"
if ($is64bit) {
    Write-Log "Detected 64-bit system"
} else {
    Write-Log "Detected 32-bit system"
}

# --- Download Helper ---
function Download-File {
    param(
        [string]$Url,
        [string]$DestinationPath
    )

    try {
        Write-Log "Downloading $Url to $DestinationPath"
        Invoke-WebRequest -Uri $Url -OutFile $DestinationPath -UseBasicParsing
    }
    catch {
        Write-Log "ERROR: Failed to download $Url. $_"
        throw
    }
}

# --- Build URLs & Download Files ---
if ($is64bit) {
    Download-File "$BaseUrl/officescan/hotfix_admin/utility/ipxfer/ipxfer_x64.exe" (Join-Path $TempFolder "ipxfer_x64.exe")
    Download-File "$BaseUrl/officescan/hotfix_pccnt/Common/OfcNTCer.dat" (Join-Path $TempFolder "OfcNTCer.dat")
} else {
    Download-File "$BaseUrl/officescan/hotfix_admin/utility/ipxfer/ipxfer.exe" (Join-Path $TempFolder "ipxfer.exe")
    Download-File "$BaseUrl/officescan/hotfix_pccnt/Common/OfcNTCer.dat" (Join-Path $TempFolder "OfcNTCer.dat")
}

# --- Execute Files with Secure Password Masking ---
try {
    if ($is64bit) {
        $exePath = Join-Path $TempFolder "ipxfer_x64.exe"
        $datPath = Join-Path $TempFolder "OfcNTCer.dat"
    } else {
        $exePath = Join-Path $TempFolder "ipxfer.exe"
        $datPath = Join-Path $TempFolder "OfcNTCer.dat"
    }

    # Build arguments as array (so password not shown in plain text)
    $args = @(
        "-s", $HostName,
        "-p", "80",
        "-sp", "443",
        "-e", $datPath,
        "-pwd", $UnloadPw
        "-acsoff"
    )

    # Create a safe version for logging (mask password)
    $safeArgs = $args.Clone()
    $pwdIndex = $safeArgs.IndexOf("-pwd")
    if ($pwdIndex -ge 0 -and ($pwdIndex + 1) -lt $safeArgs.Count) {
        $safeArgs[$pwdIndex + 1] = "********"
    }
    Write-Log "Executing: $exePath $($safeArgs -join ' ')"

    Start-Process -FilePath $exePath -ArgumentList $args -Wait -NoNewWindow
    Write-Log "Execution completed successfully."
}
catch {
    Write-Log "ERROR: Execution failed. $_"
    throw
}

Write-Log "xfer tool process finished."
