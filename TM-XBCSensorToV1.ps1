# =====================================================
# Trend Micro XBC (Endpoint Basecamp) to V1 Script.ed #
# =====================================================

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You are not running as an Administrator. Please run with elevated privileges."
    exit 1
}

# PASTE THE VALUE OF JSON BELOW BEFORE RUNNING THE SCRIPT
##### SAMPLE WHAT WOULD LOOK LIKE #####
# $JSON = @'
# {
#   "ce_uninstall_tool": {
#     "x64": "https://url.zip",
#     "x86": "https://url.zip"
#   },
#   "jwt": "xxxx-xxxx",
#   "xbc_uninstall_tool": "https://url.exe"
# }
# '@ | ConvertFrom-Json

# JSON Configuration. Paste Value below.
$JSON = @'

'@ | ConvertFrom-Json

# Variables
$XBCtoken           = $JSON.jwt
$XBCuninstallerPack = $JSON.xbc_uninstall_tool
$ce_uninstaller_x86 = $JSON.ce_uninstall_tool.x86
$ce_uninstaller_x64 = $JSON.ce_uninstall_tool.x64
$TMdir              = "C:\Program Files (x86)\Trend Micro"
$TempPath           = "C:\temp"

# Ensure temp folder exists
if (-not (Test-Path $TempPath)) {
    New-Item -Path $TempPath -ItemType Directory -Force | Out-Null
}

function Remove-UninstallFiles {
    Start-Sleep -Seconds 5
    Set-Location $TempPath
    Remove-Item -Path @(
        "XBCUninstallToken.txt",
        "XBCUninstaller.exe",
        "CloudEndpointServiceWebInstaller.exe",
        "ce_uninstaller_x86.zip",
        "ce_uninstaller_x64.zip",
        "ce_uninstaller_x86",
        "ce_uninstaller_x64",
        "XBC"
    ) -Recurse -Force -ErrorAction SilentlyContinue
}

# ============================
# Removing Existing XBC Agent
# ============================
if (Test-Path $TMdir) {
    Write-Host "Starting XBC/Basecamp Removal Process" -ForegroundColor Green
    Set-Location $TempPath

    try {
        Invoke-WebRequest -Uri $XBCuninstallerPack -OutFile "XBCUninstaller.exe" -UseBasicParsing -ErrorAction Stop
        Invoke-WebRequest -Uri $ce_uninstaller_x64 -OutFile "ce_uninstaller_x64.zip" -UseBasicParsing -ErrorAction Stop
        Invoke-WebRequest -Uri $ce_uninstaller_x86 -OutFile "ce_uninstaller_x86.zip" -UseBasicParsing -ErrorAction Stop

        Expand-Archive "ce_uninstaller_x86.zip" -DestinationPath $TempPath -Force
        Expand-Archive "ce_uninstaller_x64.zip" -DestinationPath $TempPath -Force

        Set-Content -Path "XBCUninstallToken.txt" -Value $XBCtoken -Force

        & "$TempPath\XBCUninstaller.exe" "XBCUninstallToken.txt"
        Remove-Item "$TMdir\Endpoint Basecamp" -Recurse -Force -ErrorAction SilentlyContinue

        Write-Host "Uninstall Process Completed" -ForegroundColor Green
    }
    catch {
        Write-Host "Error during uninstall: $($_.Exception.Message)" -ForegroundColor Red
        exit 2
    }
}

Write-Host "Cleaning up uninstall files..." -ForegroundColor Green
Remove-UninstallFiles

# Verify uninstall success
if(Test-Path -Path "$TMdir\Endpoint Basecamp" -ErrorAction SilentlyContinue){
   Write-Host "The agent still exists, the uninstall has failed. To determine cause try using the uninstaller manually to view error." -ForegroundColor Red
   exit 2
}
######################################################
# PASTE THE BODY OF V1 Sensor Deployment Script Below
######################################################
# =============================
# Setup Logging
# =============================
# Set log path
$env:LogPath = "$env:appdata\Trend Micro\V1ES"
New-Item -path $env:LogPath -type directory -Force
Start-Transcript -path "$env:LogPath\v1es_install.log" -append


## Pre-Check
# Check authorization
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "$(Get-Date -format T) You are not running as an Administrator. Please try again with admin privileges." -ForegroundColor Red
    Stop-Transcript
    exit 1
}

# Check if Invoke-WebRequest is available
if (-not (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue)) {
    Write-Host "$(Get-Date -format T) Invoke-WebRequest is not available. Please install PowerShell 3.0 or later." -ForegroundColor Red
    Stop-Transcript
    exit 1
}

# Check if Expand-Archive is available
if (-not (Get-Command Expand-Archive -ErrorAction SilentlyContinue)) {
    Write-Host "$(Get-Date -format T) Expand-Archive is not available. Please install PowerShell 5.0 or later." -ForegroundColor Red
    Stop-Transcript
    exit 1
}

Write-Host "$(Get-Date -format T) Start deploying." -ForegroundColor White


# Proxy_Addr_Port and Proxy_User/Proxy_Password define proxy for software download and Agent activation
$PROXY_ADDR_PORT="" 
$PROXY_USERNAME=""
$PROXY_PASSWORD=""

# Compose proxy URI, credential, and credential object
$PROXY_URI=""
$PROXY_CREDENTIAL=""
$PROXY_CREDENTIAL_OBJ=$null
if ($PROXY_ADDR_PORT.Length -ne 0) {
    $PROXY_ADDR_PORT=$PROXY_ADDR_PORT.Trim()
    $PROXY_URI="http://$PROXY_ADDR_PORT"

    if ($PROXY_USERNAME.Length -ne 0) {
        $PROXY_USERNAME=$PROXY_USERNAME.Trim()
        $PROXY_CREDENTIAL="${PROXY_USERNAME}:"
        $PROXY_CREDENTIAL_OBJ = New-Object System.Management.Automation.PSCredential ($PROXY_USERNAME, (new-object System.Security.SecureString))

        if ($PROXY_PASSWORD.Length -ne 0) {
            $PROXY_PASSWORD=$PROXY_PASSWORD.Trim()
            $PROXY_CREDENTIAL="${PROXY_USERNAME}:${PROXY_PASSWORD}"
            $PROXY_CREDENTIAL_OBJ = New-Object System.Management.Automation.PSCredential ($PROXY_USERNAME, (ConvertTo-SecureString -String $PROXY_PASSWORD -AsPlainText -Force))
        }

        # Encode proxy credential by base64
        $CREDENTIAL_ENCODE=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PROXY_CREDENTIAL))
        $PROXY_URI="$CREDENTIAL_ENCODE@$PROXY_ADDR_PORT" # Don't prepend "http://" to the proxy URI
    }
}

## Get Package
$XBC_INSTALLER_PATH = "$env:TEMP\XBC_Installer.zip"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        


## Download XBC installer
$XBC_FQDN="api-mea.xbc.trendmicro.com"
$GET_INSTALLER_URL="https://$XBC_FQDN/apk/installer"
$HTTP_BODY='{"company_id":"nnnnn-nnnnn-nnnnnn"]}'
$HTTP_HEADER = @{"X-Customer-Id"="xxxxx-xxxxxx"}

Write-Host "$(Get-Date -format T) Start downloading the installer." -ForegroundColor White

try {
    if ($PROXY_ADDR_PORT.Length -eq 0) {
        $response = Invoke-WebRequest -Uri "$GET_INSTALLER_URL" -Method Post -Body "$HTTP_BODY" -ContentType "application/json" -Headers $HTTP_HEADER -OutFile "$XBC_INSTALLER_PATH"
    }
    elseif ($PROXY_CREDENTIAL.Length -eq 0) {
        $response = Invoke-WebRequest -Uri "$GET_INSTALLER_URL" -Method Post -Body "$HTTP_BODY" -ContentType "application/json" -Proxy "http://$PROXY_ADDR_PORT" -Headers $HTTP_HEADER -OutFile "$XBC_INSTALLER_PATH"
    }
    else {
        $response = Invoke-WebRequest -Uri "$GET_INSTALLER_URL" -Method Post -Body "$HTTP_BODY" -ContentType "application/json" -Proxy "http://$PROXY_ADDR_PORT" -ProxyCredential $PROXY_CREDENTIAL_OBJ -Headers $HTTP_HEADER -OutFile "$XBC_INSTALLER_PATH"
    }
    if ($response.StatusCode -ge 400) {
        Write-Host "$(Get-Date -format T) Failed to download the installer." -ForegroundColor Red
        Stop-Transcript
        exit 1
    }
} catch {
    Write-Host "$(Get-Date -format T) Failed to download the installer." -ForegroundColor Red
    Stop-Transcript
    exit 1
}
Write-Host "$(Get-Date -format T) The installer was downloaded to $XBC_INSTALLER_PATH." -ForegroundColor White

## Unzip XBC installer / full package
$XBC_INSTALLER_DIR = "$env:TEMP\XBC_Installer"
Write-Host "$(Get-Date -format T) Start unzipping the installer / full package." -ForegroundColor White
try {
    Expand-Archive -Path $XBC_INSTALLER_PATH -DestinationPath $XBC_INSTALLER_DIR -Force
    Write-Host "$(Get-Date -format T) The installer / full package was unzipped to $XBC_INSTALLER_DIR." -ForegroundColor White
} catch {
    Write-Host "$(Get-Date -format T) Failed to unzip the installer / full package. Error: $_.Exception.Message." -ForegroundColor Red
    Stop-Transcript
    exit 1
}

## Install XBC
$XBC_INSTALLER_EXE = "$XBC_INSTALLER_DIR\EndpointBasecamp.exe"

$ARCH_TYPE = if ([System.Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }



# Architecture = x86 (0), x64 (9), ARM64 (12)
$IS_AARCH64 = (Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty Architecture) -eq 12
$AGENT_TOKEN_WIN64 = "yyyyyy-yyyyyyy-yyyyyy"
$AGENT_TOKEN_WIN32 = "yyyyyy-yyyyyyy-yyyyyy"
$AGENT_TOKEN_AARCH64 = "yyyyyy-yyyyyyy-yyyyyy"
Write-Host "$(Get-Date -format T) Start installing the agent." -ForegroundColor White
try {
    if ($PROXY_ADDR_PORT.Length -eq 0) {
        $CONNECT_CONFIG = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"fps":[{"connections": [{"type": "DIRECT_CONNECT"}]}]}'))
    } else {
        $CONNECT_CONFIG = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"fps":[{"connections": [{"type": "USER_INPUT"}]}]}'))
    }

	if ($IS_AARCH64) {
		$XBC_AGENT_TOKEN = $AGENT_TOKEN_AARCH64
	}
	elseif ($ARCH_TYPE -eq "x86_64"){
		 $XBC_AGENT_TOKEN = $AGENT_TOKEN_WIN64
	}
	else {
        $XBC_AGENT_TOKEN = $AGENT_TOKEN_WIN32
    }
	
    if ($PROXY_URI.Length -ne 0) {
		$result = & "$XBC_INSTALLER_EXE" /connection $CONNECT_CONFIG /agent_token $XBC_AGENT_TOKEN /is_full_package true /proxy_server_port $PROXY_URI
	} else {
		$result = & "$XBC_INSTALLER_EXE" /connection $CONNECT_CONFIG /agent_token $XBC_AGENT_TOKEN /is_full_package true
	}
    $exitCode = $LASTEXITCODE
	if ($exitCode -ne 0) {
		Write-Host "$(Get-Date -format T) Failed to install the agent. Error: $result" -ForegroundColor Red
		Stop-Transcript
		exit 1
	}
    Write-Host "$(Get-Date -format T) The agent is installed." -ForegroundColor White
} catch {
    Write-Host "$(Get-Date -format T) Failed to install the agent." -ForegroundColor Red
    Stop-Transcript
    exit 1
}

## Check XBC registration
if ($ARCH_TYPE -eq "x86_64") {
    $XBC_REGISTRATION_KEY = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TrendMicro\TMSecurityService"
} else {
    $XBC_REGISTRATION_KEY = "HKEY_LOCAL_MACHINE\SOFTWARE\TrendMicro\TMSecurityService"
}
$XBC_DEVICE_ID = reg query "$XBC_REGISTRATION_KEY"
$RETRY_COUNT = 0
$MAX_RETRY = 30
while ($XBC_DEVICE_ID.Length -eq 0) {
    $RETRY_COUNT++
    if ($RETRY_COUNT -ge $MAX_RETRY) {
        Write-Host "$(Get-Date -format T) The agent registration failed. Please see the EndpointBasecamp.log for more details." -ForegroundColor Red
        Stop-Transcript
        exit 1
    }
    Write-Host "$(Get-Date -format T) The agent is not registered yet. Please wait 10 seconds." -ForegroundColor White
    Start-Sleep -Seconds 10
    $XBC_DEVICE_ID = reg query "$XBC_REGISTRATION_KEY"
}
Write-Host "$(Get-Date -format T) The agent is registered." -ForegroundColor White

Write-Host "$(Get-Date -format T) Finish deploying." -ForegroundColor White
Stop-Transcript
exit 0

