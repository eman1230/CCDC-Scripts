<# 
    CCDC Windows Hardening Bootstrap (Safe / Non-Disruptive)
    - Does NOT stop/disable any services
    - Does NOT change firewall default policies or close ports
    - Focuses on:
        * Inventory (users, groups, services, ports, tasks, firewall)
        * Enabling auditing
        * Enabling PowerShell logging
        * Enabling firewall logging
#>

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Run this script from an elevated PowerShell session (Run as Administrator)."
    exit 1
}

$BaseDir = "C:\CCDC_Hardening"
$LogDir  = Join-Path $BaseDir "Logs"
$DateTag = Get-Date -Format "yyyyMMdd_HHmmss"

New-Item -ItemType Directory -Force -Path $BaseDir, $LogDir | Out-Null

Write-Host "[*] Output directory: $LogDir"

# ------------------------------
# 1. Baseline Inventory (Safe)
# ------------------------------

Write-Host "[*] Collecting user and group information..."
net user                     | Out-File -Encoding UTF8 (Join-Path $LogDir "net_user_$DateTag.txt")
Get-LocalUser               | Out-File -Encoding UTF8 (Join-Path $LogDir "local_users_$DateTag.txt")
Get-LocalGroup              | Out-File -Encoding UTF8 (Join-Path $LogDir "local_groups_$DateTag.txt")
Get-LocalGroup | ForEach-Object {
    $g = $_.Name
    try {
        Get-LocalGroupMember -Group $g | 
            Select-Object Name, ObjectClass, PrincipalSource |
            Out-File -Append -Encoding UTF8 (Join-Path $LogDir "group_members_$DateTag.txt")
        Add-Content (Join-Path $LogDir "group_members_$DateTag.txt") "`n---"
    } catch {}
}

Write-Host "[*] Collecting service inventory..."
Get-Service | Sort-Object Status, DisplayName |
    Out-File -Encoding UTF8 (Join-Path $LogDir "services_$DateTag.txt")

Write-Host "[*] Collecting listening ports (netstat) and mapping to processes..."
netstat -ano | Out-File -Encoding UTF8 (Join-Path $LogDir "netstat_ano_$DateTag.txt")

# Process map
Get-Process | Select-Object Id, ProcessName, Path, StartTime -ErrorAction SilentlyContinue |
    Sort-Object Id |
    Out-File -Encoding UTF8 (Join-Path $LogDir "processes_$DateTag.txt")

Write-Host "[*] Collecting scheduled tasks..."
schtasks /query /fo LIST /v |
    Out-File -Encoding UTF8 (Join-Path $LogDir "scheduled_tasks_$DateTag.txt")

Write-Host "[*] Collecting Windows Firewall rules..."
netsh advfirewall firewall show rule name=all |
    Out-File -Encoding UTF8 (Join-Path $LogDir "firewall_rules_$DateTag.txt")

# ------------------------------
# 2. Enable Security Auditing (Safe)
# ------------------------------
Write-Host "[*] Enabling key security auditing categories (non-disruptive)..."

# Logon/logoff auditing
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable  | Out-Null

# Account logon and management
auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null

# Policy change & privilege use
auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null

# Object access & process tracking (process creation)
auditpol /set /category:"Object Access" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable | Out-Null

Write-Host "[+] Audit policies configured."

# ------------------------------
# 3. Enable PowerShell Logging (Safe)
# ------------------------------

Write-Host "[*] Enabling PowerShell transcription and script block logging..."

# Transcription logging
$psTranscriptionKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $psTranscriptionKey)) {
    New-Item -Path $psTranscriptionKey -Force | Out-Null
}
New-ItemProperty -Path $psTranscriptionKey -Name "EnableTranscripting" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $psTranscriptionKey -Name "EnableInvocationHeader" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $psTranscriptionKey -Name "OutputDirectory" -Value "$BaseDir\PS_Transcripts" -PropertyType String -Force | Out-Null

# Script block logging
$psScriptBlockKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psScriptBlockKey)) {
    New-Item -Path $psScriptBlockKey -Force | Out-Null
}
New-ItemProperty -Path $psScriptBlockKey -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force | Out-Null

Write-Host "[+] PowerShell logging enabled (Transcription + ScriptBlock)."

# ------------------------------
# 4. Enable Windows Firewall Logging (Safe)
# ------------------------------

Write-Host "[*] Configuring Windows Firewall logging (no rules/policies changed)..."

# NOTE: This does NOT change allow/deny behavior – only logging.
$fwLogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall_$DateTag.log"

netsh advfirewall set currentprofile logging allowedconnections enable  | Out-Null
netsh advfirewall set currentprofile logging droppedconnections enable  | Out-Null
netsh advfirewall set currentprofile logging filename="$fwLogPath"      | Out-Null
netsh advfirewall set currentprofile logging maxfilesize 4096           | Out-Null

Write-Host "[+] Firewall logging configured at $fwLogPath."

# ------------------------------
# 5. (OPTIONAL) Explicit Allow Rules for Known-Critical Ports
#     - SAFE: Only adds rules, does not block anything.
#     - Fill in the list once you know which ports are graded.
# ------------------------------

# Example list (EDIT THIS to match your environment, or leave empty)
$CriticalTcpPorts = @(
    # 80,   # HTTP
    # 443,  # HTTPS
    # 3389  # RDP
    # add others as needed...
)

foreach ($port in $CriticalTcpPorts) {
    $ruleName = "CCDC-Explicit-Allow-TCP-$port"
    Write-Host "[*] Adding explicit allow rule for TCP port $port..."
    netsh advfirewall firewall add rule name="$ruleName" `
        dir=in action=allow protocol=TCP localport=$port | Out-Null
}

Write-Host "`n[+] SAFE Windows baseline hardening complete."
Write-Host "[+] No services were stopped/disabled, no firewall policies were tightened."
