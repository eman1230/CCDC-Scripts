<# 
    Suspicious Strings Scanner - Windows
    Scans EXE/DLL files for suspicious indicators.

    Logs -> C:\CCDC_Hardening\Suspicious_Strings\<DATE>\
#>

$Date = Get-Date -Format "yyyyMMdd_HHmmss"
$Base = "C:\CCDC_Hardening\Suspicious_Strings\$Date"
New-Item -ItemType Directory -Force -Path $Base | Out-Null

Write-Host "[*] Output -> $Base"

# Directories to scan
$Dirs = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "$env:ProgramFiles",
    "$env:ProgramFiles(x86)",
    "$env:LOCALAPPDATA",
    "$env:APPDATA"
)

# Suspicious patterns
$Patterns = "password","secret","token","session","key=","aws_","reverse","shell","connect","/bin/sh","cmd.exe","powershell -","IEX(","FromBase64String","wget","curl","Invoke-WebRequest","netcat","nc.exe"

# Function to scan a file with strings.exe
function Scan-File {
    param($File, $OutFile)
    try {
        # strings.exe must be present in PATH OR Sysinternals folder
        $output = & strings.exe $File 2>$null
        foreach ($p in $Patterns) {
            $hits = $output | Select-String -Pattern $p -SimpleMatch
            if ($hits) {
                Add-Content -Path $OutFile -Value "`n--- $File"
                Add-Content -Path $OutFile -Value $hits
            }
        }
    } catch {}
}

# Begin scanning
foreach ($dir in $Dirs) {
    if (Test-Path $dir) {
        $OutFile = "$Base\scan_$(Split-Path $dir -Leaf).txt"
        Write-Host "[*] Scanning $dir ..."
        $files = Get-ChildItem -Path $dir -Recurse -Include *.exe,*.dll -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            Scan-File -File $file.FullName -OutFile $OutFile
        }
    }
}

# Startup folders
$StartupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)

foreach ($sf in $StartupFolders) {
    if (Test-Path $sf) {
        $OutFile = "$Base\startup_scan.txt"
        Write-Host "[*] Scanning startup folder $sf ..."
        $files = Get-ChildItem -Path $sf -Recurse -Include *.exe,*.dll -ErrorAction SilentlyContinue
        foreach ($file in $files) { Scan-File -File $file.FullName -OutFile $OutFile }
    }
}

Write-Host "`n[+] Windows suspicious strings scan complete."
Write-Host "[+] Results saved to: $Base"
