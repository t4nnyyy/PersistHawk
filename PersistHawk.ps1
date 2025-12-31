# ================================
# Persistence Hunting Script
# Author: Tanveer Ali
# ================================

# ---------- Admin Privilege Enforcement ----------
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[!] This script must be run with Administrator privileges." -ForegroundColor Red
    Write-Host "[!] Please re-run in an elevated PowerShell session." -ForegroundColor Yellow
    exit 1
}

$ErrorActionPreference = "SilentlyContinue"

# ---------- Metadata ----------
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$OutDir    = "C:\PersistHawk_$Hostname`_$Timestamp"

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Write-Host "[+] Persistence Hunt Started" -ForegroundColor Cyan
Write-Host "[+] Output Directory: $OutDir" -ForegroundColor Green

# ---------- Admin Check ----------
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Warning "Not running as Administrator. Some checks may be incomplete."
}


# ==================================================
# 1. Registry Run / RunOnce Keys
# ==================================================
Write-Host "[+] Hunting Registry Run Keys"

$RunKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$RegResults = foreach ($Key in $RunKeys) {
    if (Test-Path $Key) {
        Get-ItemProperty $Key |
        Select-Object PSPath, PSChildName, * -ExcludeProperty PSDrive, PSProvider
    }
}

$RegResults | Out-File "$OutDir\registry_run_keys.txt"

# ==================================================
# 2. Startup Folder Persistence
# ==================================================
Write-Host "[+] Hunting Startup Folder Persistence"

$StartupPaths = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

$StartupFiles = Get-ChildItem $StartupPaths -Recurse -ErrorAction SilentlyContinue |
Select-Object FullName, CreationTime, LastWriteTime

$StartupFiles | Export-Csv "$OutDir\startup_files.csv" -NoTypeInformation

# ==================================================
# 3. Scheduled Tasks
# ==================================================
Write-Host "[+] Hunting Scheduled Tasks"

$ScheduledTasks = Get-ScheduledTask |
ForEach-Object {
    [PSCustomObject]@{
        TaskName  = $_.TaskName
        TaskPath  = $_.TaskPath
        State     = $_.State
        Execute   = $_.Actions.Execute
        Arguments = $_.Actions.Arguments
    }
}

$ScheduledTasks | Export-Csv "$OutDir\scheduled_tasks.csv" -NoTypeInformation

# ==================================================
# 4. Auto-start Services (Non-Microsoft)
# ==================================================
Write-Host "[+] Hunting Auto-start Services"

$Services = Get-CimInstance Win32_Service |
Where-Object {
    $_.StartMode -eq "Auto" -and
    $_.PathName -notmatch "Windows|Microsoft"
} |
Select-Object Name, DisplayName, State, StartMode, PathName

$Services | Export-Csv "$OutDir\services_autostart.csv" -NoTypeInformation

# ==================================================
# 5. WMI Event Subscription Persistence
# ==================================================
Write-Host "[+] Hunting WMI Persistence"

try {
    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
        Export-Csv "$OutDir\wmi_event_filters.csv" -NoTypeInformation

    Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer |
        Export-Csv "$OutDir\wmi_event_consumers.csv" -NoTypeInformation

    Get-CimInstance -Namespace root\subscription -ClassName FilterToConsumerBinding |
        Export-Csv "$OutDir\wmi_event_bindings.csv" -NoTypeInformation
}
catch {
    "No WMI persistence found or insufficient privileges." |
        Out-File "$OutDir\wmi_status.txt"
}

# ==================================================
# 6. Unsigned / Suspicious Persistence Binaries
# ==================================================
Write-Host "[+] Checking Digital Signatures"

$PersistenceBinaries = @()

$PersistenceBinaries += $StartupFiles.FullName
$PersistenceBinaries += $Services.PathName -replace '"',''

$SigResults = foreach ($File in $PersistenceBinaries | Sort-Object -Unique) {
    if (Test-Path $File) {
        $Sig = Get-AuthenticodeSignature $File
        [PSCustomObject]@{
            FilePath = $File
            Status   = $Sig.Status
            Signer   = $Sig.SignerCertificate.Subject
        }
    }
}

$SigResults | Export-Csv "$OutDir\digital_signatures.csv" -NoTypeInformation

# ==================================================
# 7. LOLBin Detection in Persistence
# ==================================================

Write-Host "[+] Detecting LOLBins"

$Lolbins = "powershell|cmd|mshta|rundll32|wscript|cscript|certutil|regsvr32"

$Suspicious = @()
$Suspicious += $RegResults | Out-String
$Suspicious += $ScheduledTasks | Out-String
$Suspicious += $Services | Out-String

$Suspicious |
Select-String -Pattern $Lolbins |
Out-File "$OutDir\suspicious_lolbins.txt"

# ==================================================
Write-Host "[+] Persistence Hunt Completed Successfully" -ForegroundColor Cyan
Write-Host "[+] Review evidence at: $OutDir"
