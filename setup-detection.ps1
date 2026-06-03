# SentinelForge detection setup — Tier 2 (Sysmon) + Tier 3 (Downloads realtime FIM)
# Run in an ELEVATED PowerShell (Right-click > Run as administrator).
# Safe: backs up ossec.conf, edits are idempotent, XML is validated, backup is
# auto-restored if validation fails. Nothing is removed.

$ErrorActionPreference = 'Stop'
$conf = "C:\Program Files (x86)\ossec-agent\ossec.conf"

# 0) require admin
$isAdmin = (New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
  ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { throw "Please run this in an ELEVATED PowerShell (Run as administrator)." }
if (-not (Test-Path $conf)) { throw "Agent config not found: $conf" }

# 1) backup
$bak = "$conf.bak_$(Get-Date -Format yyyyMMdd_HHmmss)"
Copy-Item $conf $bak -Force
Write-Host "[1/4] Backed up config -> $bak" -ForegroundColor Cyan

# 2) install / update Sysmon with SwiftOnSecurity config
Write-Host "[2/4] Installing Sysmon..." -ForegroundColor Cyan
$tmp = Join-Path $env:TEMP "sf_sysmon"
New-Item $tmp -ItemType Directory -Force | Out-Null
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$tmp\Sysmon.zip"
Expand-Archive "$tmp\Sysmon.zip" $tmp -Force
Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$tmp\sysmonconfig.xml"
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
  & "$tmp\Sysmon64.exe" -accepteula -c "$tmp\sysmonconfig.xml"   # update existing
} else {
  & "$tmp\Sysmon64.exe" -accepteula -i "$tmp\sysmonconfig.xml"   # fresh install
}

# 3) edit ossec.conf (literal, idempotent, validated)
Write-Host "[3/4] Updating agent config..." -ForegroundColor Cyan
$xml = Get-Content $conf -Raw

# 3a) forward the Sysmon event channel (insert before Policy monitoring block)
if ($xml -notmatch 'Sysmon/Operational') {
  $block = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Policy monitoring -->
"@
  $xml = $xml.Replace("  <!-- Policy monitoring -->", $block)
}

# 3b) realtime FIM on Downloads with hashing (needed for VirusTotal). Insert after Startup dir.
if ($xml -notmatch 'Downloads</directories>') {
  $anchor = '<directories realtime="yes">%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup</directories>'
  $repl   = $anchor + "`r`n    <directories realtime=`"yes`" check_all=`"yes`">C:\Users\rehan\Downloads</directories>"
  $xml = $xml.Replace($anchor, $repl)
}

# validate before writing; restore backup on failure
try { [xml]$xml | Out-Null }
catch { Copy-Item $bak $conf -Force; throw "XML invalid - restored backup. Error: $_" }
Set-Content $conf $xml -Encoding UTF8

# 4) restart the agent
Write-Host "[4/4] Restarting WazuhSvc..." -ForegroundColor Cyan
Restart-Service WazuhSvc
Start-Sleep 3

Write-Host "`nDONE." -ForegroundColor Green
Write-Host ("  Sysmon service : " + (Get-Service Sysmon64 -ErrorAction SilentlyContinue).Status)
Write-Host ("  WazuhSvc       : " + (Get-Service WazuhSvc).Status)
Write-Host ("  Backup         : " + $bak)
Write-Host "`nRollback if ever needed:  Copy-Item '$bak' '$conf' -Force ; Restart-Service WazuhSvc"
