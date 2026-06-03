# setup-mitigation.ps1
# Deploy the SentinelForge custom mitigation script to the Wazuh agent

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SentinelForge Mitigation Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Please run this script as Administrator." -ForegroundColor Red
    exit 1
}

$agentBin = "C:\Program Files (x86)\ossec-agent\active-response\bin"
if (-not (Test-Path $agentBin)) {
    Write-Host "[!] Wazuh agent not found at $agentBin" -ForegroundColor Red
    exit 1
}

# 1. Write the mitigation script for the agent
$scriptPath = Join-Path $agentBin "mitigate-threat.cmd"
$scriptContent = @"
@echo off
setlocal
:: Wazuh Active Response JSON payload is passed via STDIN
:: This is a wrapper to call PowerShell for the actual logic

powershell -ExecutionPolicy Bypass -NoProfile -Command " `
    `$json = [Console]::In.ReadToEnd(); `
    if (-not `$json) { exit 0 }; `
    `$payload = `$json | ConvertFrom-Json; `
    `$args = `$payload.arguments; `
    if (-not `$args -or `$args.Count -eq 0) { exit 0 }; `
    `$processName = `$args[0]; `
    `$baseName = `$processName -replace '.exe',''; `
    `
    # 1. Kill Process `
    Get-Process | Where-Object { `$_.Path -like '*'+`$baseName+'*' } | Stop-Process -Force -ErrorAction SilentlyContinue; `
    `
    # 2. Quarantine original file `
    `$quarantine = 'C:\Users\rehan\Videos\project\sentinelforge\quarantine'; `
    if (-not (Test-Path `$quarantine)) { New-Item -ItemType Directory -Path `$quarantine -Force | Out-Null }; `
    if (Test-Path `$processName) { Move-Item -Path `$processName -Destination `$quarantine -Force -ErrorAction SilentlyContinue }; `
    `
    # 3. Clean _MEI temp folders (PyInstaller) `
    `$temp = `$env:TEMP; `
    Get-ChildItem -Path `$temp -Filter '_MEI*' -Directory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue; `
"

exit 0
"@

Write-Host "[*] Creating mitigation script at $scriptPath"
Set-Content -Path $scriptPath -Value $scriptContent -Encoding ASCII

# 2. Add the command to Wazuh manager
$managerContainer = "single-node-wazuh.manager-1"
Write-Host "[*] Registering active-response command in Wazuh manager..."

$configSnippet = @"
  <command>
    <name>mitigate-threat</name>
    <executable>mitigate-threat.cmd</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
"@

# We use docker exec to inject this into the manager's ossec.conf before <active-response>
$dockerCmd = "docker exec $managerContainer bash -c ""sed -i '/<active-response>/i \  <command>\n    <name>mitigate-threat</name>\n    <executable>mitigate-threat.cmd</executable>\n    <timeout_allowed>yes</timeout_allowed>\n  </command>\n' /var/ossec/etc/ossec.conf"""
Invoke-Expression $dockerCmd

# Restart Wazuh Manager
Write-Host "[*] Restarting Wazuh Manager container (this may take a minute)..."
docker restart $managerContainer | Out-Null

# Restart local agent
Write-Host "[*] Restarting Wazuh Agent..."
Restart-Service -Name WazuhSvc

Write-Host ""
Write-Host "[+] Mitigation setup complete!" -ForegroundColor Green
Write-Host "SentinelForge can now remotely kill threats and clean up dropped files." -ForegroundColor Green
