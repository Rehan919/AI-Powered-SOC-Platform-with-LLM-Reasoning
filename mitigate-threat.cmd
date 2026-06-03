@echo off
setlocal
:: Wazuh Active Response JSON payload is passed via STDIN
:: This is a wrapper to call PowerShell for the actual logic

powershell -ExecutionPolicy Bypass -NoProfile -Command " $json = [Console]::In.ReadToEnd(); if (-not $json) { exit 0 }; $payload = $json | ConvertFrom-Json; $args = $payload.arguments; if (-not $args -or $args.Count -eq 0) { exit 0 }; $processName = $args[0]; $baseName = $processName -replace '.exe',''; Get-Process | Where-Object { $_.Path -like '*'+$baseName+'*' } | Stop-Process -Force -ErrorAction SilentlyContinue; $quarantine = 'C:\Users\rehan\Videos\project\sentinelforge\quarantine'; if (-not (Test-Path $quarantine)) { New-Item -ItemType Directory -Path $quarantine -Force | Out-Null }; if (Test-Path $processName) { Move-Item -Path $processName -Destination $quarantine -Force -ErrorAction SilentlyContinue }; $temp = $env:TEMP; Get-ChildItem -Path $temp -Filter '_MEI*' -Directory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue; "

exit 0
