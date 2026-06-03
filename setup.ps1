<#
.SYNOPSIS
    SentinelForge — One-click setup for Windows.
    Downloads the LLM model, creates .env, and starts all services.

.DESCRIPTION
    Run this script after cloning the repository.
    Requires: Docker Desktop running.

.EXAMPLE
    .\setup.ps1
#>

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SentinelForge — Automated Setup"       -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Check Docker is running ──────────────────────────────────────────────
Write-Host "[1/4] Checking Docker..." -ForegroundColor Yellow
try {
    docker info 2>&1 | Out-Null
    Write-Host "       Docker is running." -ForegroundColor Green
} catch {
    Write-Host "       ERROR: Docker is not running. Please start Docker Desktop and try again." -ForegroundColor Red
    exit 1
}

# ── 2. Create .env from template ────────────────────────────────────────────
Write-Host "[2/4] Setting up environment..." -ForegroundColor Yellow
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "       Created .env from .env.example" -ForegroundColor Green
} else {
    Write-Host "       .env already exists, skipping." -ForegroundColor Green
}

# ── 3. Download LLM model ──────────────────────────────────────────────────
Write-Host "[3/4] Checking LLM model..." -ForegroundColor Yellow
$modelDir  = "models"
$modelFile = "$modelDir\phi-3-mini-4k-instruct.Q4_K_M.gguf"
$modelUrl  = "https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf"

if (-not (Test-Path $modelDir)) {
    New-Item -ItemType Directory -Force -Path $modelDir | Out-Null
}

if (Test-Path $modelFile) {
    $size = (Get-Item $modelFile).Length
    if ($size -gt 1000000000) {
        Write-Host "       Model already downloaded ($([math]::Round($size/1GB, 1)) GB). Skipping." -ForegroundColor Green
    } else {
        Write-Host "       Model file looks incomplete. Re-downloading..." -ForegroundColor Yellow
        Remove-Item $modelFile -Force
    }
}

if (-not (Test-Path $modelFile)) {
    Write-Host "       Downloading Phi-3 Mini (~2.3 GB)... this may take a few minutes." -ForegroundColor Yellow
    Write-Host "       URL: $modelUrl" -ForegroundColor DarkGray
    try {
        $ProgressPreference = 'SilentlyContinue'   # speeds up Invoke-WebRequest
        Invoke-WebRequest -Uri $modelUrl -OutFile $modelFile -UseBasicParsing
        $ProgressPreference = 'Continue'
        $size = (Get-Item $modelFile).Length
        Write-Host "       Download complete ($([math]::Round($size/1GB, 1)) GB)." -ForegroundColor Green
    } catch {
        Write-Host "       WARNING: Failed to download the model. The platform will still work" -ForegroundColor Yellow
        Write-Host "       using deterministic (rule-based) analysis instead of AI." -ForegroundColor Yellow
        Write-Host "       Error: $_" -ForegroundColor DarkGray
    }
}

# ── 4. Start Docker Compose ────────────────────────────────────────────────
Write-Host "[4/4] Starting all services..." -ForegroundColor Yellow
Write-Host ""
Write-Host "       This will build and start 6 containers:" -ForegroundColor DarkGray
Write-Host "         - PostgreSQL (database)" -ForegroundColor DarkGray
Write-Host "         - ChromaDB   (vector memory)" -ForegroundColor DarkGray
Write-Host "         - Phi-3 LLM  (AI engine)" -ForegroundColor DarkGray
Write-Host "         - Backend    (FastAPI)" -ForegroundColor DarkGray
Write-Host "         - Frontend   (React dashboard)" -ForegroundColor DarkGray
Write-Host "         - Webhook    (Wazuh receiver)" -ForegroundColor DarkGray
Write-Host ""

docker compose up --build

