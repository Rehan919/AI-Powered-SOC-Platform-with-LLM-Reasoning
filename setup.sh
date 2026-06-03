#!/usr/bin/env bash
#
# SentinelForge — One-click setup for Linux / macOS.
# Downloads the LLM model, creates .env, and starts all services.
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#
set -e

echo ""
echo "========================================"
echo "  SentinelForge — Automated Setup"
echo "========================================"
echo ""

# ── 1. Check Docker is running ──────────────────────────────────────────────
echo "[1/4] Checking Docker..."
if ! docker info > /dev/null 2>&1; then
    echo "       ERROR: Docker is not running."
    echo "       Please start Docker and try again."
    exit 1
fi
echo "       Docker is running. ✓"

# ── 2. Create .env from template ────────────────────────────────────────────
echo "[2/4] Setting up environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "       Created .env from .env.example ✓"
else
    echo "       .env already exists, skipping. ✓"
fi

# ── 3. Download LLM model ──────────────────────────────────────────────────
echo "[3/4] Checking LLM model..."
MODEL_DIR="models"
MODEL_FILE="$MODEL_DIR/phi-3-mini-4k-instruct.Q4_K_M.gguf"
MODEL_URL="https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf"

mkdir -p "$MODEL_DIR"

if [ -f "$MODEL_FILE" ]; then
    SIZE=$(stat -f%z "$MODEL_FILE" 2>/dev/null || stat -c%s "$MODEL_FILE" 2>/dev/null || echo "0")
    if [ "$SIZE" -gt 1000000000 ]; then
        echo "       Model already downloaded ($(echo "scale=1; $SIZE/1073741824" | bc) GB). Skipping. ✓"
    else
        echo "       Model file looks incomplete. Re-downloading..."
        rm -f "$MODEL_FILE"
    fi
fi

if [ ! -f "$MODEL_FILE" ]; then
    echo "       Downloading Phi-3 Mini (~2.3 GB)... this may take a few minutes."
    echo "       URL: $MODEL_URL"
    if curl -L --progress-bar -o "$MODEL_FILE" "$MODEL_URL"; then
        SIZE=$(stat -f%z "$MODEL_FILE" 2>/dev/null || stat -c%s "$MODEL_FILE" 2>/dev/null || echo "0")
        echo "       Download complete ($(echo "scale=1; $SIZE/1073741824" | bc) GB). ✓"
    else
        echo "       WARNING: Failed to download the model."
        echo "       The platform will still work using deterministic (rule-based) analysis."
    fi
fi

# ── 4. Start Docker Compose ────────────────────────────────────────────────
echo "[4/4] Starting all services..."
echo ""
echo "       This will build and start 6 containers:"
echo "         - PostgreSQL (database)"
echo "         - ChromaDB   (vector memory)"
echo "         - Phi-3 LLM  (AI engine)"
echo "         - Backend    (FastAPI)"
echo "         - Frontend   (React dashboard)"
echo "         - Webhook    (Wazuh receiver)"
echo ""

docker compose up --build

