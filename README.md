<div align="center">

# 🛡️ SentinelForge

### AI-Powered Security Operations Center (SOC) Platform

An agentic SOC platform that uses **multi-agent LLM reasoning** with an OPAR loop (Observe → Plan → Act → Reflect) to automatically investigate, triage, and respond to security alerts — powered by a **locally-running Phi-3 model** (no API keys needed).

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?logo=typescript&logoColor=white)](https://typescriptlang.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Quick Start](#-quick-start)
- [Manual Setup](#-manual-setup)
- [Local Development (No Docker)](#-local-development-no-docker)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Configuration](#%EF%B8%8F-configuration)
- [Testing](#-testing)
- [Wazuh Detection & Mitigation Setup](#-wazuh-detection--mitigation-setup)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

| Category | Details |
|----------|---------|
| **Multi-Agent AI Pipeline** | 4-agent OPAR loop — Planner, Investigator, Reporter, Responder |
| **Local LLM** | Phi-3 Mini via llama.cpp — fully offline, no API keys |
| **RAG Memory** | ChromaDB vector store for MITRE ATT&CK knowledge + past incidents |
| **Threat Intelligence** | CTI lookup, MITRE ATT&CK mapping, log search tools |
| **Real-Time Dashboard** | React SOC dashboard with alert submission, incident timeline, and forensic views |
| **Wazuh Integration** | Webhook receiver for live Wazuh/SIEM alerts |
| **Active Response** | AI-suggested containment actions with approve/dismiss workflow |
| **Graceful Degradation** | All agents fall back to deterministic logic if LLM is unavailable |
| **Process Forensics** | Sysmon-based forensic analysis with visual process trees |

---

## 🏗 Architecture

```
Wazuh / SIEM Alert
        │
        ▼
┌──────────────────┐     ┌──────────────────────────────────────────────┐
│  Webhook Receiver │     │              FastAPI Backend                 │
│     (port 9090)   │────▶│                                              │
└──────────────────┘     │  ┌────────────┐    ┌───────────────────────┐ │
                          │  │   Alert     │    │    Agent Manager      │ │
  React Dashboard ───────▶│  │ Normalizer  │───▶│                       │ │
   (port 3000)            │  └────────────┘    │  ┌──────────────────┐ │ │
                          │                     │  │   OPAR Loop      │ │ │
                          │  ┌─────────────┐   │  │                  │ │ │
                          │  │  ChromaDB    │◀──│  │ Observe → Plan → │ │ │
                          │  │  RAG Memory  │   │  │ Act → Reflect    │ │ │
                          │  └─────────────┘   │  └──────────────────┘ │ │
                          │                     │           │           │ │
                          │  ┌─────────────┐   │  ┌────────▼─────────┐ │ │
                          │  │  PostgreSQL  │   │  │   Tool Router    │ │ │
                          │  │  / SQLite    │   │  │ CTI│MITRE│Wazuh  │ │ │
                          │  └─────────────┘   │  │    │Logs │       │ │ │
                          │                     │  └──────────────────┘ │ │
                          │                     └───────────────────────┘ │
                          │  ┌─────────────┐                             │
                          │  │ Phi-3 LLM   │  (llama.cpp, port 8080)    │
                          │  └─────────────┘                             │
                          └──────────────────────────────────────────────┘
```

### Agent Pipeline (OPAR Loop)

| Step | Agent | What It Does |
|------|-------|-------------|
| **Observe** | — | Alert is normalized; context loaded from RAG memory |
| **Plan** | Planner | Decides which investigation tools to use (max 3 steps) |
| **Act** | Investigator | Executes tools — CTI lookup, MITRE mapping, Wazuh log search |
| **Reflect** | — | LLM evaluates if evidence is sufficient (up to 3 iterations) |
| **Report** | Reporter | Generates a structured incident report |
| **Respond** | Responder | Suggests containment actions (isolate host, block IP, etc.) |

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.11, FastAPI, SQLAlchemy, Pydantic |
| **Frontend** | React 18, TypeScript, Vite, React Router |
| **LLM** | Phi-3 Mini (Q4 GGUF) via llama.cpp — local, no API keys |
| **Vector DB** | ChromaDB (RAG for MITRE knowledge, playbooks, past incidents) |
| **Database** | PostgreSQL 16 (Docker) / SQLite (local dev) |
| **Infra** | Docker Compose, nginx |

---

## ⚡ Quick Start

> **Prerequisites:** Git, Docker & Docker Compose, ~4 GB free RAM.

Clone and run the automated setup script — it handles **everything** (Docker check, `.env` creation, LLM model download, and starting all services):

**Windows (PowerShell):**

```powershell
git clone https://github.com/Rehan919/AI-Powered-SOC-Platform-with-LLM-Reasoning.git
cd AI-Powered-SOC-Platform-with-LLM-Reasoning
.\setup.ps1
```

**Linux / macOS:**

```bash
git clone https://github.com/Rehan919/AI-Powered-SOC-Platform-with-LLM-Reasoning.git
cd AI-Powered-SOC-Platform-with-LLM-Reasoning
chmod +x setup.sh && ./setup.sh
```

Wait for the build to finish, then open **http://localhost:3000**.

**What the script does:**

1. ✅ Verifies Docker is running
2. ✅ Creates `.env` from `.env.example`
3. ✅ Downloads Phi-3 Mini LLM (~2.3 GB) into `models/`
4. ✅ Runs `docker compose up --build` (starts all 6 services)

**Services after setup:**

| Service | URL |
|---------|-----|
| SOC Dashboard | http://localhost:3000 |
| API | http://localhost:8001 |
| API Docs (Swagger) | http://localhost:8001/docs |
| Wazuh Webhook | http://localhost:9090 |
| LLM Server | http://localhost:8080 |

---

## 🔧 Manual Setup

If you prefer to run each step yourself instead of using the setup script.

### Step 1 — Clone & Configure

```bash
git clone https://github.com/Rehan919/AI-Powered-SOC-Platform-with-LLM-Reasoning.git
cd AI-Powered-SOC-Platform-with-LLM-Reasoning
cp .env.example .env
```

### Step 2 — Download the LLM Model

The Phi-3 model (~2.3 GB) powers the AI analysis. You can skip this step — the platform falls back to deterministic (rule-based) analysis without it.

**Linux / macOS:**

```bash
mkdir -p models
curl -L -o models/phi-3-mini-4k-instruct.Q4_K_M.gguf \
  https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf
```

**Windows (PowerShell):**

```powershell
New-Item -ItemType Directory -Force -Path models
Invoke-WebRequest -Uri "https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf" `
  -OutFile "models/phi-3-mini-4k-instruct.Q4_K_M.gguf"
```

### Step 3 — Start All Services

```bash
docker compose up --build
```

This brings up **6 containers**: PostgreSQL, ChromaDB, Phi-3 LLM, Backend API, Frontend, and Wazuh Webhook Receiver.

### Step 4 — Open the Dashboard

Go to **http://localhost:3000**.

---

## 💻 Local Development (No Docker)

The backend falls back to **SQLite** when no `DATABASE_URL` is set. ChromaDB and the LLM degrade gracefully with deterministic logic if unreachable. You only need **Python 3.11+** and **Node.js 20+**.

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn src.main:app --port 8001 --reload
```

> Uses SQLite (`backend/sentinelforge.db`) automatically — no PostgreSQL needed.

### Frontend

Open a **new terminal**:

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server starts at http://localhost:3000 and proxies `/api` requests to the backend.

### LLM (Optional)

Download the Phi-3 model (see Step 2 in Manual Setup), place it in `models/`, and run llama.cpp separately — or skip it to use deterministic fallbacks.

---

## 📖 Usage

### Submit an Alert via Dashboard

1. Open http://localhost:3000
2. Paste or edit the sample JSON alert
3. Click **"Analyze Alert"**
4. Watch the AI agent investigate and generate an incident report

### Submit via API

```bash
curl -X POST http://localhost:8001/alert/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "WIN-PC",
    "process": "powershell.exe",
    "destination_ip": "185.199.1.20",
    "rule": "Suspicious Powershell",
    "mitre": "T1059",
    "severity": 10
  }'
```

### Approve / Dismiss Response Actions

```bash
curl -X POST http://localhost:8001/response/approve/1   # Approve (triggers execution)
curl -X POST http://localhost:8001/response/dismiss/1   # Dismiss
```

Full API documentation: http://localhost:8001/docs

### Alert Simulator

Send simulated Wazuh alerts to test the platform end-to-end:

```bash
python simulator.py
```

Sends a random alert every 30 seconds (PowerShell commands, SSH brute force, ransomware detection).

### Wazuh Integration

Add this to your Wazuh manager's `ossec.conf`:

```xml
<integration>
  <name>custom-sentinelforge</name>
  <hook_url>http://<SENTINELFORGE_HOST>:9090/webhook/wazuh</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

Replace `<SENTINELFORGE_HOST>` with your server's IP or hostname.

---

## 📁 Project Structure

```
sentinelforge/
├── backend/                        # FastAPI backend
│   ├── src/
│   │   ├── agent/                  # AI agent pipeline
│   │   │   ├── agents/
│   │   │   │   ├── planner.py          # Plans investigation steps
│   │   │   │   ├── investigator.py     # Executes investigation tools
│   │   │   │   ├── reporter.py         # Generates incident reports
│   │   │   │   └── responder.py        # Suggests containment actions
│   │   │   ├── manager.py             # Agent orchestration
│   │   │   ├── opar_loop.py           # OPAR loop implementation
│   │   │   └── prompts.py             # LLM prompt templates
│   │   ├── api/                    # REST API routes
│   │   ├── llm/                    # LLM client (llama.cpp)
│   │   ├── memory/                 # Database + ChromaDB RAG
│   │   ├── models/                 # Pydantic schemas
│   │   ├── tools/                  # Investigation tools
│   │   │   ├── cti_lookup.py           # Threat intelligence lookup
│   │   │   ├── mitre_lookup.py         # MITRE ATT&CK mapping
│   │   │   ├── log_search.py           # Wazuh log search
│   │   │   ├── wazuh_host.py           # Wazuh host info
│   │   │   └── wazuh_response.py       # Active response execution
│   │   ├── webhook/                # Wazuh webhook receiver
│   │   ├── config.py               # Environment configuration
│   │   └── main.py                 # FastAPI app entry point
│   ├── tests/                      # Pytest test suite
│   ├── requirements.txt
│   ├── Dockerfile
│   └── start.sh
│
├── frontend/                       # React + TypeScript dashboard
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx           # Main SOC dashboard
│   │   │   ├── AlertDetail.tsx         # Individual alert view
│   │   │   ├── AiReview.tsx            # AI analysis review
│   │   │   └── ProcessForensics.tsx    # Sysmon forensic analysis
│   │   ├── components/             # Reusable UI components
│   │   ├── api/                    # API client
│   │   ├── styles/                 # CSS
│   │   ├── App.tsx                 # Router setup
│   │   └── main.tsx                # Entry point
│   ├── package.json
│   ├── vite.config.ts
│   ├── Dockerfile
│   └── nginx.conf
│
├── models/                         # LLM model files (not committed)
│   └── phi-3-mini-4k-instruct.Q4_K_M.gguf
│
├── wazuh-deployment/               # Wazuh Docker deployment configs
│
├── docker-compose.yml              # Full-stack Docker orchestration
├── .env.example                    # Environment template
├── setup.ps1                       # One-click setup (Windows)
├── setup.sh                        # One-click setup (Linux/macOS)
├── simulator.py                    # Wazuh alert simulator
├── extract_forensics.py            # Sysmon forensic extraction script
├── parse_alerts.py                 # Alert log parser
├── setup-detection.ps1             # Sysmon + Wazuh detection setup
├── setup-mitigation.ps1            # Active response setup
├── mitigate-threat.cmd             # Wazuh active response script
├── ossec.conf                      # Example Wazuh agent config
└── test-alerts.json                # Sample alert data for testing
```

---

## ⚙️ Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

| Variable | Default (Docker) | Default (Local) | Description |
|----------|-----------------|-----------------|-------------|
| `DATABASE_URL` | `postgresql://sentinel:sentinel@postgres:5432/sentinelforge` | `sqlite:///./sentinelforge.db` | Database connection string |
| `LLM_URL` | `http://llm:8080` | `http://localhost:8080` | llama.cpp server URL |
| `CHROMA_HOST` | `chromadb` | `localhost` | ChromaDB hostname |
| `CHROMA_PORT` | `8000` | `8000` | ChromaDB port |
| `CORS_ORIGINS` | `http://localhost:3000,http://frontend:3000` | `http://localhost:3000` | Allowed CORS origins |
| `WEBHOOK_URL` | `http://wazuh-webhook:9090/webhook/generic` | `http://localhost:9999/webhook` | Webhook forwarding URL |
| `ABUSEIPDB_KEY` | *(empty)* | *(empty)* | AbuseIPDB API key (optional) |
| `API_KEY` | *(empty)* | *(empty)* | API authentication key (optional) |
| `INDEXER_URL` | `https://localhost:9200` | `https://localhost:9200` | Wazuh indexer URL |
| `WAZUH_API_URL` | `https://localhost:55000` | `https://localhost:55000` | Wazuh manager API URL |

---

## 🧪 Testing

```bash
cd backend
pip install -r requirements.txt
pytest
```

Tests cover:
- Deterministic fallback logic (when LLM is unavailable)
- Agent pipeline behavior
- Input validation and security checks

---

## 🔒 Wazuh Detection & Mitigation Setup

These scripts configure a **Windows** Wazuh agent for enhanced detection and automated response.

### Detection Setup (Sysmon + FIM)

Run in an **elevated PowerShell**:

```powershell
.\setup-detection.ps1
```

This will:
1. Back up the current Wazuh agent config
2. Install/update Sysmon with SwiftOnSecurity rules
3. Add Sysmon event channel forwarding to Wazuh
4. Enable real-time File Integrity Monitoring on the Downloads folder
5. Restart the Wazuh agent

### Mitigation Setup (Active Response)

Run in an **elevated PowerShell**:

```powershell
.\setup-mitigation.ps1
```

This will:
1. Deploy the `mitigate-threat.cmd` active response script
2. Register the command in the Wazuh manager
3. Restart both the manager and agent

### Forensic Analysis

Parse Wazuh/Sysmon alerts from JSON:

```bash
cat alerts.json | python extract_forensics.py
cat alerts.json | python parse_alerts.py
```

---

## 🔧 Troubleshooting

| Problem | Solution |
|---------|----------|
| **LLM container keeps restarting** | Ensure ~4 GB RAM free. Check model file in `models/` (~2.3 GB). |
| **Backend can't connect to PostgreSQL** | Wait 10–15 sec for health check. Run `docker compose logs postgres`. |
| **Frontend shows "Network Error"** | Ensure backend is running on port 8001. |
| **ChromaDB errors** | Optional — backend degrades gracefully. Run `docker compose logs chromadb`. |
| **`pip install` fails on `psycopg2-binary`** | Install `libpq-dev`: `sudo apt install libpq-dev` |
| **Permission denied on PowerShell scripts** | Run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| **Port already in use** | Change port mapping in `docker-compose.yml` or stop conflicting service. |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**Built with ❤️ for the cybersecurity community**

</div>
