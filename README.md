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

1. [Features](#-features)
2. [Architecture](#-architecture)
3. [Tech Stack](#-tech-stack)
4. [Quick Start](#-quick-start)
5. [Manual Setup](#-manual-setup)
6. [Local Development (No Docker)](#-local-development-no-docker)
7. [Usage](#-usage)
8. [Wazuh Integration](#-wazuh-integration)
9. [Wazuh Detection & Mitigation Setup](#-wazuh-detection--mitigation-setup)
10. [Configuration](#️-configuration)
11. [Troubleshooting](#-troubleshooting)
12. [License](#-license)

---

## ✨ Features

| Category | Details |
|----------|---------|
| **Multi-Agent AI Pipeline** | 4-agent OPAR loop — Planner, Investigator, Reporter, Responder — with deterministic fallbacks |
| **Local LLM** | Phi-3 Mini via llama.cpp — fully offline, no API keys, Phi-3 chat template with `<&#124;user&#124;>` / `<&#124;assistant&#124;>` tokens |
| **RAG Memory** | ChromaDB vector store seeded with MITRE ATT&CK knowledge, detection rules, and response playbooks |
| **Threat Intelligence** | CTI lookup via AbuseIPDB (real) + built-in ThreatFox/MalwareBazaar database (fallback) |
| **MITRE ATT&CK Mapping** | 16 technique definitions (T1003–T1566) with tactic, description, and detection guidance |
| **Real-Time Dashboard** | React SOC dashboard with live auto-refresh, risk distribution charts, MITRE heatmap, search/filter |
| **Process Forensics** | Sysmon-based forensic analysis — process trees, file drops, network connections, registry mods, DNS queries |
| **Wazuh Integration** | Webhook receiver for live Wazuh/SIEM alerts with automatic field normalization |
| **Active Response** | AI-suggested containment actions (block IP, isolate host, kill process, disable account) with approve/dismiss workflow |
| **Real Active Response** | Executes containment via Wazuh Manager API — authenticates, resolves agent ID, sends active-response commands |
| **Threat Mitigation** | Full kill-chain mitigation script: kill process tree, quarantine executable, clean temp artifacts |
| **Alert Deduplication** | Correlates repeat alerts (same host + rule within configurable window) into single incidents |
| **Incident Status Workflow** | Status management: open → in_progress → resolved / false_positive |
| **Similar Incident Search** | RAG-powered similar incident retrieval for context during investigation |
| **Graceful Degradation** | Every agent, every tool, every service falls back to deterministic logic if unavailable |
| **Dual Database** | PostgreSQL (Docker) / SQLite (local dev) — auto-detection with graceful fallback |
| **API Authentication** | Optional API key auth via `X-API-Key` header (opt-in when `API_KEY` env is set) |

---

## 🏗 Architecture

```
                         ┌──────────────────────────────────────────────────┐
  Wazuh / SIEM Alert     │                FastAPI Backend (:8001)           │
         │               │                                                  │
         ▼               │  ┌──────────────┐    ┌────────────────────────┐ │
  ┌──────────────┐       │  │    Alert      │    │     Agent Manager      │ │
  │   Webhook    │──────▶│  │  Normalizer   │───▶│                        │ │
  │  Receiver    │       │  └──────────────┘    │  ┌──────────────────┐  │ │
  │  (:9090)     │       │                       │  │    OPAR Loop     │  │ │
  └──────────────┘       │  ┌──────────────┐    │  │                  │  │ │
                         │  │   ChromaDB    │◀──▶│  │ 1. Observe       │  │ │
  React Dashboard ──────▶│  │  RAG Memory   │    │  │ 2. Plan          │  │ │
   (:3000)               │  │  - MITRE ATT&CK│   │  │ 3. Act (tools)   │  │ │
                         │  │  - Playbooks  │    │  │ 4. Reflect       │  │ │
                         │  │  - Past cases │    │  │ 5. Report        │  │ │
                         │  └──────────────┘    │  │ 6. Respond       │  │ │
                         │                       │  └──────────────────┘  │ │
                         │  ┌──────────────┐    │           │            │ │
                         │  │  PostgreSQL   │    │  ┌────────▼─────────┐ │ │
                         │  │  / SQLite     │    │  │   Tool Router    │ │ │
                         │  │  - Alerts     │    │  │  ┌───┬───┬───┐  │ │ │
                         │  │  - Incidents  │    │  │  │CTI│MIT│WAZ│  │ │ │
                         │  │  - Actions    │    │  │  │   │RE │UH │  │ │ │
                         │  │  - AgentSteps │    │  │  └───┴───┴───┘  │ │ │
                         │  └──────────────┘    │  └──────────────────┘ │ │
                         │                       └────────────────────────┘ │
                         │  ┌──────────────┐                                │
                         │  │  Phi-3 LLM   │  llama.cpp server (:8080)     │
                         │  └──────────────┘                                │
                         └──────────────────────────────────────────────────┘
```

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.11, FastAPI 0.115, SQLAlchemy 2.0, Pydantic 2.9, httpx |
| **Frontend** | React 18, TypeScript 5.6, Vite 8, React Router 6 |
| **LLM** | Phi-3 Mini 4K Instruct (Q4_K_M GGUF, ~2.3 GB) via llama.cpp |
| **Vector DB** | ChromaDB 0.5 — HTTP server (Docker) or PersistentClient (local) |
| **Database** | PostgreSQL 16 (Docker) / SQLite (local dev, auto-fallback) |
| **Infra** | Docker Compose, nginx, multi-stage Docker builds |
| **Testing** | pytest, pytest-asyncio |

---

## ⚡ Quick Start

> **Prerequisites:** Git, Docker Desktop (with Docker Compose), ~4 GB free RAM.

Clone and run the automated setup script — it checks Docker, creates `.env`, downloads the LLM model (~2.3 GB), and starts all 6 services automatically:

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
4. ✅ Runs `docker compose up --build` — starts all 6 services

**Services after setup:**

| Service | URL | Description |
|---------|-----|-------------|
| SOC Dashboard | http://localhost:3000 | React frontend (nginx) |
| Backend API | http://localhost:8001 | FastAPI analysis engine |
| Swagger Docs | http://localhost:8001/docs | Interactive API reference |
| Wazuh Webhook | http://localhost:9090 | Alert ingestion from Wazuh/SIEMs |
| LLM Server | http://localhost:8080 | Phi-3 via llama.cpp |
| PostgreSQL | localhost:5432 | Incidents, alerts, actions storage |
| ChromaDB | http://localhost:8000 | Vector memory (RAG) |

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

The Phi-3 model (~2.3 GB) powers the AI analysis. **This step is optional** — the platform falls back to deterministic (rule-based) analysis without it.

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

The backend falls back to **SQLite** when PostgreSQL is unreachable. ChromaDB falls back to a **local PersistentClient**. The LLM falls back to **deterministic logic**. You only need **Python 3.11+** and **Node.js 20+**.

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn src.main:app --port 8001 --reload
```

### Frontend (new terminal)

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server starts at http://localhost:3000 and proxies `/api` → `localhost:8001`.

### LLM (Optional)

Download the Phi-3 model (see Step 2 in Manual Setup), then run llama.cpp separately — or skip it entirely.

---

## 📖 Usage

### Dashboard

Open http://localhost:3000. The dashboard includes:

- **Threat Summary Cards** — Total, Critical, High, Open, Resolved incident counts
- **Risk Distribution Chart** — Visual bar chart of incidents by severity
- **Activity Chart** — 7-day incident activity timeline
- **MITRE ATT&CK Heatmap** — Clickable technique chips with occurrence counts
- **Incident Table** — Searchable, filterable list with host, summary, risk, MITRE, status, and timestamp
- **Live Auto-Refresh** — Polls every 8 seconds (toggleable)
- **Alert Deduplication** — Repeat alerts show `×N` event count badges

### Submit an Alert

1. Send a JSON alert via the API (see below) or the webhook
2. The AI agent pipeline investigates automatically
3. View the generated incident report at http://localhost:3000/incident/{id}
4. Review AI-suggested response actions (approve or dismiss)

### Process Forensics

Navigate to http://localhost:3000/incident/{id}/forensics for:

- **Process tree** — All processes spawned with command lines, PIDs, parent processes, hashes
- **Files created** — Dropped files with source process and timestamps
- **Network connections** — Outbound connections with destination IP/port and protocol
- **DLLs loaded** — Loaded libraries with hashes
- **DNS queries** — Resolved domains with query results
- **Registry modifications** — Created keys and set values
- **Risk indicators** — Auto-detected patterns (PyInstaller packed, crypto libs, temp writes)
- **MITRE techniques** — Extracted from Sysmon rules

### Alert Simulator

```bash
python simulator.py
```

Sends a random Wazuh alert every 30 seconds:
- Suspicious PowerShell Command (T1059.001) on WIN-SERVER-01
- Multiple Failed SSH Logins (T1110.001) on UBUNTU-WEB-02
- Ransomware Behavior (T1486) on MAC-DEV-05

---

## 🔗 Wazuh Integration

### Webhook Receiver

SentinelForge includes a dedicated webhook service (port 9090) that accepts Wazuh alerts and normalizes them automatically. It handles:

- Nested Wazuh alert formats (`data.win.eventdata`, `rule.mitre`, `agent.name`)
- MITRE technique extraction from Wazuh rule metadata
- Sysmon event data extraction (process names, IPs, usernames)
- Background processing (returns `200 OK` immediately to avoid Wazuh timeout)

### Configure Wazuh Manager

Add this to your Wazuh manager's `ossec.conf`:

```xml
<integration>
  <name>custom-sentinelforge</name>
  <hook_url>http://<SENTINELFORGE_HOST>:9090/webhook/wazuh</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

### Active Response

When you approve a response action, SentinelForge executes real containment via the Wazuh Manager API:

1. Authenticates with the Wazuh API (`/security/user/authenticate`)
2. Resolves the agent ID by hostname (`/agents?q=name=...`)
3. Sends the active-response command (`PUT /active-response`)

Supported active-response commands:

| SentinelForge Action | Wazuh Command | What It Does |
|---------------------|---------------|--------------|
| `block_ip` | `netsh` | Block IP via Windows Firewall |
| `isolate_host` | `netsh` | Network isolation |
| `disable_account` | `disable-account` | Disable user account |
| `mitigate_threat` | `mitigate-threat` | Custom kill + quarantine + clean script |

---

## 🔒 Wazuh Detection & Mitigation Setup

These PowerShell scripts configure a **Windows** Wazuh agent for enhanced detection and automated response.

### Detection Setup (Tiers 1, 2 & 3)

The platform provides layered defense-in-depth detection tiers:
- **Tier 1 (Windows Defender)** — Forwards native Windows Defender detections directly to the SOC platform.
- **Tier 2 (Sysmon)** — Catches execution and behavior, including fileless malware, by logging process creation, network connections, and registry modifications.
- **Tier 3 (VirusTotal)** — Performs hash lookups on file drops via real-time FIM (detect-on-download, no execution required).

#### 1. Agent Setup (Tiers 1, 2, & 3 FIM)

Run in an **elevated PowerShell**:

```powershell
.\setup-detection.ps1
```

This will:
1. Back up the current Wazuh agent config (`ossec.conf.bak_*`)
2. Add Windows Defender event channel forwarding (**Tier 1**)
3. Download and install Sysmon with SwiftOnSecurity rules (**Tier 2**)
4. Add Sysmon event channel forwarding to Wazuh
5. Enable real-time File Integrity Monitoring on the `Downloads` folder for VirusTotal hash lookups (**Tier 3**)
6. Validate the XML config (auto-restores backup on failure)
7. Restart the Wazuh agent

#### 2. Manager Setup (Tier 3 VirusTotal Integration)

To enable Tier 3 detect-on-download capabilities, you need a free VirusTotal API key.
Add the following to your manager's `/var/ossec/etc/ossec.conf` file:

```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_VIRUSTOTAL_API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```
Restart the manager to apply the integration: `docker restart wazuh.manager`

#### 3. Verification (EICAR Test)

To verify the pipeline is fully operational:
1. Download the harmless **[EICAR test file](https://www.eicar.org/download-anti-malware-testfile/)** into your `Downloads` directory.
2. The agent will immediately hash it (FIM).
3. The manager queries VirusTotal and fires a high-severity alert.
4. The alert hits SentinelForge via Webhook and appears in the dashboard without ever executing the file.

### Mitigation Setup (Active Response)

Run in an **elevated PowerShell**:

```powershell
.\setup-mitigation.ps1
```

This will:
1. Deploy the `mitigate-threat.cmd` script to the Wazuh agent's active-response directory
2. Register the `mitigate-threat` command in the Wazuh manager config
3. Restart both the Wazuh manager container and local agent

### Forensic Analysis Scripts

Parse Wazuh/Sysmon alert logs from JSON:

```bash
# Full forensic report (processes, files, network, DNS, registry, DLLs)
cat alerts.json | python extract_forensics.py

# Quick alert summary (rule, MITRE, image, target)
cat alerts.json | python parse_alerts.py
```

---

## ⚙️ Configuration

All configuration is via environment variables. Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

### Core Settings

| Variable | Default (Docker) | Default (Local) | Description |
|----------|-----------------|-----------------|-------------|
| `DATABASE_URL` | `postgresql://sentinel:sentinel@postgres:5432/sentinelforge` | `sqlite:///./sentinelforge.db` | Database connection string |
| `LLM_URL` | `http://llm:8080` | `http://localhost:8080` | llama.cpp server URL |
| `CHROMA_HOST` | `chromadb` | `localhost` | ChromaDB hostname |
| `CHROMA_PORT` | `8000` | `8000` | ChromaDB port |
| `CORS_ORIGINS` | `http://localhost:3000,http://frontend:3000` | `http://localhost:3000` | Allowed CORS origins (comma-separated) |
| `WEBHOOK_URL` | `http://wazuh-webhook:9090/webhook/generic` | `http://localhost:9999/webhook` | Webhook forwarding URL |
| `DEDUP_WINDOW_MIN` | `60` | `60` | Alert deduplication window in minutes |

### Wazuh Integration (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `INDEXER_URL` | `https://localhost:9200` | Wazuh indexer (OpenSearch) URL |
| `INDEXER_USER` | `admin` | Indexer username |
| `INDEXER_PASS` | `SecretPassword` | Indexer password |
| `WAZUH_API_URL` | `https://localhost:55000` | Wazuh manager API URL |
| `WAZUH_API_USER` | `wazuh-wui` | Wazuh API username |
| `WAZUH_API_PASS` | `MyS3cr37P450r.*-` | Wazuh API password |

### Security & Threat Intel (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `ABUSEIPDB_KEY` | *(empty)* | AbuseIPDB API key for real CTI lookups |
| `API_KEY` | *(empty)* | API authentication key (enforced when set) |

---

## 🔧 Troubleshooting

| Problem | Solution |
|---------|----------|
| **LLM container keeps restarting** | Ensure ~4 GB RAM free. Check model exists in `models/` (~2.3 GB). Try `docker compose logs llm`. |
| **Backend can't connect to PostgreSQL** | Wait 10–15 sec for health check. `docker compose logs postgres`. Falls back to SQLite automatically. |
| **Frontend shows "Network Error"** | Ensure backend is running on port 8001. Check `docker compose logs backend`. |
| **ChromaDB errors** | Optional — backend falls back to local PersistentClient. `docker compose logs chromadb`. |
| **"No Sysmon events found"** | Sysmon must be installed and forwarding to Wazuh. Run `setup-detection.ps1`. |
| **Active response not working** | Run `setup-mitigation.ps1`. Ensure Wazuh API credentials are correct in `.env`. |
| **`pip install` fails on `psycopg2-binary`** | Install `libpq-dev`: `sudo apt install libpq-dev` |
| **Permission denied on `.ps1` scripts** | Run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| **Port already in use** | Change port mapping in `docker-compose.yml` or stop conflicting service. |
| **LLM responses are slow** | Normal — Phi-3 runs on CPU. First request loads the model. Increase `--parallel` in docker-compose for throughput. |

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**Built with ❤️ for the cybersecurity community**

</div>
