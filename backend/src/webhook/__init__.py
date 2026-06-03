"""Wazuh webhook receiver — accepts alerts from Wazuh active response / integrations
and forwards them to the SentinelForge analysis pipeline."""

import asyncio
import logging
import os
import httpx
from fastapi import FastAPI, Request, BackgroundTasks

app = FastAPI(title="SentinelForge Wazuh Webhook")
logger = logging.getLogger(__name__)

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8001")
_HEADERS = {"X-API-Key": os.environ["API_KEY"]} if os.getenv("API_KEY") else {}


async def _process_alert(alert: dict):
    """Background task: forward alert to the AI backend (may take minutes)."""
    try:
        async with httpx.AsyncClient(timeout=600.0) as client:
            resp = await client.post(f"{BACKEND_URL}/alert/analyze", json=alert, headers=_HEADERS)
            resp.raise_for_status()
            result = resp.json()
        logger.info("Alert analyzed: incident_id=%s risk=%s", result.get("incident_id"), result.get("risk_level"))
    except Exception as e:
        logger.error("Failed to process alert: %s", e)


@app.post("/webhook/wazuh")
async def receive_wazuh_alert(request: Request, background_tasks: BackgroundTasks):
    """Receives raw Wazuh alert JSON and forwards to the analysis endpoint.
    Returns immediately to avoid Wazuh integratord timeout."""
    payload = await request.json()

    # Wazuh sends alerts nested under different keys depending on config
    alert = _extract_alert(payload)

    # Fire and forget — return 200 instantly, process in background
    background_tasks.add_task(_process_alert, alert)
    logger.info("Alert received and queued for analysis")
    return {"status": "queued"}


@app.post("/webhook/generic")
async def receive_generic_alert(request: Request):
    """Generic webhook endpoint for any SIEM/alert source."""
    payload = await request.json()
    async with httpx.AsyncClient(timeout=300.0) as client:
        resp = await client.post(f"{BACKEND_URL}/alert/analyze", json=payload, headers=_HEADERS)
        resp.raise_for_status()
        return resp.json()


@app.get("/health")
def health():
    return {"status": "ok", "service": "wazuh-webhook"}


def _extract_alert(payload: dict) -> dict:
    """Normalize Wazuh webhook payload formats."""
    # Wazuh sends alerts with some fields at root and some inside 'data'
    data = payload.get("data", {}) if isinstance(payload.get("data"), dict) else payload
    win = data.get("win", {}) if isinstance(data.get("win"), dict) else {}
    system = win.get("system", {}) if isinstance(win.get("system"), dict) else {}
    eventdata = win.get("eventdata", {}) if isinstance(win.get("eventdata"), dict) else {}

    def get_val(key, subkey=None):
        # Check root first, then data
        val = payload.get(key)
        if val is None:
            val = data.get(key)
        if isinstance(val, dict) and subkey:
            return val.get(subkey)
        return val

    # Map Wazuh fields to SentinelForge expected format
    return {
        "hostname": get_val("agent", "name") or get_val("hostname") or "Unknown",
        "username": data.get("dstuser") or eventdata.get("targetUserName") or eventdata.get("subjectUserName") or payload.get("username") or "Unknown",
        "process": data.get("process_name") or eventdata.get("processName") or eventdata.get("image") or payload.get("process") or "Unknown",
        "destination_ip": data.get("dstip") or payload.get("destination_ip"),
        "source_ip": data.get("srcip") or eventdata.get("ipAddress") or payload.get("source_ip"),
        "rule": get_val("rule", "description") or get_val("rule") or "Unknown Alert",
        "mitre": _extract_mitre(payload),
        "severity": get_val("rule", "level") or get_val("severity") or 5,
        # Preserve rich context for the LLM (kept in raw_json), capped to keep prompts small
        "event_message": (system.get("message") or payload.get("full_log") or "")[:600] or None,
        "event_id": system.get("eventID"),
        "win_eventdata": eventdata or None,
    }


def _extract_mitre(data: dict) -> str | None:
    """Extract MITRE technique ID from Wazuh alert."""
    rule = data.get("rule", {})
    if isinstance(rule, dict):
        mitre = rule.get("mitre", {})
        if isinstance(mitre, dict):
            ids = mitre.get("id", [])
            return ids[0] if ids else None
    return data.get("mitre")
