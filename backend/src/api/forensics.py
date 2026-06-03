"""Forensics & Threat Mitigation API — gathers Sysmon telemetry for an incident
and provides full remediation (kill process tree + clean dropped files)."""

import json
import logging
import re
import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.memory.database import get_db, Incident
from src.tools.wazuh_response import trigger_active_response
from src.config import INDEXER_URL, INDEXER_USER, INDEXER_PASS

logger = logging.getLogger(__name__)
router = APIRouter()

# ── helpers ─────────────────────────────────────────────────────────────────

async def _opensearch_query(pattern: str, max_lines: int = 500) -> list[dict]:
    """Query the manager's OpenSearch index for a pattern and parse JSON lines."""
    # Escape Lucene special characters for query_string
    escaped = re.sub(r'([+\-=&|><!(){}\[\]^"~*?:\\/])', r'\\\1', pattern)
    
    query = {
        "size": max_lines,
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": f'*{escaped}* AND rule.groups:sysmon'
                        }
                    }
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            resp = await client.post(
                f"{INDEXER_URL}/wazuh-alerts-*/_search",
                auth=(INDEXER_USER, INDEXER_PASS),
                json=query
            )
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
            return [hit.get("_source", {}) for hit in hits]
    except Exception as e:
        logger.error("OpenSearch query failed: %s", e)
        return []


def _categorize_events(alerts: list[dict]) -> dict:
    """Categorize Sysmon alerts by Event ID into forensic buckets."""
    categories: dict[str, list] = {
        "processes_spawned": [],
        "files_created": [],
        "network_connections": [],
        "dlls_loaded": [],
        "registry_modifications": [],
        "dns_queries": [],
        "other_events": [],
    }
    rules_fired: dict[str, int] = {}
    mitre_techniques: set[str] = set()
    risk_indicators: list[str] = []
    seen_files: set[str] = set()
    seen_procs: set[str] = set()
    seen_nets: set[str] = set()

    for a in alerts:
        rule = a.get("rule", {})
        data = a.get("data", {}).get("win", {})
        ed = data.get("eventdata", {})
        sd = data.get("system", {})
        eid = sd.get("eventID", "")
        ts = a.get("timestamp", "")

        # Track rules
        rdesc = rule.get("description", "Unknown")
        rules_fired[rdesc] = rules_fired.get(rdesc, 0) + 1

        # Track MITRE
        mitre = rule.get("mitre", {})
        if isinstance(mitre, dict):
            for tid in mitre.get("id", []):
                mitre_techniques.add(tid)
            for tech in mitre.get("technique", []):
                mitre_techniques.add(tech)

        if eid == "1":  # Process Create
            img = ed.get("image", "")
            cmd = ed.get("commandLine", "")
            pid = ed.get("processId", "")
            key = f"{img}|{pid}"
            if key not in seen_procs:
                seen_procs.add(key)
                categories["processes_spawned"].append({
                    "image": img, "command_line": cmd,
                    "process_id": pid, "user": ed.get("user", ""),
                    "parent_image": ed.get("parentImage", ""),
                    "hashes": ed.get("hashes", ""),
                    "timestamp": ts,
                })
        elif eid == "3":  # Network Connection
            dst = f"{ed.get('destinationIp', '')}:{ed.get('destinationPort', '')}"
            key = f"{ed.get('image', '')}|{dst}"
            if key not in seen_nets:
                seen_nets.add(key)
                categories["network_connections"].append({
                    "image": ed.get("image", ""),
                    "destination_ip": ed.get("destinationIp", ""),
                    "destination_port": ed.get("destinationPort", ""),
                    "protocol": ed.get("protocol", ""),
                    "user": ed.get("user", ""),
                    "timestamp": ts,
                })
        elif eid == "7":  # Image Loaded (DLL)
            dll = ed.get("imageLoaded", ed.get("image", ""))
            if dll not in seen_files:
                seen_files.add(dll)
                categories["dlls_loaded"].append({
                    "image": ed.get("image", ""),
                    "dll_loaded": dll,
                    "hashes": ed.get("hashes", ""),
                    "timestamp": ts,
                })
        elif eid == "11":  # File Created
            target = ed.get("targetFilename", "")
            if target not in seen_files:
                seen_files.add(target)
                categories["files_created"].append({
                    "source_process": ed.get("image", ""),
                    "target_file": target,
                    "timestamp": ts,
                })
        elif eid in ("12", "13"):  # Registry
            categories["registry_modifications"].append({
                "event_type": "CreateKey" if eid == "12" else "SetValue",
                "image": ed.get("image", ""),
                "target_object": ed.get("targetObject", ""),
                "details": ed.get("details", ""),
                "timestamp": ts,
            })
        elif eid == "22":  # DNS Query
            categories["dns_queries"].append({
                "image": ed.get("image", ""),
                "query_name": ed.get("queryName", ""),
                "query_results": ed.get("queryResults", ""),
                "timestamp": ts,
            })
        else:
            categories["other_events"].append({
                "event_id": eid,
                "rule": rdesc,
                "timestamp": ts,
            })

    # Detect risk indicators
    file_targets = [f["target_file"] for f in categories["files_created"]]
    if any("_MEI" in f for f in file_targets):
        risk_indicators.append("PyInstaller packed binary (extracts to _MEI* temp folder)")
    if any("libcrypto" in f.lower() or "libssl" in f.lower() for f in file_targets):
        risk_indicators.append("Drops cryptographic libraries (libcrypto/libssl)")
    if any("python3" in f.lower() for f in file_targets):
        risk_indicators.append("Contains embedded Python runtime")
    if categories["network_connections"]:
        risk_indicators.append(f"Made {len(categories['network_connections'])} network connection(s)")
    if categories["dns_queries"]:
        risk_indicators.append(f"Resolved {len(categories['dns_queries'])} DNS domain(s)")
    if categories["registry_modifications"]:
        risk_indicators.append(f"Modified {len(categories['registry_modifications'])} registry key(s)")
    if any("Temp" in f for f in file_targets):
        risk_indicators.append("Writes to Temp directory (common malware staging)")

    return {
        "categories": {k: v for k, v in categories.items() if v},
        "summary": {k: len(v) for k, v in categories.items()},
        "rules_fired": rules_fired,
        "mitre_techniques": sorted(mitre_techniques),
        "risk_indicators": risk_indicators,
    }


def _extract_process_name(incident: Incident) -> str | None:
    """Extract the suspicious process image name from the incident's alert."""
    if not incident.alert or not incident.alert.raw_json:
        return None
    raw = incident.alert.raw_json
    proc = raw.get("process", "")
    # Try eventdata image path
    ed = raw.get("win_eventdata", {})
    if isinstance(ed, dict):
        img = ed.get("image", "") or ed.get("targetFilename", "")
        if img:
            proc = img
    # Try event_message for the image path
    msg = raw.get("event_message", "")
    if not proc and msg:
        m = re.search(r"Image:\s*(.+?)\\r", msg)
        if m:
            proc = m.group(1)
    return proc if proc else None


def _get_search_pattern(process_path: str) -> str:
    """Extract a safe grep pattern from a process path."""
    # Use the executable filename for broad matching
    parts = process_path.replace("\\\\", "\\").replace("\\", "/").split("/")
    exe_name = parts[-1] if parts else process_path
    # Remove extension and version suffixes for broader matching
    base = exe_name.replace(".exe", "").replace(".EXE", "")
    # Just extract alphanumeric prefix before parentheses or special chars for best fuzzy matching
    m = re.match(r"^([A-Za-z0-9_]+)", base)
    if m:
        return m.group(1)
    return base


# ── endpoints ───────────────────────────────────────────────────────────────

@router.get("/forensics/{incident_id}")
async def get_forensics(incident_id: int, db: Session = Depends(get_db)):
    """Get full forensic analysis of what a threat process did on the system."""
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    process_path = _extract_process_name(inc)
    if not process_path:
        raise HTTPException(status_code=404, detail="No process information found in this incident's alert")

    pattern = _get_search_pattern(process_path)
    alerts = await _opensearch_query(pattern)

    if not alerts:
        return {
            "incident_id": incident_id,
            "process_name": process_path,
            "total_events": 0,
            "message": "No Sysmon events found for this process. The process may not have been executed while Sysmon was active.",
        }

    result = _categorize_events(alerts)
    return {
        "incident_id": incident_id,
        "process_name": process_path,
        "total_events": len(alerts),
        **result,
    }


@router.post("/mitigate/{incident_id}")
async def mitigate_threat(incident_id: int, db: Session = Depends(get_db)):
    """Full threat mitigation: kill process tree, clean dropped files, quarantine executable via Wazuh Active Response."""
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    process_path = _extract_process_name(inc)
    if not process_path:
        raise HTTPException(status_code=404, detail="No process information in this incident")

    hostname = inc.alert.hostname if inc and inc.alert else None
    
    # Send mitigation command to Wazuh Agent
    result = await trigger_active_response("mitigate_threat", hostname, src_ip=None, custom_args=[process_path])
    
    if not result or result.get("status") != "active_response_sent":
        raise HTTPException(status_code=500, detail=f"Failed to trigger mitigation on agent: {result}")

    # Mark as resolved
    inc.status = "resolved"
    db.commit()
    
    return {
        "incident_id": incident_id,
        "process_name": process_path,
        "actions_taken": [
            {
                "action": "mitigation_initiated", 
                "detail": "Mitigation script launched on agent via Wazuh Active Response."
            },
            {
                "action": "incident_resolved",
                "detail": f"Incident #{incident_id} marked as resolved."
            }
        ],
        "errors": [],
        "status": "completed",
    }
