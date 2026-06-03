import httpx
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Header, Body
from sqlalchemy.orm import Session
from src.memory.database import get_db, Incident, Action, AgentStep, Alert
from src.agent.manager import AgentManager
from src.tools.wazuh_response import trigger_active_response
from src.config import WEBHOOK_URL, API_KEY

logger = logging.getLogger(__name__)


def require_api_key(x_api_key: str | None = Header(default=None)):
    """Opt-in auth: enforced only when API_KEY env is set."""
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


router = APIRouter(dependencies=[Depends(require_api_key)])
manager = AgentManager()

VALID_STATUSES = {"open", "in_progress", "resolved", "false_positive"}


@router.post("/alert/analyze")
async def analyze_alert(raw_alert: dict):
    result = await manager.analyze(raw_alert)
    return result


@router.get("/incidents")
def list_incidents(skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()
    return [
        {
            "id": inc.id,
            "alert_id": inc.alert_id,
            "summary": inc.summary,
            "mitre_tactics": inc.mitre_tactics,
            "risk_level": inc.risk_level,
            "confidence": inc.confidence,
            "status": inc.status,
            "event_count": inc.event_count,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "hostname": inc.alert.hostname if inc.alert else None,
        }
        for inc in incidents
    ]


@router.get("/incident/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    steps = db.query(AgentStep).filter(AgentStep.incident_id == incident_id).order_by(AgentStep.step_number).all()
    actions = db.query(Action).filter(Action.incident_id == incident_id).all()
    similar = []
    if manager.memory and inc.summary:
        try:
            similar = manager.memory.similar_incidents(inc.summary, exclude_id=inc.id)
        except Exception as exc:
            logger.warning("similar_incidents failed for %s: %s", incident_id, exc)
    return {
        "id": inc.id,
        "alert_id": inc.alert_id,
        "summary": inc.summary,
        "mitre_tactics": inc.mitre_tactics,
        "risk_level": inc.risk_level,
        "confidence": inc.confidence,
        "status": inc.status,
        "event_count": inc.event_count,
        "similar": similar,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "hostname": inc.alert.hostname if inc.alert else None,
        "severity": inc.alert.severity if inc.alert else None,
        "process": inc.alert.raw_json.get("process") if inc.alert and inc.alert.raw_json else None,
        "alert": {
            "id": inc.alert.id,
            "hostname": inc.alert.hostname,
            "username": inc.alert.username,
            "severity": inc.alert.severity,
            "rule_name": inc.alert.rule_name,
            "mitre_id": inc.alert.mitre_id,
            "timestamp": inc.alert.timestamp.isoformat() if inc.alert.timestamp else None,
            "raw_json": inc.alert.raw_json,
        } if inc.alert else None,
        "steps": [
            {
                "id": s.id,
                "step_number": s.step_number,
                "phase": s.phase,
                "agent": s.agent,
                "thought": s.thought,
                "tool_used": s.tool_used,
                "tool_input": s.tool_input,
                "tool_output": s.tool_output,
                "conclusion": s.conclusion,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in steps
        ],
        "actions": [
            {
                "id": a.id,
                "action_type": a.action_type,
                "approved": a.approved,
                "executed_at": a.executed_at.isoformat() if a.executed_at else None,
            }
            for a in actions
        ],
    }


@router.patch("/incident/{incident_id}")
def set_incident_status(incident_id: int, status: str = Body(..., embed=True), db: Session = Depends(get_db)):
    if status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Use one of {sorted(VALID_STATUSES)}")
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc.status = status
    db.commit()
    return {"id": inc.id, "status": inc.status}


@router.post("/response/approve/{action_id}")
async def approve_action(action_id: int, db: Session = Depends(get_db)):
    action = db.query(Action).filter(Action.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    action.approved = True
    action.executed_at = datetime.now(timezone.utc)

    # Resolve host/src_ip for containment
    inc = db.query(Incident).filter(Incident.id == action.incident_id).first()
    hostname = inc.alert.hostname if inc and inc.alert else None
    src_ip = (inc.alert.raw_json or {}).get("source_ip") if inc and inc.alert and inc.alert.raw_json else None

    # Try real Wazuh active-response; fall back to webhook stub
    result = await trigger_active_response(action.action_type, hostname, src_ip)
    if result and result.get("status") == "active_response_sent":
        action.webhook_response = result
        db.commit()
        return {"message": f"Action '{action.action_type}' executed via Wazuh active-response", "response": result}

    webhook_resp = {"status": "sent", "url": WEBHOOK_URL, "action": action.action_type}
    if result:
        webhook_resp["active_response"] = result
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(WEBHOOK_URL, json={"action": action.action_type, "incident_id": action.incident_id})
    except httpx.HTTPError as exc:
        logger.warning("Response webhook unreachable for action %s: %s", action_id, exc)
        webhook_resp["status"] = "webhook_unreachable"
    action.webhook_response = webhook_resp
    db.commit()
    return {"message": f"Action '{action.action_type}' approved and executed", "webhook": webhook_resp}


@router.post("/response/dismiss/{action_id}")
def dismiss_action(action_id: int, db: Session = Depends(get_db)):
    action = db.query(Action).filter(Action.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    action.approved = False
    db.commit()
    return {"message": f"Action '{action.action_type}' dismissed"}


@router.get("/threat-summary")
def threat_summary(db: Session = Depends(get_db)):
    total = db.query(Incident).count()
    critical = db.query(Incident).filter(Incident.risk_level == "critical").count()
    high = db.query(Incident).filter(Incident.risk_level == "high").count()
    open_count = db.query(Incident).filter(Incident.status == "open").count()
    resolved = db.query(Incident).filter(Incident.status == "resolved").count()
    return {"total_incidents": total, "critical": critical, "high": high, "open_incidents": open_count, "resolved": resolved}
