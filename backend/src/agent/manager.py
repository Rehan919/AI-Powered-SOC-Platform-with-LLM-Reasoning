import logging
from datetime import datetime, timezone, timedelta

from src.api.normalizer import normalize_alert
from src.agent.opar_loop import OPARLoop
from src.agent.agents.reporter import ReporterAgent
from src.agent.agents.responder import ResponderAgent
from src.tools.router import ToolRouter
from src.memory.database import SessionLocal, Alert, Incident, Action, AgentStep
from src.memory.vector_store import SecurityMemory
from src.config import DEDUP_WINDOW_MIN

logger = logging.getLogger(__name__)


class AgentManager:
    def __init__(self):
        self.tool_router = ToolRouter()
        self.opar = OPARLoop(self.tool_router)
        self.reporter = ReporterAgent()
        self.responder = ResponderAgent()
        self.memory = None
        try:
            self.memory = SecurityMemory()
            self.memory.seed_knowledge()
        except Exception as exc:
            logger.warning("Security memory is unavailable; continuing without RAG: %s", exc)

    def _find_duplicate(self, alert):
        """Return an existing open incident (same host+rule, within the dedup
        window) with its event_count incremented, or None."""
        if not alert.hostname or not alert.rule:
            return None
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=DEDUP_WINDOW_MIN)
        db = SessionLocal()
        try:
            inc = (db.query(Incident).join(Alert, Incident.alert_id == Alert.id)
                   .filter(Incident.status == "open",
                           Alert.hostname == alert.hostname,
                           Alert.rule_name == alert.rule,
                           Incident.created_at >= cutoff)
                   .order_by(Incident.created_at.desc()).first())
            if not inc:
                return None
            inc.event_count = (inc.event_count or 1) + 1
            db.commit()
            return {
                "incident_id": inc.id,
                "alert_id": inc.alert_id,
                "summary": inc.summary,
                "mitre_tactics": inc.mitre_tactics,
                "risk_level": inc.risk_level,
                "confidence": inc.confidence,
                "status": inc.status,
                "event_count": inc.event_count,
                "actions": [a.action_type for a in inc.actions],
                "deduped": True,
            }
        finally:
            db.close()

    async def analyze(self, raw_alert: dict) -> dict:
        """Full pipeline: normalize → OPAR → report → suggest → store."""
        alert = normalize_alert(raw_alert)

        # Correlation/dedup: fold repeat alerts (same host+rule, still open, recent)
        # into the existing incident instead of creating a new one.
        dup = self._find_duplicate(alert)
        if dup is not None:
            return dup

        # Query RAG for context
        context = []
        if self.memory:
            try:
                query = f"{alert.rule} {alert.mitre} {alert.process} {alert.hostname}"
                context = self.memory.query_context(query)
            except Exception as exc:
                logger.warning("Security memory query failed; continuing without RAG context: %s", exc)

        # Run OPAR loop
        opar_result = await self.opar.run(alert, context=context)

        # Generate report
        report = await self.reporter.report(alert, opar_result["evidence"], opar_result["steps"])

        # Suggest response actions
        actions = await self.responder.suggest(report["summary"], report["risk_level"])

        # Store in database
        db = SessionLocal()
        try:
            db_alert = Alert(
                hostname=alert.hostname,
                username=alert.username,
                raw_json=raw_alert,
                severity=alert.severity,
                rule_name=alert.rule,
                mitre_id=alert.mitre,
            )
            db.add(db_alert)
            db.flush()

            db_incident = Incident(
                alert_id=db_alert.id,
                summary=report["summary"],
                mitre_tactics=report["mitre_tactics"],
                risk_level=report["risk_level"],
                confidence=report["confidence"],
            )
            db.add(db_incident)
            db.flush()

            # Store agent steps
            for i, step in enumerate(opar_result["steps"]):
                db_step = AgentStep(
                    incident_id=db_incident.id,
                    step_number=i + 1,
                    phase=step.get("phase", ""),
                    agent=step.get("agent", ""),
                    thought=step.get("thought"),
                    tool_used=step.get("tool_used"),
                    tool_input=step.get("tool_input"),
                    tool_output=step.get("tool_output") if not isinstance(step.get("tool_output"), list) else {"steps": step["tool_output"]},
                    conclusion=step.get("conclusion"),
                )
                db.add(db_step)

            # Store suggested actions
            for action_type in actions:
                db_action = Action(incident_id=db_incident.id, action_type=action_type)
                db.add(db_action)

            db.commit()
            db.refresh(db_incident)

            # Store in vector memory for future RAG
            if self.memory:
                try:
                    self.memory.store_incident(db_incident.id, report["summary"], report["mitre_tactics"])
                except Exception as exc:
                    logger.warning("Failed to store incident %s in security memory: %s", db_incident.id, exc)

            return {
                "incident_id": db_incident.id,
                "alert_id": db_alert.id,
                "summary": report["summary"],
                "mitre_tactics": report["mitre_tactics"],
                "risk_level": report["risk_level"],
                "confidence": report["confidence"],
                "status": db_incident.status,
                "event_count": db_incident.event_count,
                "actions": actions,
                "steps_count": len(opar_result["steps"]),
            }
        finally:
            db.close()
