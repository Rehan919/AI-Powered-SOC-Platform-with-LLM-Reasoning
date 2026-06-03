import json
import logging
from src.llm.phi3_client import complete
from src.agent.prompts import REPORTER_PROMPT
from src.models.schemas import AlertInput

logger = logging.getLogger(__name__)


class ReporterAgent:
    async def report(self, alert: AlertInput, evidence: list[dict], steps: list[dict]) -> dict:
        """Generate a detailed markdown report (LLM) with deterministic triage."""
        report = self._fallback_report(alert)
        prompt = REPORTER_PROMPT.format(
            alert=alert.model_dump_json(),
            evidence=json.dumps(evidence, default=str),
        )
        try:
            narrative = (await complete(prompt, max_tokens=180)).strip()
        except Exception as exc:
            logger.warning("Reporter LLM call failed; using deterministic fallback report: %s", exc)
            return report
        if narrative:
            report["summary"] = narrative
            report["confidence"] = 80.0
        return report

    def _fallback_report(self, alert: AlertInput) -> dict:
        mitre = [alert.mitre] if alert.mitre else []
        risk = "critical" if alert.severity >= 9 else "high" if alert.severity >= 7 else "medium"
        summary = (
            f"## Summary\n{alert.rule or 'Security alert'} detected on {alert.hostname}.\n\n"
            f"## What Happened\nProcess: {alert.process}. User: {alert.username}. "
            f"Source IP: {alert.source_ip or 'n/a'}.\n\n"
            f"## Recommended Actions\n- Investigate the host {alert.hostname}\n- Review related activity for the user\n- Correlate with other alerts"
        )
        return {
            "summary": summary,
            "mitre_tactics": mitre,
            "risk_level": risk,
            "confidence": 60.0,
        }
