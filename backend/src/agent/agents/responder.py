import json
import logging
from src.llm.phi3_client import complete
from src.agent.prompts import RESPONDER_PROMPT

logger = logging.getLogger(__name__)


# Rules-based action mapping as fallback
RISK_ACTIONS = {
    "critical": ["block_ip", "isolate_host", "kill_process", "disable_account", "create_ticket"],
    "high": ["block_ip", "isolate_host", "create_ticket"],
    "medium": ["block_ip", "create_ticket"],
    "low": ["create_ticket"],
}


class ResponderAgent:
    async def suggest(self, incident_summary: str, risk_level: str) -> list[str]:
        """Suggest response actions based on the incident. Does NOT execute."""
        prompt = RESPONDER_PROMPT.format(incident=incident_summary)
        try:
            response = await complete(prompt)
        except Exception as exc:
            logger.warning("Responder LLM call failed; using rules-based action mapping: %s", exc)
            return RISK_ACTIONS.get(risk_level, ["create_ticket"])
        actions = self._parse_actions(response)
        if not actions:
            actions = RISK_ACTIONS.get(risk_level, ["create_ticket"])
        return actions

    def _parse_actions(self, response: str) -> list[str]:
        try:
            start = response.find("[")
            end = response.rfind("]") + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except (json.JSONDecodeError, ValueError):
            pass
        return []
