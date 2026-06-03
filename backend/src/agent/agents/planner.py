import json
import logging
from src.llm.phi3_client import complete
from src.agent.prompts import PLANNER_PROMPT
from src.models.schemas import AlertInput
from src.tools.router import ToolRouter

logger = logging.getLogger(__name__)


class PlannerAgent:
    def __init__(self, tool_router: ToolRouter):
        self.tool_router = tool_router

    async def plan(self, alert: AlertInput, context: list[str] | None = None) -> list[str]:
        context = context or []
        tools_desc = "\n".join(
            f"- {t['name']}: {t['description']}" for t in self.tool_router.list_tools()
        )
        prompt = PLANNER_PROMPT.format(
            tools=tools_desc,
            alert=alert.model_dump_json(),
            context="\n".join(context) if context else "None",
        )
        try:
            response = await complete(prompt)
        except Exception as exc:
            logger.warning("Planner LLM call failed; using deterministic fallback plan: %s", exc)
            return self._fallback_steps(alert)
        return self._parse_steps(response, alert)

    def _parse_steps(self, response: str, alert: AlertInput) -> list[str]:
        try:
            # Try to extract JSON list from response
            start = response.find("[")
            end = response.rfind("]") + 1
            if start >= 0 and end > start:
                steps = json.loads(response[start:end])
                return steps[:3]
        except (json.JSONDecodeError, ValueError):
            pass
        return self._fallback_steps(alert)

    def _fallback_steps(self, alert: AlertInput) -> list[str]:
        steps = []
        if alert.destination_ip:
            steps.append(f"cti_lookup:{alert.destination_ip}")
        if alert.hostname:
            steps.append(f"wazuh_host:{alert.hostname}")
        if alert.mitre:
            steps.append(f"mitre_lookup:{alert.mitre}")
        return steps[:3]
