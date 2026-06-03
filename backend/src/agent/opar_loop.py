import json
import logging
from src.models.schemas import AlertInput
from src.agent.agents.planner import PlannerAgent
from src.agent.agents.investigator import InvestigatorAgent
from src.agent.prompts import REFLECT_PROMPT
from src.llm.phi3_client import complete
from src.tools.router import ToolRouter

MAX_ITERATIONS = 1
logger = logging.getLogger(__name__)


class OPARLoop:
    def __init__(self, tool_router: ToolRouter = None):
        self.tool_router = tool_router or ToolRouter()
        self.planner = PlannerAgent(self.tool_router)
        self.investigator = InvestigatorAgent(self.tool_router)

    async def run(self, alert: AlertInput, context: list[str] | None = None) -> dict:
        """Run OPAR loop: Observe → Plan → Act → Reflect. Returns evidence and steps."""
        steps_log = []
        evidence = []
        context = context or []

        # OBSERVE
        steps_log.append({"phase": "observe", "agent": "system", "conclusion": f"Alert received: {alert.rule or 'Unknown'} on {alert.hostname}"})

        for iteration in range(MAX_ITERATIONS):
            # PLAN
            plan = await self.planner.plan(alert, context + [json.dumps(e) for e in evidence])
            steps_log.append({"phase": "plan", "agent": "planner", "conclusion": f"Plan: {plan}", "tool_output": plan})

            # ACT
            for step in plan:
                result = self.investigator.investigate(step)
                evidence.append(result)
                steps_log.append({
                    "phase": "act",
                    "agent": "investigator",
                    "tool_used": result.get("tool"),
                    "tool_input": {"step": step},
                    "tool_output": result.get("result"),
                    "conclusion": f"Investigated: {step}",
                })

            # REFLECT
            reflect_prompt = REFLECT_PROMPT.format(
                alert=alert.model_dump_json(),
                evidence=json.dumps(evidence, default=str),
            )
            try:
                reflection = await complete(reflect_prompt)
            except Exception as exc:
                logger.warning("Reflection LLM call failed; using fallback decision: %s", exc)
                reflection = "YES" if evidence else "NO"
            sufficient = "YES" in reflection.upper()
            steps_log.append({"phase": "reflect", "agent": "system", "thought": reflection, "conclusion": "Sufficient" if sufficient else "Need more"})

            if sufficient:
                break

        return {"evidence": evidence, "steps": steps_log}
