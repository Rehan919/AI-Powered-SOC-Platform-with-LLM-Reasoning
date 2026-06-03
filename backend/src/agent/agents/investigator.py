from src.tools.router import ToolRouter


class InvestigatorAgent:
    def __init__(self, tool_router: ToolRouter):
        self.tool_router = tool_router

    def investigate(self, step: str) -> dict:
        """Execute a single investigation step. Format: 'tool_name:input_value'"""
        if ":" not in step:
            return {"error": f"Invalid step format: {step}"}

        tool_name, input_value = step.split(":", 1)
        input_map = self._build_input(tool_name, input_value)

        try:
            result = self.tool_router.execute(tool_name, input_map)
            return {"tool": tool_name, "input": input_value, "result": result}
        except ValueError as e:
            return {"tool": tool_name, "input": input_value, "error": str(e)}

    def _build_input(self, tool_name: str, value: str) -> dict:
        mapping = {
            "cti_lookup": "indicator",
            "mitre_lookup": "technique_id",
            "wazuh_host": "hostname",
            "log_search": "hostname",
        }
        key = mapping.get(tool_name, "query")
        return {key: value}
