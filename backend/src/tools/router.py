from src.tools.cti_lookup import CTILookupTool
from src.tools.mitre_lookup import MITRELookupTool
from src.tools.wazuh_host import WazuhHostTool
from src.tools.log_search import LogSearchTool


class ToolRouter:
    def __init__(self):
        self.tools = {}
        for tool_cls in [CTILookupTool, MITRELookupTool, WazuhHostTool, LogSearchTool]:
            tool = tool_cls()
            self.tools[tool.name] = tool

    def list_tools(self) -> list[dict]:
        return [{"name": t.name, "description": t.description} for t in self.tools.values()]

    def execute(self, tool_name: str, input: dict) -> dict:
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        return self.tools[tool_name].run(input)
