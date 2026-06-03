import pytest

from src.agent.agents.planner import PlannerAgent
from src.agent.agents.reporter import ReporterAgent
from src.agent.agents.responder import ResponderAgent
from src.api.normalizer import normalize_alert
from src.models.schemas import AlertInput
from src.tools.router import ToolRouter


async def failing_complete(*args, **kwargs):
    raise RuntimeError("llm unavailable")


def test_normalize_alert_defaults_bad_severity():
    alert = normalize_alert({"agent": "WIN-PC", "severity": "not-a-number"})

    assert alert.hostname == "WIN-PC"
    assert alert.severity == 5


@pytest.mark.asyncio
async def test_planner_uses_alert_fields_when_llm_fails(monkeypatch):
    import src.agent.agents.planner as planner_module

    monkeypatch.setattr(planner_module, "complete", failing_complete)
    planner = PlannerAgent(ToolRouter())
    alert = AlertInput(hostname="WIN-PC", destination_ip="185.199.1.20", mitre="T1059")

    steps = await planner.plan(alert)

    assert steps == ["cti_lookup:185.199.1.20", "wazuh_host:WIN-PC", "mitre_lookup:T1059"]


@pytest.mark.asyncio
async def test_reporter_uses_severity_risk_when_llm_fails(monkeypatch):
    import src.agent.agents.reporter as reporter_module

    monkeypatch.setattr(reporter_module, "complete", failing_complete)
    reporter = ReporterAgent()
    alert = AlertInput(hostname="WIN-PC", process="powershell.exe", rule="Suspicious Powershell", mitre="T1059", severity=10)

    report = await reporter.report(alert, evidence=[], steps=[])

    assert report["risk_level"] == "critical"
    assert report["mitre_tactics"] == ["T1059"]
    assert report["confidence"] == 60.0


@pytest.mark.asyncio
async def test_responder_uses_risk_mapping_when_llm_fails(monkeypatch):
    import src.agent.agents.responder as responder_module

    monkeypatch.setattr(responder_module, "complete", failing_complete)
    responder = ResponderAgent()

    actions = await responder.suggest("Suspicious PowerShell activity", "high")

    assert actions == ["block_ip", "isolate_host", "create_ticket"]
