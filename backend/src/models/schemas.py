from pydantic import BaseModel
from pydantic import Field
from typing import Optional
from datetime import datetime


class AlertInput(BaseModel):
    hostname: Optional[str] = None
    username: Optional[str] = None
    process: Optional[str] = None
    destination_ip: Optional[str] = None
    source_ip: Optional[str] = None
    rule: Optional[str] = None
    mitre: Optional[str] = None
    severity: int = 5
    raw_json: Optional[dict] = None


class AgentStepOut(BaseModel):
    id: int
    step_number: int
    phase: str
    agent: str
    thought: Optional[str] = None
    tool_used: Optional[str] = None
    tool_input: Optional[dict] = None
    tool_output: Optional[dict] = None
    conclusion: Optional[str] = None
    created_at: datetime


class ResponseActionOut(BaseModel):
    id: int
    incident_id: int
    action_type: str
    approved: bool
    executed_at: Optional[datetime] = None


class IncidentReport(BaseModel):
    id: int
    alert_id: int
    summary: str
    mitre_tactics: list[str] = Field(default_factory=list)
    risk_level: str
    confidence: float
    status: str = "open"
    created_at: datetime
    steps: list[AgentStepOut] = Field(default_factory=list)
    actions: list[ResponseActionOut] = Field(default_factory=list)


class ThreatSummary(BaseModel):
    total_incidents: int
    critical: int
    high: int
    open_incidents: int
    resolved: int
