from pathlib import Path

from src.webhook import _extract_alert
from src.tools.mitre_lookup import MITRELookupTool
from src.models.schemas import AlertInput
from src.memory.database import init_db, SessionLocal, Alert, Incident
from src.agent.manager import AgentManager
from src.config import DATABASE_URL


def test_extract_alert_real_wazuh_shape():
    payload = {
        "agent": {"name": "WH-01"},
        "rule": {"description": "Logon failure", "level": 9, "mitre": {"id": ["T1059.001"]}},
        "data": {"win": {"system": {"eventID": "4625", "message": "an account failed to log on"},
                         "eventdata": {"targetUserName": "bob", "ipAddress": "1.2.3.4"}}},
    }
    a = _extract_alert(payload)
    assert a["hostname"] == "WH-01"
    assert a["rule"] == "Logon failure"
    assert a["severity"] == 9
    assert a["mitre"] == "T1059.001"
    assert a["username"] == "bob"
    assert a["source_ip"] == "1.2.3.4"
    assert a["event_id"] == "4625"
    assert a["win_eventdata"]["targetUserName"] == "bob"


def test_mitre_subtechnique_resolves_to_parent():
    r = MITRELookupTool().run({"technique_id": "T1484.001"})
    assert r["name"] != "Unknown"
    assert r["tactic"] != "Unknown"


def test_find_duplicate_increments_event_count():
    init_db()
    db = SessionLocal()
    try:
        a = Alert(hostname="HOST-DUP", rule_name="Repeat rule", severity=8)
        db.add(a)
        db.flush()
        inc = Incident(alert_id=a.id, summary="s", risk_level="high", status="open", event_count=1)
        db.add(inc)
        db.commit()
        inc_id = inc.id
    finally:
        db.close()

    dup = AgentManager()._find_duplicate(AlertInput(hostname="HOST-DUP", rule="Repeat rule", severity=8))
    assert dup is not None
    assert dup["incident_id"] == inc_id
    assert dup["event_count"] == 2
    assert dup["deduped"] is True


def test_tests_use_isolated_sqlite_database():
    assert DATABASE_URL.startswith("sqlite:///")
    assert Path(DATABASE_URL.removeprefix("sqlite:///")).name == ".pytest-sentinelforge.db"
