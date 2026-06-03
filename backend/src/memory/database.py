import json
import logging
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, TypeDecorator, text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime, timezone
from src.config import DATABASE_URL


# Custom types that work with both SQLite and PostgreSQL
class JSONType(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return None

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return None


class ArrayType(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return "[]"

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return []


SQLITE_URL = "sqlite:///./sentinelforge.db"
logger = logging.getLogger(__name__)


def _build_engine(url: str):
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url, connect_args={"connect_timeout": 2})


def _resolve_engine():
    """Use the configured DB; fall back to SQLite if it is unreachable
    (e.g. a Docker-only Postgres host when running locally)."""
    if DATABASE_URL.startswith("sqlite"):
        return _build_engine(DATABASE_URL)
    if not DATABASE_URL.startswith("sqlite"):
        try:
            eng = _build_engine(DATABASE_URL)
            with eng.connect():
                pass
            return eng
        except Exception as exc:
            logger.warning("Database '%s' unreachable (%s); falling back to SQLite.", DATABASE_URL, exc)
    return _build_engine(SQLITE_URL)


engine = _resolve_engine()
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    hostname = Column(String)
    username = Column(String)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    raw_json = Column(JSONType)
    severity = Column(Integer)
    rule_name = Column(String)
    mitre_id = Column(String)
    incident = relationship("Incident", back_populates="alert", uselist=False)


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"))
    summary = Column(Text)
    mitre_tactics = Column(ArrayType, default=list)
    risk_level = Column(String, default="medium")
    confidence = Column(Float, default=0.0)
    status = Column(String, default="open")
    event_count = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    alert = relationship("Alert", back_populates="incident")
    steps = relationship("AgentStep", back_populates="incident", order_by="AgentStep.step_number")
    actions = relationship("Action", back_populates="incident")


class Action(Base):
    __tablename__ = "actions"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    action_type = Column(String)
    approved = Column(Boolean, default=False)
    executed_at = Column(DateTime(timezone=True))
    webhook_response = Column(JSONType)
    incident = relationship("Incident", back_populates="actions")


class AgentStep(Base):
    __tablename__ = "agent_steps"
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    step_number = Column(Integer)
    phase = Column(String)
    agent = Column(String)
    thought = Column(Text)
    tool_used = Column(String)
    tool_input = Column(JSONType)
    tool_output = Column(JSONType)
    conclusion = Column(String)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    incident = relationship("Incident", back_populates="steps")


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate()


def _migrate():
    """Best-effort additive migrations for pre-existing tables."""
    stmts = ["ALTER TABLE incidents ADD COLUMN event_count INTEGER DEFAULT 1"]
    for s in stmts:
        try:
            with engine.begin() as conn:
                conn.execute(text(s))
        except Exception:
            pass  # column already exists


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
