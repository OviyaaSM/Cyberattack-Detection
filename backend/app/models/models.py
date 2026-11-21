import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from app.database.session import Base

class Computer(Base):
    __tablename__ = "computers"

    id = Column(String(64), primary_key=True, index=True)
    hostname = Column(String(128), index=True, nullable=False)
    ip_address = Column(String(64), nullable=False)
    os_type = Column(String(64), default="Linux")
    role = Column(String(64), default="Workstation")  # Workstation, Server, Domain Controller, etc.
    status = Column(String(32), default="HEALTHY")    # HEALTHY, SUSPICIOUS, COMPROMISED
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    events = relationship("SecurityEvent", back_populates="computer", cascade="all, delete-orphan")


class UserIdentity(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True, index=True)
    username = Column(String(128), unique=True, index=True, nullable=False)
    role = Column(String(64), default="user")          # user, admin, service_account
    department = Column(String(64), default="IT")
    is_privileged = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, index=True, nullable=False)
    computer_id = Column(String(64), ForeignKey("computers.id"), index=True, nullable=False)
    hostname = Column(String(128), index=True, nullable=False)
    user_id = Column(String(64), index=True, nullable=False)
    source_ip = Column(String(64), index=True, nullable=False)
    destination_ip = Column(String(64), index=True, nullable=False)
    event_type = Column(String(64), index=True, nullable=False)
    action = Column(String(128), nullable=False)
    status = Column(String(32), default="SUCCESS")     # SUCCESS, FAILURE, ATTEMPT
    severity = Column(String(32), default="LOW")       # LOW, MEDIUM, HIGH, CRITICAL
    session_id = Column(String(64), index=True, nullable=True)
    metadata_json = Column(Text, default="{}")
    raw_data = Column(Text, nullable=True)
    is_simulated = Column(Boolean, default=False)
    simulation_run_id = Column(String(64), nullable=True, index=True)
    ingestion_timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    computer = relationship("Computer", back_populates="events")
    evidence_items = relationship("AlertEvidence", back_populates="event", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_event_time_comp", "timestamp", "computer_id"),
        Index("ix_event_time_user", "timestamp", "user_id"),
        Index("ix_event_time_type", "timestamp", "event_type"),
    )


class TemporalRelationship(Base):
    __tablename__ = "temporal_relationships"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_event_id = Column(String(64), ForeignKey("security_events.event_id"), index=True, nullable=False)
    target_event_id = Column(String(64), ForeignKey("security_events.event_id"), index=True, nullable=False)
    relation_type = Column(String(64), index=True, nullable=False) # BEFORE, AFTER, SIMULTANEOUS, WITHIN_TIME_WINDOW, OVERLAPS, CAUSALLY_RELATED_CANDIDATE
    delta_seconds = Column(Float, nullable=False)
    confidence = Column(Float, default=1.0)
    evidence_text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    __table_args__ = (
        Index("ix_temp_src_tgt", "source_event_id", "target_event_id"),
    )


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=False)
    scenario = Column(String(64), nullable=False)
    severity = Column(String(32), default="HIGH")       # LOW, MEDIUM, HIGH, CRITICAL
    default_risk_score = Column(Float, default=75.0)
    time_window_minutes = Column(Integer, default=30)
    is_enabled = Column(Boolean, default=True)
    parameters_json = Column(Text, default="{}")

    alerts = relationship("AttackAlert", back_populates="rule")


class AttackAlert(Base):
    __tablename__ = "attack_alerts"

    id = Column(String(64), primary_key=True, index=True)
    rule_id = Column(String(64), ForeignKey("detection_rules.id"), index=True, nullable=False)
    rule_name = Column(String(128), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), default="HIGH")       # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, default=70.0)            # 0 - 100
    affected_computers = Column(Text, default="[]")     # JSON list of computer_ids
    related_users = Column(Text, default="[]")          # JSON list of user_ids
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    status = Column(String(32), default="NEW")          # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    explanation = Column(Text, nullable=False)
    temporal_constraints = Column(Text, default="{}")   # JSON satisfied constraints
    detection_timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    rule = relationship("DetectionRule", back_populates="alerts")
    evidence = relationship("AlertEvidence", back_populates="alert", cascade="all, delete-orphan")
    investigation_reports = relationship("InvestigationReport", back_populates="alert", cascade="all, delete-orphan")


class AlertEvidence(Base):
    __tablename__ = "alert_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), ForeignKey("attack_alerts.id"), index=True, nullable=False)
    event_id = Column(String(64), ForeignKey("security_events.event_id"), index=True, nullable=False)
    sequence_order = Column(Integer, default=1)
    stage_name = Column(String(64), default="Execution")
    role_in_attack = Column(Text, nullable=False)

    alert = relationship("AttackAlert", back_populates="evidence")
    event = relationship("SecurityEvent", back_populates="evidence_items")


class SimulationRun(Base):
    __tablename__ = "simulation_runs"

    id = Column(String(64), primary_key=True, index=True)
    scenario_name = Column(String(128), nullable=False)
    status = Column(String(32), default="RUNNING")      # RUNNING, COMPLETED, STOPPED, FAILED
    events_generated = Column(Integer, default=0)
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    seed = Column(Integer, nullable=True)


class InvestigationReport(Base):
    __tablename__ = "investigation_reports"

    id = Column(String(64), primary_key=True, index=True)
    alert_id = Column(String(64), ForeignKey("attack_alerts.id"), index=True, nullable=False)
    summary = Column(Text, nullable=False)
    technical_analysis = Column(Text, nullable=False)
    temporal_analysis = Column(Text, nullable=False)
    recommended_actions = Column(Text, default="[]")    # JSON list of action steps
    generated_by = Column(String(64), default="DETERMINISTIC_ENGINE") # DETERMINISTIC_ENGINE, AI_ASSISTANT
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    alert = relationship("AttackAlert", back_populates="investigation_reports")
