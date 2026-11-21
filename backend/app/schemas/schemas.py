import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

# Computer Schemas
class ComputerBase(BaseModel):
    id: str
    hostname: str
    ip_address: str
    os_type: str = "Linux"
    role: str = "Workstation"
    status: str = "HEALTHY"

class ComputerCreate(ComputerBase):
    pass

class ComputerResponse(ComputerBase):
    created_at: datetime.datetime
    model_config = ConfigDict(from_attributes=True)


# User Schemas
class UserBase(BaseModel):
    id: str
    username: str
    role: str = "user"
    department: str = "IT"
    is_privileged: bool = False

class UserCreate(UserBase):
    pass

class UserResponse(UserBase):
    created_at: datetime.datetime
    model_config = ConfigDict(from_attributes=True)


# Security Event Schemas
class SecurityEventCreate(BaseModel):
    event_id: Optional[str] = None
    timestamp: datetime.datetime
    computer_id: str
    hostname: str
    user_id: str
    source_ip: str
    destination_ip: str
    event_type: str
    action: str
    status: str = "SUCCESS"
    severity: str = "LOW"
    session_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    raw_data: Optional[str] = None
    is_simulated: bool = False
    simulation_run_id: Optional[str] = None

class SecurityEventResponse(BaseModel):
    id: int
    event_id: str
    timestamp: datetime.datetime
    computer_id: str
    hostname: str
    user_id: str
    source_ip: str
    destination_ip: str
    event_type: str
    action: str
    status: str
    severity: str
    session_id: Optional[str] = None
    metadata_json: Optional[str] = None
    is_simulated: bool = False
    simulation_run_id: Optional[str] = None
    ingestion_timestamp: datetime.datetime
    model_config = ConfigDict(from_attributes=True)


# Temporal Relationship Schemas
class TemporalRelationshipResponse(BaseModel):
    id: int
    source_event_id: str
    target_event_id: str
    relation_type: str
    delta_seconds: float
    confidence: float
    evidence_text: str
    created_at: datetime.datetime
    model_config = ConfigDict(from_attributes=True)


# Detection Rule Schemas
class DetectionRuleBase(BaseModel):
    name: str
    description: str
    scenario: str
    severity: str = "HIGH"
    default_risk_score: float = 75.0
    time_window_minutes: int = 30
    is_enabled: bool = True
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)

class DetectionRuleCreate(DetectionRuleBase):
    id: str

class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    default_risk_score: Optional[float] = None
    time_window_minutes: Optional[int] = None
    is_enabled: Optional[bool] = None
    parameters: Optional[Dict[str, Any]] = None

class DetectionRuleResponse(DetectionRuleBase):
    id: str
    parameters_json: str
    model_config = ConfigDict(from_attributes=True)


# Alert Evidence Schemas
class AlertEvidenceResponse(BaseModel):
    id: int
    alert_id: str
    event_id: str
    sequence_order: int
    stage_name: str
    role_in_attack: str
    event: Optional[SecurityEventResponse] = None
    model_config = ConfigDict(from_attributes=True)


# Attack Alert Schemas
class AttackAlertResponse(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    title: str
    severity: str
    risk_score: float
    affected_computers: str  # JSON list
    related_users: str      # JSON list
    start_time: datetime.datetime
    end_time: datetime.datetime
    status: str
    explanation: str
    temporal_constraints: str
    detection_timestamp: datetime.datetime
    evidence: Optional[List[AlertEvidenceResponse]] = None
    model_config = ConfigDict(from_attributes=True)

class AlertStatusUpdate(BaseModel):
    status: str


# Investigation Schemas
class InvestigationReportResponse(BaseModel):
    id: str
    alert_id: str
    summary: str
    technical_analysis: str
    temporal_analysis: str
    recommended_actions: str  # JSON list
    generated_by: str
    created_at: datetime.datetime
    model_config = ConfigDict(from_attributes=True)

class InvestigationRequest(BaseModel):
    alert_id: str
    use_ai: bool = False


# Simulation Schemas
class SimulationScenarioRequest(BaseModel):
    scenario_type: str  # normal, brute_force, lateral_movement, data_exfiltration, privilege_escalation, multi_stage
    speed: Optional[float] = 1.0
    event_count: Optional[int] = 20
    seed: Optional[int] = None

class SimulationRunResponse(BaseModel):
    id: str
    scenario_name: str
    status: str
    events_generated: int
    started_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None
    seed: Optional[int] = None
    model_config = ConfigDict(from_attributes=True)


# Dashboard Schemas
class DashboardSummary(BaseModel):
    total_computers: int
    total_events: int
    active_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    risk_distribution: Dict[str, int]
    system_health: str


# Network Graph Schemas
class NetworkNode(BaseModel):
    id: str
    label: str
    ip: str
    role: str
    status: str
    alert_count: int

class NetworkEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str  # observed, inferred, attack_path
    label: str
    is_suspicious: bool
    event_count: int
    events: List[str]

class NetworkGraphResponse(BaseModel):
    nodes: List[NetworkNode]
    edges: List[NetworkEdge]
