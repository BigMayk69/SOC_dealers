from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from backend.schemas.alert import AlertResponse

class ContainmentActionSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    incident_id: str
    action_type: str
    target: str
    status: str = "Pending"
    execution_details: Optional[str] = None
    executed_by: Optional[str] = "Dealers AI SOC Lead"
    executed_at: Optional[datetime] = None
    payload: Optional[Dict[str, Any]] = None

class IncidentBase(BaseModel):
    title: str
    status: str = "New"
    priority: str = "P2 - High"
    risk_score: float = 50.0
    threat_severity_score: float = 50.0
    max_asset_criticality: float = 0.5
    blast_radius_score: float = 30.0
    alert_count: int = 1
    raw_alert_reduction_pct: float = 0.0
    assigned_analyst: str = "Dealers SOC Analyst"
    triage_time_seconds: int = 74
    
    summary_ai: Optional[str] = None
    root_cause_ai: Optional[str] = None
    attack_narrative_ai: Optional[str] = None
    ai_confidence_score: float = 0.92
    ai_model_used: str = "Ollama/Llama-3 (Azure)"
    
    mitre_tactics: List[str] = []
    mitre_techniques: List[Dict[str, Any]] = []
    impacted_hosts: List[str] = []
    impacted_users: List[str] = []
    impacted_ips: List[str] = []
    pivot_entities: List[str] = []
    containment_recommendations: List[Dict[str, Any]] = []

class IncidentResponse(IncidentBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    first_alert_time: datetime
    last_alert_time: datetime
    duration_minutes: float
    created_at: datetime
    updated_at: datetime
    alerts: Optional[List[AlertResponse]] = []
    containment_actions: Optional[List[ContainmentActionSchema]] = []
    graph_topology: Optional[Dict[str, Any]] = None

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_analyst: Optional[str] = None
    notes: Optional[str] = None
