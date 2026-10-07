from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class AITriageRequest(BaseModel):
    model: Optional[str] = "llama3"
    custom_prompt: Optional[str] = None
    force_refresh: bool = False

class AITriageResponse(BaseModel):
    incident_id: str
    summary: str
    root_cause: str
    attack_narrative: str
    confidence_score: float
    model_used: str
    containment_steps: List[Dict[str, Any]]
    mitre_stage_analysis: Dict[str, Any]

class ChatMessage(BaseModel):
    role: str # user, assistant, system
    content: str

class AICopilotChatRequest(BaseModel):
    incident_id: Optional[str] = None
    messages: List[ChatMessage]
    model: Optional[str] = "llama3"

class AICopilotChatResponse(BaseModel):
    reply: str
    recommended_actions: Optional[List[Dict[str, Any]]] = None
    suggested_queries: Optional[List[str]] = None

class SOCStatsResponse(BaseModel):
    total_raw_alerts: int
    total_incidents: int
    reduction_percentage: float
    average_mttt_seconds: int
    alerts_per_source: Dict[str, int]
    severity_distribution: Dict[str, int]
    incidents_by_status: Dict[str, int]
    incidents_by_priority: Dict[str, int]
    top_mitre_tactics: List[Dict[str, Any]]
    top_targeted_hosts: List[Dict[str, Any]]
    top_targeted_users: List[Dict[str, Any]]
    system_health: Dict[str, Any]
