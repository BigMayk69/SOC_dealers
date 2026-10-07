from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime

class AlertBase(BaseModel):
    source: str = Field(..., description="e.g. CrowdStrike, Suricata, AWS_CloudTrail, Okta, Sysmon")
    rule_name: str
    event_type: str
    severity: str = "Medium" # Critical, High, Medium, Low, Informational
    severity_score: Optional[float] = 50.0
    confidence: Optional[float] = 0.85
    
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    src_host: Optional[str] = None
    dest_host: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None

    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None

    asset_criticality: Optional[float] = 0.5
    raw_payload: Optional[Dict[str, Any]] = None
    description: Optional[str] = None

class AlertCreate(AlertBase):
    id: Optional[str] = None
    timestamp: Optional[datetime] = None

class AlertResponse(AlertBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    incident_id: Optional[str] = None

class BatchAlertIngest(BaseModel):
    alerts: List[AlertCreate]
    auto_correlate: bool = True
