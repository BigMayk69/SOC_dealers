from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime

class RecommendedAction(BaseModel):
    action_type: str = Field(..., description="isolate_host | revoke_token | block_ip | kill_process | resolve_benign | monitor")
    target: str = Field(..., description="Entity identifier e.g. WORKSTATION-01, alice.smith, 185.220.101.5")
    priority: str = Field(default="P1 - Immediate", description="P1 - Immediate | P2 - High | P3 - Medium")
    label: str = Field(..., description="Short button/action label")
    description: str = Field(..., description="Explanation of the mitigation action")
    command: Optional[str] = Field(default=None, description="Optional CLI / PowerShell command to execute")
    rationale: Optional[str] = Field(default=None, description="Why this containment step is recommended")

class StructuredInvestigationResult(BaseModel):
    executive_summary: str = Field(..., description="High-level plain English summary for leadership and analysts")
    what_happened: str = Field(..., description="Clear explanation of the activity sequence")
    attack_progression: List[str] = Field(default_factory=list, description="Chronological kill-chain stages observed")
    root_cause: str = Field(..., description="Patient zero entry vector and primary compromise cause")
    supporting_evidence: List[str] = Field(default_factory=list, description="Concrete evidence lines (hashes, commands, IPs)")
    mitre_reasoning: Dict[str, str] = Field(default_factory=dict, description="Techniques identified and contextual reasoning")
    affected_assets: List[Dict[str, Any]] = Field(default_factory=list, description="Impacted hosts, users, IPs with criticality")
    recommended_actions: List[RecommendedAction] = Field(default_factory=list, description="Prioritized mitigation playbooks")
    confidence_score: float = Field(default=0.95, description="0.0 to 1.0 confidence in analysis")
    uncertainties_and_gaps: List[str] = Field(default_factory=list, description="What the AI cannot confirm or still doesn't know")
    detection_rule_yaml: Optional[str] = Field(default=None, description="Ready-to-deploy Sigma detection rule for SOC SIEM/EDR")
    decision_memory_context: Optional[str] = Field(default=None, description="Historical analyst feedback alignment notes")


class AgentInvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    run_id: str
    incident_id: str
    autonomy_tier: str # AUTO_RESOLVE | REVIEW_NEEDED | HUMAN_REQUIRED
    policy_reason: str
    model_used: str
    tools_called: List[str]
    analysis: StructuredInvestigationResult
    evidence_summary: Dict[str, Any]
    created_at: datetime

class AnalystFeedbackCreate(BaseModel):
    run_id: Optional[str] = None
    incident_id: str
    is_correct: bool = True
    analyst_verdict: Optional[str] = "True Positive" # True Positive | False Positive | Misclassified | Under-scoped
    notes: Optional[str] = None
    submitted_by: Optional[str] = "SOC Lead Analyst"

class AnalystFeedbackResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    run_id: Optional[str] = None
    incident_id: str
    is_correct: bool
    analyst_verdict: Optional[str] = None
    notes: Optional[str] = None
    submitted_by: str
    created_at: datetime
