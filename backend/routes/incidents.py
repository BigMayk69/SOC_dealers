from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional, Dict, Any
from datetime import datetime
from backend.database import get_db
from backend.models.incident import Incident
from backend.models.alert import Alert
from backend.models.containment import ContainmentAction
from backend.models.entity import Entity
from backend.schemas.incident import IncidentResponse, IncidentUpdate, ContainmentActionSchema
from backend.schemas.triage import AITriageRequest, AITriageResponse
from backend.engine.llm_triage import llm_engine
from backend.engine.risk_scorer import RiskScorer
from backend.engine.mitre import MitreMapper

router = APIRouter(prefix="/incidents", tags=["Incident Triage & Investigation"])

@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    min_risk: Optional[float] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if priority:
        query = query.filter(Incident.priority == priority)
    if min_risk is not None:
        query = query.filter(Incident.risk_score >= min_risk)
    if search:
        query = query.filter(
            Incident.title.ilike(f"%{search}%") |
            Incident.id.ilike(f"%{search}%")
        )
    return query.order_by(desc(Incident.risk_score), desc(Incident.created_at)).offset(skip).limit(limit).all()

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident

@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(incident_id: str, update_in: IncidentUpdate, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    
    if update_in.status:
        incident.status = update_in.status
    if update_in.priority:
        incident.priority = update_in.priority
    if update_in.assigned_analyst:
        incident.assigned_analyst = update_in.assigned_analyst
        
    incident.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(incident)
    return incident

@router.post("/{incident_id}/triage-ai", response_model=AITriageResponse)
async def generate_ai_triage(incident_id: str, request: AITriageRequest = None, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    alerts = db.query(Alert).filter(Alert.incident_id == incident_id).order_by(Alert.timestamp).all()
    alerts_data = [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else "",
            "rule_name": a.rule_name,
            "severity": a.severity,
            "src_host": a.src_host,
            "dest_host": a.dest_host,
            "username": a.username,
            "mitre_tactic": a.mitre_tactic,
            "mitre_technique_id": a.mitre_technique_id,
            "command_line": a.command_line,
            "process_name": a.process_name
        } for a in alerts
    ]

    incident_dict = {
        "id": incident.id,
        "title": incident.title,
        "risk_score": incident.risk_score,
        "priority": incident.priority,
        "impacted_hosts": incident.impacted_hosts or [],
        "impacted_users": incident.impacted_users or [],
        "impacted_ips": incident.impacted_ips or [],
        "mitre_tactics": incident.mitre_tactics or []
    }

    # Invoke LLM Triage Engine
    briefing = await llm_engine.generate_incident_briefing(incident_dict, alerts_data)

    # Persist AI outputs to incident
    incident.summary_ai = briefing["summary"]
    incident.root_cause_ai = briefing["root_cause"]
    incident.attack_narrative_ai = briefing["attack_narrative"]
    incident.ai_confidence_score = briefing["confidence_score"]
    incident.ai_model_used = briefing["model_used"]
    incident.containment_recommendations = briefing["containment_steps"]
    incident.updated_at = datetime.utcnow()
    
    db.commit()

    return {
        "incident_id": incident.id,
        "summary": briefing["summary"],
        "root_cause": briefing["root_cause"],
        "attack_narrative": briefing["attack_narrative"],
        "confidence_score": briefing["confidence_score"],
        "model_used": briefing["model_used"],
        "containment_steps": briefing["containment_steps"],
        "mitre_stage_analysis": briefing.get("mitre_stage_analysis", {})
    }

@router.post("/{incident_id}/contain", response_model=ContainmentActionSchema)
def execute_containment_action(
    incident_id: str,
    action_in: ContainmentActionSchema,
    db: Session = Depends(get_db)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    action_type = action_in.action_type
    target = action_in.target

    # Simulate execution on underlying asset
    details = f"Successfully executed [{action_type}] on target '{target}'. SOC isolation token applied."
    
    # If host isolation, mark entity as isolated
    if action_type == "isolate_host":
        entity = db.query(Entity).filter(Entity.entity_value == target).first()
        if entity:
            entity.is_isolated = 1
            entity.is_compromised = 1

    action_record = ContainmentAction(
        incident_id=incident.id,
        action_type=action_type,
        target=target,
        status="Executed",
        execution_details=details,
        executed_by=action_in.executed_by or "Dealers AI SOC Lead",
        executed_at=datetime.utcnow(),
        payload={"command_executed": action_in.payload.get("command") if action_in.payload else "Default EDR Action"}
    )
    
    db.add(action_record)
    
    # Automatically move status to Triaging / Contained if P1 action
    if incident.status in ["New", "Triaging"]:
        incident.status = "Contained"
    
    db.commit()
    db.refresh(action_record)
    return action_record
