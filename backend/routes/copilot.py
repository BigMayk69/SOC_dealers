from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from backend.database import get_db
from backend.models.incident import Incident
from backend.schemas.triage import AICopilotChatRequest, AICopilotChatResponse
from backend.engine.llm_triage import llm_engine

router = APIRouter(prefix="/copilot", tags=["AI SOC Analyst Copilot"])

@router.post("/chat", response_model=AICopilotChatResponse)
async def chat_with_copilot(
    request: AICopilotChatRequest,
    db: Session = Depends(get_db)
):
    incident_data = None
    if request.incident_id:
        incident = db.query(Incident).filter(Incident.id == request.incident_id).first()
        if incident:
            incident_data = {
                "id": incident.id,
                "title": incident.title,
                "risk_score": incident.risk_score,
                "priority": incident.priority,
                "status": incident.status,
                "impacted_hosts": incident.impacted_hosts or [],
                "impacted_users": incident.impacted_users or [],
                "impacted_ips": incident.impacted_ips or [],
                "mitre_tactics": incident.mitre_tactics or [],
                "triage_time_seconds": incident.triage_time_seconds,
                "alert_count": incident.alert_count
            }

    messages_payload = [{"role": m.role, "content": m.content} for m in request.messages]
    
    result = await llm_engine.chat_copilot(incident_data, messages_payload)
    return result
