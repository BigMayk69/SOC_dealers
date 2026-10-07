"""
REST API Router for Autonomous AI SOC Agent.
Provides endpoints for triggering investigations, auditing decision trails, and collecting analyst feedback.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from datetime import datetime, timezone

from backend.database import get_db
from backend.models import AgentInvestigationRun, AnalystFeedback, Incident
from backend.schemas.agent import (
    AgentInvestigationResponse,
    AnalystFeedbackCreate,
    AnalystFeedbackResponse,
    StructuredInvestigationResult
)
from backend.agent.orchestrator import SOCAgentOrchestrator

router = APIRouter(prefix="/agent", tags=["Autonomous AI SOC Agent"])

@router.post("/investigate/{incident_id}", response_model=AgentInvestigationResponse)
async def investigate_incident(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """
    Triggers autonomous AI SOC Agent investigation for a specific incident:
    - Reads multi-source evidence via read-only tools
    - Generates deep structured forensic analysis
    - Evaluates deterministic autonomy policy (AUTO_RESOLVE / REVIEW_NEEDED / HUMAN_REQUIRED)
    - Records immutable audit trail in DB
    """
    orchestrator = SOCAgentOrchestrator(db)
    try:
        response = await orchestrator.investigate_incident(incident_id)
        return response
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent investigation error: {str(e)}")

@router.get("/runs/{incident_id}", response_model=List[AgentInvestigationResponse])
def get_incident_investigation_runs(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """Fetch all historical investigation audit runs for a specific incident."""
    runs = db.query(AgentInvestigationRun).filter(
        AgentInvestigationRun.incident_id == incident_id
    ).order_by(desc(AgentInvestigationRun.created_at)).all()

    return [
        AgentInvestigationResponse(
            run_id=r.id,
            incident_id=r.incident_id,
            autonomy_tier=r.autonomy_tier,
            policy_reason=r.policy_reason or "",
            model_used=r.model_used or "",
            tools_called=r.tools_called or [],
            analysis=StructuredInvestigationResult(**r.structured_result),
            evidence_summary=r.evidence_retrieved or {},
            created_at=r.created_at
        )
        for r in runs
    ]

@router.get("/runs", response_model=List[AgentInvestigationResponse])
def list_all_investigation_runs(
    limit: int = 50,
    skip: int = 0,
    db: Session = Depends(get_db)
):
    """List recent agent investigation runs across all incidents."""
    runs = db.query(AgentInvestigationRun).order_by(
        desc(AgentInvestigationRun.created_at)
    ).offset(skip).limit(limit).all()

    return [
        AgentInvestigationResponse(
            run_id=r.id,
            incident_id=r.incident_id,
            autonomy_tier=r.autonomy_tier,
            policy_reason=r.policy_reason or "",
            model_used=r.model_used or "",
            tools_called=r.tools_called or [],
            analysis=StructuredInvestigationResult(**r.structured_result),
            evidence_summary=r.evidence_retrieved or {},
            created_at=r.created_at
        )
        for r in runs
    ]

@router.post("/feedback", response_model=AnalystFeedbackResponse)
def submit_analyst_feedback(
    feedback_in: AnalystFeedbackCreate,
    db: Session = Depends(get_db)
):
    """
    Records human analyst validation (Correct [✓] / Wrong [✗] + notes).
    Builds the decision memory dataset for continuous SOC policy refinement.
    """
    fb_record = AnalystFeedback(
        run_id=feedback_in.run_id,
        incident_id=feedback_in.incident_id,
        is_correct=feedback_in.is_correct,
        analyst_verdict=feedback_in.analyst_verdict,
        notes=feedback_in.notes,
        submitted_by=feedback_in.submitted_by or "SOC Lead Analyst",
        created_at=datetime.now(timezone.utc)
    )
    db.add(fb_record)
    db.commit()
    db.refresh(fb_record)
    return fb_record

@router.get("/feedback", response_model=List[AnalystFeedbackResponse])
def list_analyst_feedback(
    incident_id: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Fetch stored analyst feedback records for audit and dataset building."""
    query = db.query(AnalystFeedback)
    if incident_id:
        query = query.filter(AnalystFeedback.incident_id == incident_id)
    return query.order_by(desc(AnalystFeedback.created_at)).limit(limit).all()
