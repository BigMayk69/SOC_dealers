from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.database import Base

class AgentInvestigationRun(Base):
    __tablename__ = "agent_investigation_runs"

    id = Column(String(64), primary_key=True, index=True) # RUN-20261001-XXXX
    incident_id = Column(String(64), ForeignKey("incidents.id"), index=True)
    
    # Audit trail of investigation
    tools_called = Column(JSON, default=list)        # ["get_incident", "get_related_alerts", ...]
    evidence_retrieved = Column(JSON, default=dict)  # Snapshots of raw evidence gathered
    structured_result = Column(JSON, default=dict)   # Full structured JSON analysis output
    
    # Evaluation & Autonomy decision
    confidence_score = Column(Float, default=0.90)
    autonomy_tier = Column(String(30), default="REVIEW_NEEDED", index=True) # AUTO_RESOLVE, REVIEW_NEEDED, HUMAN_REQUIRED
    policy_reason = Column(Text, nullable=True)
    model_used = Column(String(100), default="Ollama/Llama-3")
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    feedbacks = relationship("AnalystFeedback", back_populates="run", cascade="all, delete-orphan")


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), ForeignKey("agent_investigation_runs.id"), nullable=True, index=True)
    incident_id = Column(String(64), index=True)
    
    # Human Feedback
    is_correct = Column(Boolean, default=True)               # True = Correct, False = Wrong
    analyst_verdict = Column(String(50), default="True Positive") # True Positive, False Positive, Misclassified, Under-scoped
    notes = Column(Text, nullable=True)
    submitted_by = Column(String(100), default="SOC Lead Analyst")
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    run = relationship("AgentInvestigationRun", back_populates="feedbacks")
