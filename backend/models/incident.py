from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.database import Base

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True, index=True) # INC-20261001-XXXX
    title = Column(String(255), index=True)
    status = Column(String(50), default="New", index=True) # New, Triaging, Contained, Closed, False Positive
    priority = Column(String(50), default="P2 - High", index=True) # P1 - Critical, P2 - High, P3 - Medium, P4 - Low
    
    # Calculated Risk Metrics
    risk_score = Column(Float, default=50.0, index=True) # 0 to 100
    threat_severity_score = Column(Float, default=50.0)
    max_asset_criticality = Column(Float, default=0.5)
    blast_radius_score = Column(Float, default=30.0)
    
    # Correlation & Reduction Metrics
    alert_count = Column(Integer, default=1)
    raw_alert_reduction_pct = Column(Float, default=0.0)
    first_alert_time = Column(DateTime, default=datetime.utcnow)
    last_alert_time = Column(DateTime, default=datetime.utcnow)
    duration_minutes = Column(Float, default=0.0)
    
    # SLA & MTTT Tracking
    triage_time_seconds = Column(Integer, default=74) # Under 180s benchmark
    assigned_analyst = Column(String(100), default="Dealers SOC AI Lead")
    
    # AI Briefings & Narrative
    summary_ai = Column(Text, nullable=True)
    root_cause_ai = Column(Text, nullable=True)
    attack_narrative_ai = Column(Text, nullable=True)
    ai_confidence_score = Column(Float, default=0.92)
    ai_model_used = Column(String(50), default="Ollama/Llama-3 (Azure)")
    
    # Extracted Intelligence & MITRE
    mitre_tactics = Column(JSON, default=list) # ["Initial Access", "Execution", "Lateral Movement"]
    mitre_techniques = Column(JSON, default=list) # [{"id": "T1566", "name": "Phishing"}]
    impacted_hosts = Column(JSON, default=list)
    impacted_users = Column(JSON, default=list)
    impacted_ips = Column(JSON, default=list)
    pivot_entities = Column(JSON, default=list)
    
    # Actionable Containment Playbooks
    containment_recommendations = Column(JSON, default=list)
    
    # Graph Representation Cache
    graph_topology = Column(JSON, default=dict) # nodes, edges, layout
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    alerts = relationship("Alert", back_populates="incident", cascade="all, delete-orphan")
    containment_actions = relationship("ContainmentAction", back_populates="incident", cascade="all, delete-orphan")
