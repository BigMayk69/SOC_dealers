from sqlalchemy import Column, String, Integer, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.database import Base

class ContainmentAction(Base):
    __tablename__ = "containment_actions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(64), ForeignKey("incidents.id"), index=True)
    action_type = Column(String(50)) # isolate_host, revoke_token, block_ip, kill_process, sinkhole_dns
    target = Column(String(255))     # e.g. "WORKSTATION-04", "alice.smith", "198.51.100.23"
    status = Column(String(50), default="Pending") # Pending, Executed, Failed, Reverted
    execution_details = Column(Text, nullable=True)
    executed_by = Column(String(100), default="Dealers AI Auto-Remediator")
    executed_at = Column(DateTime, default=datetime.utcnow)
    payload = Column(JSON, default=dict)

    # Relationship
    incident = relationship("Incident", back_populates="containment_actions")
