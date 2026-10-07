from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, Text
from datetime import datetime
from backend.database import Base

class Entity(Base):
    __tablename__ = "entities"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    entity_type = Column(String(50), index=True) # ip, host, user, process, file_hash, domain
    entity_value = Column(String(255), unique=True, index=True)
    
    # Asset Context
    criticality = Column(Float, default=0.5) # 0.1 to 1.0 (Tier 0 = 1.0, Tier 1 = 0.8, Tier 2 = 0.5, Tier 3 = 0.2)
    asset_tier = Column(String(50), default="Tier 2 - Workstation") # Tier 0 - Domain Controller / Tier 1 - Prod Server / etc.
    department = Column(String(100), default="General")
    owner = Column(String(100), default="Unassigned")
    
    # Threat & State
    is_compromised = Column(Integer, default=0) # 1 if active in critical incident
    is_isolated = Column(Integer, default=0)    # 1 if host isolated / account locked
    tags = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
