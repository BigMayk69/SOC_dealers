from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    # Core Identifiers
    id = Column(String(64), primary_key=True, index=True) # alert_id (UUID / String)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String(50), index=True) # EDR, Azure AD, Firewall, Proxy, IDS, DNS, Windows Security, Cloud Audit, M365
    alert_name = Column(String(255), index=True, nullable=True)
    rule_name = Column(String(255), index=True, nullable=True) # Alias for alert_name
    event_type = Column(String(100), index=True, nullable=True) # ProcessCreation, NetworkBeacon, etc.
    description = Column(Text, nullable=True)
    severity = Column(String(20), index=True) # Low, Medium, High, Critical
    severity_score = Column(Float, default=50.0) # 0 to 100
    confidence = Column(Float, default=0.85) # 0.0 to 1.0

    # User & Device Entities
    username = Column(String(100), index=True, nullable=True) # user
    user = Column(String(100), nullable=True) # user email
    src_host = Column(String(100), index=True, nullable=True) # device_hostname
    device_hostname = Column(String(100), nullable=True)
    dest_host = Column(String(100), index=True, nullable=True)

    # Network Entities
    src_ip = Column(String(45), index=True, nullable=True)
    dst_ip = Column(String(45), index=True, nullable=True)
    dest_ip = Column(String(45), nullable=True) # Alias
    dst_port = Column(Integer, nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), default="TCP")
    url_or_domain = Column(String(255), index=True, nullable=True)
    domain = Column(String(255), nullable=True)
    geo_country = Column(String(10), nullable=True)

    # Process & File Entities
    process_name = Column(String(255), nullable=True)
    process_path = Column(String(500), nullable=True)
    command_line = Column(Text, nullable=True)
    parent_process = Column(String(255), nullable=True)
    file_hash = Column(String(128), index=True, nullable=True)

    # Asset Inventory Enrichment
    asset_id = Column(String(64), index=True, nullable=True)
    asset_criticality = Column(Float, default=2.0) # 1 to 5 scale from dataset
    asset_type = Column(String(50), nullable=True) # workstation, domain controller, database, etc.

    # Threat Intelligence & MITRE ATT&CK
    mitre_tactic = Column(String(100), index=True, nullable=True)
    mitre_technique_id = Column(String(50), index=True, nullable=True)
    mitre_technique_name = Column(String(255), nullable=True)
    threat_intel_match = Column(Boolean, default=False)
    anomaly_score = Column(Float, default=0.0)

    # Deduplication
    is_duplicate_of = Column(String(64), index=True, nullable=True)

    # Incident Cluster Association
    incident_id = Column(String(64), ForeignKey("incidents.id"), nullable=True, index=True)
    raw_payload = Column(JSON, default=dict)

    # Relationships
    incident = relationship("Incident", back_populates="alerts")
