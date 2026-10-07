from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from datetime import datetime, timezone
from backend.database import get_db
from backend.models.alert import Alert
from backend.models.incident import Incident
from backend.schemas.alert import AlertResponse, AlertCreate, BatchAlertIngest
from backend.engine.correlation import GraphCorrelationEngine
from backend.engine.risk_scorer import RiskScorer
from backend.engine.mitre import MitreMapper

router = APIRouter(prefix="/alerts", tags=["Alerts Ingestion & Query"])
correlation_engine = GraphCorrelationEngine(time_window_minutes=60)

@router.get("", response_model=List[AlertResponse])
def list_alerts(
    skip: int = 0,
    limit: int = 100,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    incident_id: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Alert)
    if source:
        query = query.filter(Alert.source == source)
    if severity:
        query = query.filter(Alert.severity == severity)
    if incident_id:
        query = query.filter(Alert.incident_id == incident_id)
    if search:
        query = query.filter(
            Alert.rule_name.ilike(f"%{search}%") |
            Alert.src_host.ilike(f"%{search}%") |
            Alert.username.ilike(f"%{search}%")
        )
    return query.order_by(desc(Alert.timestamp)).offset(skip).limit(limit).all()

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_by_id(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert

@router.post("/ingest", response_model=AlertResponse)
def ingest_single_alert(alert_in: AlertCreate, db: Session = Depends(get_db)):
    # If tactic not provided, map automatically
    tactic = alert_in.mitre_tactic
    tech_id = alert_in.mitre_technique_id
    tech_name = alert_in.mitre_technique_name
    
    if not tactic or not tech_id:
        mapped = MitreMapper.map_alert_to_technique(alert_in.rule_name, alert_in.event_type, alert_in.command_line)
        tactic = tactic or mapped["tactic"]
        tech_id = tech_id or mapped["id"]
        tech_name = tech_name or mapped["name"]

    now_dt = datetime.now(timezone.utc)
    alert_id = alert_in.id or f"ALT-{now_dt.strftime('%Y%m%d%H%M%S')}-{db.query(Alert).count() + 1}"
    
    db_alert = Alert(
        id=alert_id,
        timestamp=alert_in.timestamp or now_dt,
        source=alert_in.source,
        rule_name=alert_in.rule_name,
        event_type=alert_in.event_type,
        severity=alert_in.severity,
        severity_score=alert_in.severity_score or 50.0,
        confidence=alert_in.confidence or 0.85,
        src_ip=alert_in.src_ip,
        dest_ip=alert_in.dest_ip,
        src_host=alert_in.src_host,
        dest_host=alert_in.dest_host,
        username=alert_in.username,
        process_name=alert_in.process_name,
        process_path=alert_in.process_path,
        command_line=alert_in.command_line,
        parent_process=alert_in.parent_process,
        file_hash=alert_in.file_hash,
        domain=alert_in.domain,
        port=alert_in.port,
        protocol=alert_in.protocol or "TCP",
        mitre_tactic=tactic,
        mitre_technique_id=tech_id,
        mitre_technique_name=tech_name,
        asset_criticality=alert_in.asset_criticality or 0.5,
        raw_payload=alert_in.raw_payload or {},
        description=alert_in.description
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert

@router.post("/batch-ingest")
def ingest_batch_alerts(batch_in: BatchAlertIngest, db: Session = Depends(get_db)):
    ingested_count = 0
    db_objs = []
    
    for alert_in in batch_in.alerts:
        tactic = alert_in.mitre_tactic
        tech_id = alert_in.mitre_technique_id
        tech_name = alert_in.mitre_technique_name
        
        if not tactic or not tech_id:
            mapped = MitreMapper.map_alert_to_technique(alert_in.rule_name, alert_in.event_type, alert_in.command_line)
            tactic = tactic or mapped["tactic"]
            tech_id = tech_id or mapped["id"]
            tech_name = tech_name or mapped["name"]

        now_dt = datetime.now(timezone.utc)
        alert_id = alert_in.id or f"ALT-{now_dt.strftime('%Y%m%d%H%M%S')}-{db.query(Alert).count() + ingested_count + 1}"
        
        db_objs.append(Alert(
            id=alert_id,
            timestamp=alert_in.timestamp or now_dt,
            source=alert_in.source,
            rule_name=alert_in.rule_name,
            event_type=alert_in.event_type,
            severity=alert_in.severity,
            severity_score=alert_in.severity_score or 50.0,
            confidence=alert_in.confidence or 0.85,
            src_ip=alert_in.src_ip,
            dest_ip=alert_in.dest_ip,
            src_host=alert_in.src_host,
            dest_host=alert_in.dest_host,
            username=alert_in.username,
            process_name=alert_in.process_name,
            process_path=alert_in.process_path,
            command_line=alert_in.command_line,
            parent_process=alert_in.parent_process,
            file_hash=alert_in.file_hash,
            domain=alert_in.domain,
            port=alert_in.port,
            protocol=alert_in.protocol or "TCP",
            mitre_tactic=tactic,
            mitre_technique_id=tech_id,
            mitre_technique_name=tech_name,
            asset_criticality=alert_in.asset_criticality or 0.5,
            raw_payload=alert_in.raw_payload or {},
            description=alert_in.description
        ))
        ingested_count += 1
        
    db.bulk_save_objects(db_objs)
    db.commit()
    
    return {
        "status": "success",
        "ingested_count": ingested_count,
        "message": f"Successfully ingested {ingested_count} alerts into database."
    }

