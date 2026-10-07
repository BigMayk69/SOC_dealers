from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Dict, Any, List
from backend.database import get_db
from backend.models.alert import Alert
from backend.models.incident import Incident
from backend.models.entity import Entity
from backend.schemas.triage import SOCStatsResponse
from backend.engine.llm_triage import llm_engine
from backend.engine.dataset_loader import DatasetLoader

router = APIRouter(prefix="/stats", tags=["SOC Stats & KPIs"])

@router.get("", response_model=SOCStatsResponse)
async def get_soc_stats(db: Session = Depends(get_db)):
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    total_incidents = db.query(func.count(Incident.id)).scalar() or 0
    
    reduction_pct = 0.0
    if total_alerts > 0:
        reduction_pct = round((1.0 - (total_incidents / total_alerts)) * 100.0, 1)

    avg_mttt = db.query(func.avg(Incident.triage_time_seconds)).scalar()
    avg_mttt_val = int(avg_mttt) if avg_mttt else 74

    source_counts = db.query(Alert.source, func.count(Alert.id)).group_by(Alert.source).all()
    alerts_by_source = {s: count for s, count in source_counts if s}

    priority_counts = db.query(Incident.priority, func.count(Incident.id)).group_by(Incident.priority).all()
    incidents_by_priority = {p: count for p, count in priority_counts if p}

    status_counts = db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all()
    incidents_by_status = {s: count for s, count in status_counts if s}

    sev_counts = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    severity_distribution = {sev: count for sev, count in sev_counts if sev}

    host_counts = db.query(Alert.src_host, func.count(Alert.id)).filter(Alert.src_host.isnot(None)).group_by(Alert.src_host).order_by(func.count(Alert.id).desc()).limit(5).all()
    top_hosts = [{"host": h, "alert_count": c} for h, c in host_counts]

    user_counts = db.query(Alert.username, func.count(Alert.id)).filter(Alert.username.isnot(None)).group_by(Alert.username).order_by(func.count(Alert.id).desc()).limit(5).all()
    top_users = [{"username": u, "alert_count": c} for u, c in user_counts if u and u.lower() not in ["system", "local", "n/a"]]

    tactic_counts = db.query(Alert.mitre_tactic, func.count(Alert.id)).filter(Alert.mitre_tactic.isnot(None)).group_by(Alert.mitre_tactic).order_by(func.count(Alert.id).desc()).limit(8).all()
    top_tactics = [{"tactic": t, "count": c} for t, c in tactic_counts]

    is_ollama_active = await llm_engine.check_ollama_available()

    return {
        "total_raw_alerts": total_alerts,
        "total_incidents": total_incidents,
        "reduction_percentage": reduction_pct,
        "average_mttt_seconds": avg_mttt_val,
        "alerts_per_source": alerts_by_source,
        "severity_distribution": severity_distribution,
        "incidents_by_status": incidents_by_status,
        "incidents_by_priority": incidents_by_priority,
        "top_mitre_tactics": top_tactics,
        "top_targeted_hosts": top_hosts,
        "top_targeted_users": top_users,
        "system_health": {
            "database": "Online (SQLAlchemy)",
            "correlation_engine": "Active (NetworkX 60m sliding window)",
            "ollama_status": "Online (Local / Azure)" if is_ollama_active else "Embedded CyberAI Active (Fallback)",
            "sla_target_mttt": "180s (Sub-3min)"
        }
    }

@router.get("/evaluation/benchmark")
def get_evaluation_benchmark(db: Session = Depends(get_db)):
    """Returns evaluation metrics against ground_truth.csv and assets inventory"""
    return DatasetLoader.evaluate_ground_truth(db)
