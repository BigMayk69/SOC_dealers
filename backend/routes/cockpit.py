"""
Frontend Connection & Cockpit Aggregation API Router.
Provides optimized single-call dashboard payloads, Cytoscape/Vis.js graph topologies,
and Server-Sent Events (SSE) live streaming for the frontend UI.
"""
import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from backend.database import get_db
from backend.models import Incident, Alert, Entity, ContainmentAction, AgentInvestigationRun
from backend.engine.llm_triage import llm_engine

router = APIRouter(prefix="/cockpit", tags=["Frontend Cockpit & Real-Time Connection"])

@router.get("/summary")
async def get_cockpit_dashboard_summary(db: Session = Depends(get_db)):
    """
    Consolidated single-call payload for the Frontend 3-Pane Command Center:
    - Top Hero KPIs (Total Alerts, Incident Count, Volume Reduction %, Average MTTT)
    - Prioritized Incident Queue (sorted by composite risk score)
    - Active Containment Queue & Execution Status
    - Telemetry Source Distributions & Top Targeted Assets
    - AI Engine & Backend Connection Health Status
    """
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    total_incidents = db.query(func.count(Incident.id)).scalar() or 0
    
    reduction_pct = 0.0
    if total_alerts > 0:
        reduction_pct = round((1.0 - (total_incidents / float(total_alerts))) * 100.0, 1)

    avg_mttt = db.query(func.avg(Incident.triage_time_seconds)).scalar()
    avg_mttt_val = int(avg_mttt) if avg_mttt else 74

    # Incidents List for Left Pane (Top 30 prioritized)
    incidents = db.query(Incident).order_by(
        desc(Incident.risk_score),
        desc(Incident.created_at)
    ).limit(30).all()

    incidents_payload = [
        {
            "id": inc.id,
            "title": inc.title,
            "status": inc.status,
            "priority": inc.priority,
            "risk_score": inc.risk_score,
            "alert_count": inc.alert_count,
            "reduction_pct": inc.raw_alert_reduction_pct,
            "impacted_hosts": inc.impacted_hosts or [],
            "impacted_users": inc.impacted_users or [],
            "impacted_ips": inc.impacted_ips or [],
            "mitre_tactics": inc.mitre_tactics or [],
            "triage_time_seconds": inc.triage_time_seconds,
            "first_alert_time": str(inc.first_alert_time),
            "last_alert_time": str(inc.last_alert_time)
        }
        for inc in incidents
    ]

    # Recent Containment Actions for Right Pane
    actions = db.query(ContainmentAction).order_by(
        desc(ContainmentAction.executed_at)
    ).limit(10).all()

    actions_payload = [
        {
            "id": a.id,
            "incident_id": a.incident_id,
            "action_type": a.action_type,
            "target": a.target,
            "status": a.status,
            "executed_by": a.executed_by,
            "executed_at": str(a.executed_at),
            "details": a.execution_details
        }
        for a in actions
    ]

    # Telemetry distributions
    source_counts = db.query(Alert.source, func.count(Alert.id)).group_by(Alert.source).all()
    sev_counts = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    
    # Check Ollama AI status
    is_ollama_active = await llm_engine.check_ollama_available()

    return {
        "kpis": {
            "total_raw_alerts": total_alerts,
            "consolidated_incidents": total_incidents,
            "volume_reduction_pct": reduction_pct,
            "average_mttt_seconds": avg_mttt_val,
            "mttt_target_seconds": 180,
            "target_sla_met": avg_mttt_val <= 180,
            "critical_p1_count": db.query(func.count(Incident.id)).filter(Incident.priority == "P1 - Critical").scalar() or 0
        },
        "incidents_queue": incidents_payload,
        "recent_containment_actions": actions_payload,
        "telemetry_breakdown": {
            "by_source": {s: c for s, c in source_counts if s},
            "by_severity": {sev: c for sev, c in sev_counts if sev}
        },
        "connection_health": {
            "backend_status": "online",
            "database_connected": True,
            "ai_engine": "Ollama / Azure Live" if is_ollama_active else "Embedded CyberAI Fallback",
            "api_version": "2.0.0",
            "server_time": datetime.now(timezone.utc).isoformat()
        }
    }

@router.get("/graph/{incident_id}")
def get_incident_graph_for_frontend(incident_id: str, db: Session = Depends(get_db)):
    """
    Returns graph topology formatted with layout metadata, colors, and node icons
    compatible with Vis-Network, Cytoscape.js, or React Flow.
    """
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    topology = inc.graph_topology or {"nodes": [], "edges": []}
    return {
        "incident_id": inc.id,
        "title": inc.title,
        "risk_score": inc.risk_score,
        "priority": inc.priority,
        "graph": topology,
        "stats": {
            "total_nodes": len(topology.get("nodes", [])),
            "total_edges": len(topology.get("edges", []))
        }
    }

@router.get("/stream")
async def stream_live_soc_telemetry(request: Request, db: Session = Depends(get_db)):
    """
    Server-Sent Events (SSE) stream endpoint for live real-time frontend updates.
    Pushes telemetry updates, agent milestones, and containment statuses every 3 seconds.
    """
    async def event_generator():
        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                break

            total_alerts = db.query(func.count(Alert.id)).scalar() or 0
            total_incidents = db.query(func.count(Incident.id)).scalar() or 0
            latest_run = db.query(AgentInvestigationRun).order_by(desc(AgentInvestigationRun.created_at)).first()

            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "SOC_HEARTBEAT",
                "metrics": {
                    "total_alerts": total_alerts,
                    "total_incidents": total_incidents,
                    "reduction_pct": round((1.0 - (total_incidents / max(1, total_alerts))) * 100.0, 1)
                },
                "latest_agent_run": {
                    "run_id": latest_run.id if latest_run else None,
                    "incident_id": latest_run.incident_id if latest_run else None,
                    "autonomy_tier": latest_run.autonomy_tier if latest_run else None,
                    "confidence": latest_run.confidence_score if latest_run else None
                } if latest_run else None
            }

            yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(3)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
