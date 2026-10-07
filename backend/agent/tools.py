"""
Safe Read-Only Investigation Tools for the AI SOC Agent.
Provides clean query interfaces into the existing database and telemetry store.
"""
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_
from backend.models import Incident, Alert, Entity, ContainmentAction
from backend.engine.mitre import MitreMapper

class InvestigationToolRegistry:
    def __init__(self, db: Session):
        self.db = db

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Fetch primary metadata, scores, and entity lists for an incident."""
        inc = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not inc:
            return None
        return {
            "id": inc.id,
            "title": inc.title,
            "status": inc.status,
            "priority": inc.priority,
            "risk_score": inc.risk_score,
            "threat_severity_score": inc.threat_severity_score,
            "max_asset_criticality": inc.max_asset_criticality,
            "blast_radius_score": inc.blast_radius_score,
            "alert_count": inc.alert_count,
            "raw_alert_reduction_pct": inc.raw_alert_reduction_pct,
            "first_alert_time": str(inc.first_alert_time),
            "last_alert_time": str(inc.last_alert_time),
            "duration_minutes": inc.duration_minutes,
            "impacted_hosts": inc.impacted_hosts or [],
            "impacted_users": inc.impacted_users or [],
            "impacted_ips": inc.impacted_ips or [],
            "mitre_tactics": inc.mitre_tactics or [],
            "mitre_techniques": inc.mitre_techniques or [],
            "pivot_entities": inc.pivot_entities or [],
            "assigned_analyst": inc.assigned_analyst,
            "created_at": str(inc.created_at)
        }

    def get_related_alerts(self, incident_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch chronologically ordered constituent alerts for the incident."""
        alerts = self.db.query(Alert).filter(
            Alert.incident_id == incident_id
        ).order_by(Alert.timestamp.asc()).limit(limit).all()

        return [
            {
                "id": a.id,
                "timestamp": str(a.timestamp),
                "source": a.source,
                "rule_name": a.rule_name,
                "event_type": a.event_type,
                "severity": a.severity,
                "severity_score": a.severity_score,
                "confidence": a.confidence,
                "src_host": a.src_host,
                "dest_host": a.dest_host,
                "username": a.username,
                "src_ip": a.src_ip,
                "dest_ip": a.dest_ip,
                "process_name": a.process_name,
                "command_line": a.command_line,
                "parent_process": a.parent_process,
                "file_hash": a.file_hash,
                "domain": a.domain,
                "port": a.port,
                "mitre_tactic": a.mitre_tactic,
                "mitre_technique_id": a.mitre_technique_id,
                "mitre_technique_name": a.mitre_technique_name,
                "asset_criticality": a.asset_criticality,
                "description": a.description
            }
            for a in alerts
        ]

    def get_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """Constructs a high-signal step-by-step chronological timeline of major attack steps."""
        alerts = self.get_related_alerts(incident_id, limit=200)
        timeline = []
        seen_signatures = set()

        for a in alerts:
            # Create a signature to deduplicate repetitive identical alerts in the timeline
            sig = f"{a.get('rule_name')}|{a.get('src_host')}|{a.get('dest_host')}|{a.get('mitre_tactic')}|{a.get('process_name')}|{a.get('command_line')}"
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)

            timeline.append({
                "timestamp": a.get("timestamp"),
                "rule_name": a.get("rule_name"),
                "tactic": a.get("mitre_tactic", "Execution"),
                "technique_id": a.get("mitre_technique_id"),
                "technique_name": a.get("mitre_technique_name"),
                "host": a.get("src_host"),
                "dest_host": a.get("dest_host"),
                "user": a.get("username"),
                "process": a.get("process_name"),
                "command": a.get("command_line"),
                "dest_ip": a.get("dest_ip")
            })

        return timeline


    def get_mitre_analysis(self, incident_id: str) -> Dict[str, Any]:
        """Calculates kill-chain progression, coverage percentage, and stage analysis."""
        inc = self.get_incident(incident_id)
        if not inc:
            return {}
        tactics = inc.get("mitre_tactics", [])
        return MitreMapper.analyze_kill_chain_progression(tactics)

    def get_asset_details(self, hostnames: List[str], usernames: List[str]) -> Dict[str, Any]:
        """Fetch asset inventory and identity context (criticality tiers, department, privileged status)."""
        hosts_info = []
        users_info = []

        if hostnames:
            entities = self.db.query(Entity).filter(
                Entity.entity_type == "host",
                Entity.entity_value.in_(hostnames)
            ).all()
            for e in entities:
                hosts_info.append({
                    "hostname": e.entity_value,
                    "criticality": e.criticality,
                    "tier": e.asset_tier,
                    "department": e.department,
                    "owner": e.owner,
                    "is_isolated": bool(e.is_isolated)
                })

        if usernames:
            entities = self.db.query(Entity).filter(
                Entity.entity_type == "user",
                Entity.entity_value.in_(usernames)
            ).all()
            for e in entities:
                users_info.append({
                    "username": e.entity_value,
                    "criticality": e.criticality,
                    "tier": e.asset_tier,
                    "department": e.department,
                    "role": e.owner
                })

        return {
            "hosts": hosts_info,
            "users": users_info,
            "max_host_criticality": max([h["criticality"] for h in hosts_info], default=0.5),
            "contains_tier_0": any("Tier 0" in str(h.get("tier", "")) or h.get("criticality", 0) >= 0.9 for h in hosts_info)
        }

    def search_related_incidents(self, hostnames: List[str], usernames: List[str], current_inc_id: str) -> List[Dict[str, Any]]:
        """Search historical / other incidents sharing any of the same hosts or identities."""
        related = []
        query = self.db.query(Incident).filter(Incident.id != current_inc_id)

        for inc in query.order_by(desc(Incident.risk_score)).limit(10).all():
            inc_hosts = set(inc.impacted_hosts or [])
            inc_users = set(inc.impacted_users or [])
            
            shared_hosts = list(inc_hosts.intersection(set(hostnames)))
            shared_users = list(inc_users.intersection(set(usernames)))

            if shared_hosts or shared_users:
                related.append({
                    "incident_id": inc.id,
                    "title": inc.title,
                    "status": inc.status,
                    "risk_score": inc.risk_score,
                    "shared_hosts": shared_hosts,
                    "shared_users": shared_users,
                    "first_seen": str(inc.first_alert_time)
                })

        return related

    def get_containment_history(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch previously executed containment actions and audit records."""
        actions = self.db.query(ContainmentAction).filter(
            ContainmentAction.incident_id == incident_id
        ).order_by(ContainmentAction.executed_at.desc()).all()

        return [
            {
                "id": a.id,
                "action_type": a.action_type,
                "target": a.target,
                "status": a.status,
                "executed_by": a.executed_by,
                "executed_at": str(a.executed_at),
                "details": a.execution_details
            }
            for a in actions
        ]

    def get_analyst_feedback_memory(self, hostnames: List[str], usernames: List[str]) -> Dict[str, Any]:
        """Queries historical human feedback decisions on incidents sharing similar assets."""
        from backend.models.agent_audit import AnalystFeedback
        feedbacks = self.db.query(AnalystFeedback).order_by(AnalystFeedback.created_at.desc()).limit(20).all()
        matched = []
        for fb in feedbacks:
            matched.append({
                "incident_id": fb.incident_id,
                "is_correct": fb.is_correct,
                "verdict": fb.analyst_verdict,
                "notes": fb.notes,
                "submitted_by": fb.submitted_by,
                "date": str(fb.created_at)
            })
        return {
            "host_feedback": matched,
            "user_feedback": matched,
            "recent": matched,
            "total_count": len(matched)
        }

    def get_process_tree(self, incident_id: str) -> Dict[str, Any]:
        """Extracts parent-to-child process execution lineages from EDR/Sysmon telemetry."""
        alerts = self.get_related_alerts(incident_id, limit=50)
        processes = []
        edges = []
        anomalies = []
        for a in alerts:
            pname = a.get("process_name")
            cmd = a.get("command_line")
            pparent = a.get("parent_process") or "explorer.exe"
            if pname or cmd:
                proc_entry = {
                    "parent_process": pparent,
                    "process_name": pname or "unknown.exe",
                    "command_line": cmd or "",
                    "host": a.get("src_host"),
                    "timestamp": a.get("timestamp")
                }
                processes.append(proc_entry)
                edges.append({"source": pparent, "target": pname or "unknown.exe"})
                if cmd and any(k in cmd.lower() for k in ["-enc", "downloadstring", "invoke-mimikatz", "vssadmin", "certutil", "whoami"]):
                    anomalies.append(proc_entry)

        return {
            "processes": processes,
            "edges": edges,
            "anomalies": anomalies,
            "total_processes": len(processes)
        }

    def execute_ssh_forensics(self, target_host: str, command_type: str = "collect_process_tree") -> Dict[str, Any]:
        """Executes a safe allowlisted live forensic diagnostic over SSH on an impacted endpoint."""
        from backend.engine.ssh_engine import SSHEngine
        return SSHEngine.execute_command(
            target_host=target_host,
            command_type=command_type,
            db=self.db
        )



