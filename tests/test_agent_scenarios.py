"""
Scenario Evaluation Test Suite for Autonomous AI SOC Agent.
Tests the agent across a curated set of Benign, Suspicious, and Malicious Outbreak scenarios
with graduated autonomy tiers, live SSH DFIR probes, staged remediation, and RBAC walls.
"""
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app import app
from backend.database import SessionLocal
from backend.models import Incident, Alert, Entity
from backend.agent.orchestrator import SOCAgentOrchestrator
from backend.agent.policy_engine import AutonomyPolicyEngine, AutonomyTier

client = TestClient(app)


def test_scenario_benign_auto_resolve():
    """
    Scenario 1: Benign Internal Vulnerability Scan / Routine Maintenance.
    Expected: AutonomyTier.AUTO_RESOLVE, high confidence, auto-closed when dry_run=False.
    """
    db = SessionLocal()
    try:
        inc_id = "INC-BENIGN-001"
        now_dt = datetime.now(timezone.utc)
        
        # Seed benign incident
        inc = Incident(
            id=inc_id,
            title="Routine Internal Vulnerability Scan Probe",
            status="New",
            priority="P4 - Low",
            risk_score=14.5,
            raw_alert_reduction_pct=90.0,
            alert_count=5,
            impacted_hosts=["DEV-TEST-01"],
            impacted_users=["scanner-svc"],
            impacted_ips=["10.10.1.25"],
            mitre_tactics=["Discovery"],
            max_asset_criticality=0.2,
            first_alert_time=now_dt,
            last_alert_time=now_dt,
            triage_time_seconds=12
        )
        db.merge(inc)

        # Seed constituent alerts
        alert = Alert(
            id="ALT-BENIGN-01",
            incident_id=inc_id,
            timestamp=now_dt,
            source="Suricata NIDS",
            rule_name="Internal Vulnerability Scanner Ping Sweep",
            event_type="PortScan",
            severity="Low",
            severity_score=15.0,
            confidence=0.98,
            src_host="DEV-TEST-01",
            username="scanner-svc",
            mitre_tactic="Discovery",
            mitre_technique_id="T1046",
            mitre_technique_name="Network Service Discovery",
            asset_criticality=0.2
        )
        db.merge(alert)
        db.commit()

        orchestrator = SOCAgentOrchestrator(db)
        
        # Test dry_run investigation
        res_dry = client.post(f"/api/agent/investigate/{inc_id}?dry_run=true")
        assert res_dry.status_code == 200
        data_dry = res_dry.json()
        assert data_dry["autonomy_tier"] == "AUTO_RESOLVE"
        assert data_dry["dry_run"] is True

        # Test live investigation (dry_run=False)
        res_live = client.post(f"/api/agent/investigate/{inc_id}?dry_run=false")
        assert res_live.status_code == 200
        data_live = res_live.json()
        assert data_live["autonomy_tier"] == "AUTO_RESOLVE"
        
        # Verify incident status was auto-resolved in database
        updated_inc = db.query(Incident).filter(Incident.id == inc_id).first()
        assert updated_inc.status == "Closed - Auto Resolved"

    finally:
        db.close()


def test_scenario_suspicious_review_needed():
    """
    Scenario 2: Suspicious Off-Hours Admin Activity / Unapproved Scripting.
    Expected: AutonomyTier.REVIEW_NEEDED, assigned to analyst queue, no automatic closure.
    """
    db = SessionLocal()
    try:
        inc_id = "INC-SUSPICIOUS-002"
        now_dt = datetime.now(timezone.utc)

        inc = Incident(
            id=inc_id,
            title="Suspicious Off-Hours PowerShell Invocation",
            status="New",
            priority="P2 - High",
            risk_score=52.0,
            raw_alert_reduction_pct=85.0,
            alert_count=8,
            impacted_hosts=["WORKSTATION-01"],
            impacted_users=["david.miller"],
            impacted_ips=["192.168.1.100"],
            mitre_tactics=["Execution", "Discovery"],
            max_asset_criticality=0.5,
            first_alert_time=now_dt,
            last_alert_time=now_dt,
            triage_time_seconds=45
        )
        db.merge(inc)

        alert = Alert(
            id="ALT-SUSP-01",
            incident_id=inc_id,
            timestamp=now_dt,
            source="CrowdStrike Falcon",
            rule_name="Unapproved PowerShell Execution",
            event_type="ProcessCreation",
            severity="Medium",
            severity_score=50.0,
            confidence=0.88,
            src_host="WORKSTATION-01",
            username="david.miller",
            process_name="powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass Get-Process",
            mitre_tactic="Execution",
            mitre_technique_id="T1059.001",
            mitre_technique_name="PowerShell",
            asset_criticality=0.5
        )
        db.merge(alert)
        db.commit()

        response = client.post(f"/api/agent/investigate/{inc_id}?dry_run=true")
        assert response.status_code == 200
        data = response.json()
        assert data["autonomy_tier"] == "REVIEW_NEEDED"
        assert len(data["forensic_playbook_trace"]) >= 1
        assert "WORKSTATION-01" in data["analysis"]["what_happened"] or "WORKSTATION-01" in data["analysis"]["executive_summary"]
        assert len(data["analysis"]["recommended_actions"]) >= 1

    finally:
        db.close()


def test_scenario_malicious_ransomware_human_required_and_rbac_wall():
    """
    Scenario 3: Multi-Stage Ransomware & Lateral Movement to Tier-0 Domain Controller.
    Expected:
    1. AutonomyTier.HUMAN_REQUIRED (Tier-0 Domain Controller protection).
    2. Staged allowlisted containment commands (isolate_host, block_ip, revoke_token).
    3. Live SSH forensic playbook execution (process tree, network sockets, auth log).
    4. RBAC Wall: Tier-1 Analyst blocked from executing containment, Admin permitted.
    """
    db = SessionLocal()
    try:
        inc_id = "INC-20261001-001" # Seeded critical incident
        
        # 1. Trigger Agent Investigation
        response = client.post(f"/api/agent/investigate/{inc_id}?dry_run=true")
        assert response.status_code == 200
        data = response.json()

        assert data["autonomy_tier"] == "HUMAN_REQUIRED"
        assert data["analysis"]["confidence_score"] >= 0.85
        assert len(data["staged_remediation_commands"]) >= 1
        assert len(data["forensic_playbook_trace"]) >= 3

        # Verify staged containment commands
        staged_types = [c["action_type"] for c in data["staged_remediation_commands"]]
        assert "isolate_host" in staged_types

        # 2. RBAC Gate: Verify Tier-1 Analyst cannot execute containment SSH
        tier1_headers = {
            "X-User-Email": "tier1.analyst@dealers.corp",
            "X-User-Role": "TIER1_ANALYST"
        }
        res_t1 = client.post(
            "/api/ssh/execute",
            json={"target_host": "WORKSTATION-01", "command_type": "isolate_host_firewall"},
            headers=tier1_headers
        )
        assert res_t1.status_code == 403

        # 3. RBAC Gate: Verify SOC Lead Admin CAN execute containment SSH
        admin_headers = {
            "X-User-Email": "admin@dealers.corp",
            "X-User-Role": "SOC_LEAD_ADMIN"
        }
        res_admin = client.post(
            "/api/ssh/execute",
            json={"target_host": "WORKSTATION-01", "command_type": "isolate_host_firewall"},
            headers=admin_headers
        )
        assert res_admin.status_code == 200
        assert res_admin.json()["is_containment"] is True

        # 4. Verify Sigma YAML rule generated
        assert data["analysis"]["detection_rule_yaml"] is not None
        assert "title:" in data["analysis"]["detection_rule_yaml"]
        assert "logsource:" in data["analysis"]["detection_rule_yaml"]

    finally:
        db.close()


def test_scenario_simulation_dry_run_integrity():
    """
    Scenario 4: Validates that dry_run mode generates complete staged playbooks
    without altering machine or network firewall state.
    """
    response = client.post("/api/agent/investigate/INC-20261001-001?dry_run=true")
    assert response.status_code == 200
    data = response.json()
    assert data["dry_run"] is True
    assert "forensic_playbook_trace" in data
    assert "staged_remediation_commands" in data
    for cmd in data["staged_remediation_commands"]:
        assert cmd["status"].startswith("STAGED")
