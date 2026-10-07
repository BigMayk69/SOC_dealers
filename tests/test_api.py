import pytest
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_soc_stats_endpoint():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_raw_alerts" in data
    assert "total_incidents" in data
    assert "reduction_percentage" in data

def test_list_incidents():
    response = client.get("/api/incidents")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_copilot_chat():
    payload = {
        "messages": [
            {"role": "user", "content": "How do we contain the active ransomware outbreak?"}
        ]
    }
    response = client.post("/api/copilot/chat", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "reply" in data
    assert len(data["reply"]) > 10

def test_single_alert_ingest():
    payload = {
        "source": "CrowdStrike Falcon",
        "rule_name": "Suspicious PowerShell Download",
        "event_type": "ProcessCreation",
        "severity": "High",
        "src_host": "DEV-TEST-01",
        "username": "test.user",
        "command_line": "powershell.exe -enc SQBFAFgA..."
    }
    response = client.post("/api/alerts/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["rule_name"] == "Suspicious PowerShell Download"
    assert data["mitre_tactic"] == "Execution"

def test_batch_alert_ingest():
    payload = {
        "alerts": [
            {
                "source": "Suricata NIDS",
                "rule_name": "C2 Beacon",
                "event_type": "NetworkBeacon",
                "severity": "Critical",
                "src_host": "DEV-TEST-02"
            }
        ]
    }
    response = client.post("/api/alerts/batch-ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["ingested_count"] == 1
def test_cockpit_summary():
    response = client.get("/api/cockpit/summary")
    assert response.status_code == 200
    data = response.json()
    assert "kpis" in data
    assert "incidents_queue" in data
    assert "recent_containment_actions" in data
    assert "telemetry_breakdown" in data
    assert "connection_health" in data
    assert data["kpis"]["volume_reduction_pct"] >= 0.0

def test_cockpit_graph():
    # Test with standard seeded incident
    response = client.get("/api/cockpit/graph/INC-20261001-001")
    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] == "INC-20261001-001"
    assert "graph" in data
    assert "nodes" in data["graph"]
    assert "edges" in data["graph"]
