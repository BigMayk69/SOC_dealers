import pytest
from datetime import datetime, timedelta
from backend.engine.correlation import GraphCorrelationEngine

def test_graph_correlation_groups_by_shared_host():
    engine = GraphCorrelationEngine(time_window_minutes=60)
    base_time = datetime(2026, 10, 1, 10, 0, 0)
    
    alerts = [
        {
            "id": "ALT-001",
            "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
            "rule_name": "Suspicious PowerShell Ingress",
            "severity": "High",
            "src_host": "WORKSTATION-01",
            "username": "alice.smith",
            "mitre_tactic": "Initial Access",
            "mitre_technique_id": "T1566"
        },
        {
            "id": "ALT-002",
            "timestamp": (base_time + timedelta(minutes=15)).isoformat(),
            "rule_name": "LSASS Memory Dump",
            "severity": "Critical",
            "src_host": "WORKSTATION-01",
            "username": "alice.smith",
            "mitre_tactic": "Credential Access",
            "mitre_technique_id": "T1003.001"
        },
        {
            "id": "ALT-003",
            "timestamp": (base_time + timedelta(minutes=30)).isoformat(),
            "rule_name": "PsExec Lateral Traversal to File Server",
            "severity": "Critical",
            "src_host": "WORKSTATION-01",
            "dest_host": "FILE-SRV-01",
            "username": "alice.smith",
            "mitre_tactic": "Lateral Movement",
            "mitre_technique_id": "T1021.002"
        }
    ]
    
    clusters = engine.correlate_alerts(alerts)
    assert len(clusters) == 1
    inc = clusters[0]
    assert inc["alert_count"] == 3
    assert "WORKSTATION-01" in inc["impacted_hosts"]
    assert "FILE-SRV-01" in inc["impacted_hosts"]
    assert "alice.smith" in inc["impacted_users"]
    assert len(inc["mitre_tactics"]) == 3
    assert inc["raw_alert_reduction_pct"] >= 66.0

def test_temporal_window_splits_distant_alerts():
    engine = GraphCorrelationEngine(time_window_minutes=60)
    base_time = datetime(2026, 10, 1, 10, 0, 0)
    
    alerts = [
        {
            "id": "ALT-001",
            "timestamp": base_time.isoformat(),
            "rule_name": "Alert 1",
            "src_host": "WORKSTATION-01"
        },
        {
            "id": "ALT-002",
            "timestamp": (base_time + timedelta(minutes=120)).isoformat(), # 2 hours later (> 60m window)
            "rule_name": "Alert 2",
            "src_host": "WORKSTATION-01"
        }
    ]
    
    clusters = engine.correlate_alerts(alerts)
    assert len(clusters) == 2
