import pytest
from backend.engine.risk_scorer import RiskScorer

def test_risk_scorer_critical_threat_and_tier0_asset():
    alerts = [
        {"severity": "Critical", "severity_score": 98.0},
        {"severity": "Critical", "severity_score": 95.0},
        {"severity": "High", "severity_score": 80.0}
    ]
    hosts = ["DC-PROD-01", "FILE-SRV-01"] # Domain Controller Tier 0
    users = ["alice.smith", "krbtgt"]
    ips = ["185.220.101.5"]
    tactics = ["Initial Access", "Credential Access", "Lateral Movement", "Impact"]

    risk_metrics = RiskScorer.calculate_incident_risk(
        alerts=alerts,
        impacted_hosts=hosts,
        impacted_users=users,
        impacted_ips=ips,
        mitre_tactics=tactics,
        max_asset_criticality=1.0 # Tier 0
    )

    assert risk_metrics["risk_score"] >= 85.0
    assert risk_metrics["priority"] == "P1 - Critical"
    assert risk_metrics["threat_severity_score"] >= 90.0
    assert risk_metrics["max_asset_criticality"] == 1.0

def test_risk_scorer_low_severity_workstation():
    alerts = [
        {"severity": "Low", "severity_score": 20.0}
    ]
    hosts = ["WORKSTATION-05"]
    users = ["eva.green"]
    ips = []
    tactics = ["Discovery"]

    risk_metrics = RiskScorer.calculate_incident_risk(
        alerts=alerts,
        impacted_hosts=hosts,
        impacted_users=users,
        impacted_ips=ips,
        mitre_tactics=tactics,
        max_asset_criticality=0.2 # Tier 3
    )

    assert risk_metrics["risk_score"] <= 40.0
    assert risk_metrics["priority"] == "P4 - Low"
