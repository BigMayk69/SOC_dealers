import pytest
from fastapi.testclient import TestClient
from backend.app import app
from backend.database import SessionLocal
from backend.agent.tools import InvestigationToolRegistry
from backend.agent.context_builder import AgentContextBuilder
from backend.agent.policy_engine import AutonomyPolicyEngine, AutonomyTier
from backend.schemas.agent import StructuredInvestigationResult, RecommendedAction

client = TestClient(app)

def test_agent_tool_registry():
    db = SessionLocal()
    try:
        tools = InvestigationToolRegistry(db)
        inc = tools.get_incident("INC-20261001-001")
        assert inc is not None
        assert inc["id"] == "INC-20261001-001"
        assert len(inc["impacted_hosts"]) > 0

        alerts = tools.get_related_alerts("INC-20261001-001", limit=10)
        assert len(alerts) > 0

        timeline = tools.get_timeline("INC-20261001-001")
        assert len(timeline) > 0

        assets = tools.get_asset_details(inc["impacted_hosts"], inc["impacted_users"])
        assert "hosts" in assets
        assert "contains_tier_0" in assets

        mitre = tools.get_mitre_analysis("INC-20261001-001")
        assert "stage_count" in mitre

        ptree = tools.get_process_tree("INC-20261001-001")
        assert "processes" in ptree
        assert "edges" in ptree
        assert "anomalies" in ptree

        mem = tools.get_analyst_feedback_memory(inc["impacted_hosts"], inc["impacted_users"])
        assert "host_feedback" in mem
        assert "user_feedback" in mem
    finally:
        db.close()

def test_agent_context_builder():
    db = SessionLocal()
    try:
        tools = InvestigationToolRegistry(db)
        builder = AgentContextBuilder(tools)
        context, tools_called, raw_evidence = builder.build_investigation_context("INC-20261001-001")
        
        assert context["incident_id"] == "INC-20261001-001"
        assert len(tools_called) >= 7
        assert "get_incident" in tools_called
        assert "get_timeline" in tools_called
        assert "get_process_tree" in tools_called
        assert "timeline_text" in context
    finally:
        db.close()

def test_policy_engine_tier0_human_required():
    mock_incident = {
        "id": "INC-001",
        "risk_score": 98.0,
        "max_asset_criticality": 1.0,
        "mitre_tactics": ["Initial Access", "Impact"]
    }
    mock_result = StructuredInvestigationResult(
        executive_summary="Critical Ransomware Attack",
        what_happened="Adversary encrypted files",
        root_cause="Compromised domain controller",
        attack_progression=["Ingress", "Encryption"],
        supporting_evidence=["Shadow copy deleted"],
        mitre_reasoning={"Impact": "Encryption"},
        affected_assets=[{"name": "DC-PROD-01", "type": "Host", "criticality": 1.0}],
        recommended_actions=[
            RecommendedAction(
                action_type="isolate_host",
                target="DC-PROD-01",
                label="Isolate Host",
                description="Sever network access"
            )
        ],
        confidence_score=0.98,
        uncertainties_and_gaps=[]
    )
    mock_assets = {"contains_tier_0": True, "hosts": [{"tier": "Tier 0 - Domain Controller"}]}

    decision = AutonomyPolicyEngine.evaluate(mock_incident, mock_result, mock_assets)
    assert decision["tier"] == AutonomyTier.HUMAN_REQUIRED
    assert "Tier 0" in decision["reason"] or "High risk" in decision["reason"]

def test_policy_engine_low_risk_auto_resolve():
    mock_incident = {
        "id": "INC-002",
        "risk_score": 15.0,
        "max_asset_criticality": 0.2,
        "mitre_tactics": ["Discovery"]
    }
    mock_result = StructuredInvestigationResult(
        executive_summary="Routine port scan from internal guest network",
        what_happened="Benign vulnerability scanner probe",
        root_cause="Scheduled scanner",
        attack_progression=["Discovery"],
        supporting_evidence=["ICMP sweep"],
        mitre_reasoning={"Discovery": "Ping sweep"},
        affected_assets=[{"name": "GUEST-01", "type": "Host", "criticality": 0.2}],
        recommended_actions=[
            RecommendedAction(
                action_type="resolve_benign",
                target="INC-002",
                label="Auto-Resolve",
                description="Suppress benign scan"
            )
        ],
        confidence_score=0.96,
        uncertainties_and_gaps=[]
    )
    mock_assets = {"contains_tier_0": False, "hosts": [{"tier": "Tier 3 - Guest"}]}

    decision = AutonomyPolicyEngine.evaluate(mock_incident, mock_result, mock_assets)
    assert decision["tier"] == AutonomyTier.AUTO_RESOLVE

def test_api_agent_investigate_endpoint():
    response = client.post("/api/agent/investigate/INC-20261001-001")
    assert response.status_code == 200
    data = response.json()
    
    assert data["incident_id"] == "INC-20261001-001"
    assert "run_id" in data
    assert data["autonomy_tier"] == "HUMAN_REQUIRED"
    assert data["analysis"]["confidence_score"] > 0.8
    assert len(data["tools_called"]) >= 7
    assert len(data["analysis"]["recommended_actions"]) > 0
    assert "detection_rule_yaml" in data["analysis"]
    assert "title:" in data["analysis"]["detection_rule_yaml"]


def test_api_agent_feedback_endpoints():
    fb_payload = {
        "incident_id": "INC-20261001-001",
        "is_correct": True,
        "analyst_verdict": "True Positive",
        "notes": "Tested via pytest",
        "submitted_by": "Test Suite"
    }
    res_post = client.post("/api/agent/feedback", json=fb_payload)
    assert res_post.status_code == 200
    data = res_post.json()
    assert data["is_correct"] is True
    assert data["submitted_by"] == "Test Suite"

    res_get = client.get("/api/agent/feedback?incident_id=INC-20261001-001")
    assert res_get.status_code == 200
    feedbacks = res_get.json()
    assert len(feedbacks) >= 1
