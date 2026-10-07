"""
Deterministic Autonomy Policy Engine for Dealers AI SOC Agent.
Enforces rigid, deterministic safety boundaries on agent permissions.
The LLM cannot determine its own execution tier.
"""
from enum import Enum
from typing import Dict, Any, List
from backend.schemas.agent import StructuredInvestigationResult

class AutonomyTier(str, Enum):
    AUTO_RESOLVE = "AUTO_RESOLVE"       # Low Risk + High Confidence Benign/Noise -> Auto Resolved
    REVIEW_NEEDED = "REVIEW_NEEDED"     # Medium Risk / Anomaly -> AI Investigates, Queued for Analyst Review
    HUMAN_REQUIRED = "HUMAN_REQUIRED"   # High Risk / Tier-0 Assets / Critical Tactics -> Mandatory Human Approval

class AutonomyPolicyEngine:
    @staticmethod
    def evaluate(
        incident: Dict[str, Any],
        ai_result: StructuredInvestigationResult,
        assets: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluates deterministic policy rules to assign the autonomy tier.
        """
        risk_score = float(incident.get("risk_score", 50.0))
        confidence = float(ai_result.confidence_score)
        tactics = set(incident.get("mitre_tactics", []))
        has_tier_0 = assets.get("contains_tier_0", False) or float(incident.get("max_asset_criticality", 0.5)) >= 0.9

        # Check for critical / destructive tactics
        critical_tactics = {"Impact", "Credential Access", "Lateral Movement", "Exfiltration"}
        has_critical_tactics = bool(tactics.intersection(critical_tactics))

        # Check if recommended actions include active containment (isolate host, revoke token, kill process)
        active_containment_actions = [
            a for a in ai_result.recommended_actions
            if a.action_type in ["isolate_host", "revoke_token", "block_ip", "kill_process"]
        ]

        # -------------------------------------------------------------
        # GATE 1: HUMAN REQUIRED (Mandatory Human Sign-off)
        # -------------------------------------------------------------
        if has_tier_0:
            return {
                "tier": AutonomyTier.HUMAN_REQUIRED,
                "reason": f"Tier 0 Asset involvement detected (Criticality: {incident.get('max_asset_criticality', 1.0)}). Mandatory human oversight required."
            }

        if risk_score >= 65.0:
            return {
                "tier": AutonomyTier.HUMAN_REQUIRED,
                "reason": f"High composite risk score ({risk_score}/100 exceeds 65.0 threshold). Human sign-off required."
            }

        if has_critical_tactics:
            matched = ", ".join(tactics.intersection(critical_tactics))
            return {
                "tier": AutonomyTier.HUMAN_REQUIRED,
                "reason": f"Critical MITRE attack tactic(s) detected: [{matched}]. Immediate human analyst validation required."
            }

        if active_containment_actions:
            return {
                "tier": AutonomyTier.HUMAN_REQUIRED,
                "reason": f"Active containment actions recommended ({len(active_containment_actions)} action(s)). Execution requires explicit human authorization."
            }

        # -------------------------------------------------------------
        # GATE 2: AUTO-RESOLVE (Safe, high-confidence, low-risk cases)
        # -------------------------------------------------------------
        if risk_score <= 30.0 and confidence >= 0.90 and not has_critical_tactics:
            return {
                "tier": AutonomyTier.AUTO_RESOLVE,
                "reason": f"Low risk anomaly ({risk_score}/100) with high AI confidence ({confidence:.2f}). Safe for automatic resolution/suppression."
            }

        # -------------------------------------------------------------
        # GATE 3: REVIEW NEEDED (Standard triage queue)
        # -------------------------------------------------------------
        return {
            "tier": AutonomyTier.REVIEW_NEEDED,
            "reason": f"Medium risk anomaly ({risk_score}/100). AI investigation dossier attached; queued for analyst review."
        }
