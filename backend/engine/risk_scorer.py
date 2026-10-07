"""
Dynamic Risk Scoring Engine for Dealers AI SOC Triage
Factors in: Threat Severity + Asset Criticality + Blast Radius + MITRE Depth
"""
import math
from typing import List, Dict, Any

SEVERITY_BASE_MAP = {
    "CRITICAL": 95.0,
    "HIGH": 75.0,
    "MEDIUM": 45.0,
    "LOW": 20.0,
    "INFORMATIONAL": 5.0,
    "INFO": 5.0
}

ASSET_TIER_WEIGHTS = {
    "Tier 0 - Domain Controller / KeyVault / Prod DB": 1.0,
    "Tier 1 - Core App Server / API Gateway": 0.8,
    "Tier 2 - Corporate Workstation / VPN": 0.5,
    "Tier 3 - Sandbox / Lab / Guest Network": 0.2
}

class RiskScorer:
    @staticmethod
    def calculate_incident_risk(
        alerts: List[Dict[str, Any]],
        impacted_hosts: List[str],
        impacted_users: List[str],
        impacted_ips: List[str],
        mitre_tactics: List[str],
        max_asset_criticality: float = 0.5
    ) -> Dict[str, Any]:
        """
        Calculates composite risk score (0-100), breakdown metrics, and priority assignment.
        """
        if not alerts:
            return {
                "risk_score": 10.0,
                "threat_severity_score": 10.0,
                "max_asset_criticality": max_asset_criticality,
                "blast_radius_score": 5.0,
                "priority": "P4 - Low"
            }

        # 1. Base Threat Severity
        severity_scores = []
        for a in alerts:
            sev_str = str(a.get("severity", "Medium")).upper()
            score = a.get("severity_score") or SEVERITY_BASE_MAP.get(sev_str, 45.0)
            severity_scores.append(score)

        max_sev = max(severity_scores) if severity_scores else 45.0
        avg_sev = sum(severity_scores) / len(severity_scores)
        
        # Diminishing returns on alert volume
        volume_factor = min(18.0, 4.0 * math.log(1 + len(alerts)))
        threat_severity_score = min(100.0, max_sev * 0.75 + avg_sev * 0.25 + volume_factor)

        # 2. Asset Criticality Factor (Tier 0 to Tier 3)
        # Ensure asset criticality is clamped between 0.1 and 1.0
        asset_crit = max(0.1, min(1.0, max_asset_criticality))
        asset_weight = 0.45 + (0.55 * asset_crit) # range 0.505 to 1.00

        # 3. Blast Radius (Unique Hosts, Users, External IPs)
        num_hosts = len(impacted_hosts)
        num_users = len(impacted_users)
        num_ips = len(impacted_ips)
        
        blast_points = (num_hosts * 14.0) + (num_users * 12.0) + (num_ips * 6.0)
        blast_radius_score = min(100.0, max(10.0, blast_points))
        blast_multiplier = 1.0 + min(0.35, (blast_radius_score / 300.0))

        # 4. MITRE ATT&CK Depth Multiplier
        num_tactics = len(set(mitre_tactics))
        mitre_multiplier = 1.0
        if num_tactics >= 4:
            mitre_multiplier = 1.25 # Full Kill Chain in progress
        elif num_tactics >= 2:
            mitre_multiplier = 1.12
        
        # High impact penalties
        if "Impact" in mitre_tactics or "Exfiltration" in mitre_tactics:
            mitre_multiplier *= 1.15

        # 5. Composite Final Score
        raw_composite = threat_severity_score * asset_weight * blast_multiplier * mitre_multiplier
        final_risk_score = round(min(99.8, max(5.0, raw_composite)), 1)

        # 6. Priority Classification
        if final_risk_score >= 85.0:
            priority = "P1 - Critical"
        elif final_risk_score >= 65.0:
            priority = "P2 - High"
        elif final_risk_score >= 40.0:
            priority = "P3 - Medium"
        else:
            priority = "P4 - Low"

        return {
            "risk_score": final_risk_score,
            "threat_severity_score": round(threat_severity_score, 1),
            "max_asset_criticality": round(asset_crit, 2),
            "blast_radius_score": round(blast_radius_score, 1),
            "priority": priority
        }
