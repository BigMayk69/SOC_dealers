"""
AI Context Builder for Dealers AI SOC Agent.
Synthesizes multi-source evidence (graph topology, alert lineage, asset tiers, MITRE stages) into structured prompt context.
"""
from typing import Dict, Any, List, Tuple
from backend.agent.tools import InvestigationToolRegistry

class AgentContextBuilder:
    def __init__(self, tools: InvestigationToolRegistry):
        self.tools = tools

    def build_investigation_context(self, incident_id: str) -> Tuple[Dict[str, Any], List[str], Dict[str, Any]]:
        """
        Executes safe read-only tools to gather multi-vector evidence.
        Returns:
            (context_dict, tools_called_list, raw_evidence_dict)
        """
        tools_called = []
        raw_evidence = {}

        # 1. Incident Metadata
        inc = self.tools.get_incident(incident_id)
        tools_called.append("get_incident")
        raw_evidence["incident"] = inc

        if not inc:
            return {}, tools_called, raw_evidence

        # 2. Constituent Alerts
        alerts = self.tools.get_related_alerts(incident_id, limit=50)
        tools_called.append("get_related_alerts")
        raw_evidence["alert_count"] = len(alerts)

        # 3. High-Signal Chronological Timeline
        timeline = self.tools.get_timeline(incident_id)
        tools_called.append("get_timeline")
        raw_evidence["timeline"] = timeline

        # 4. Asset Details & Identity Criticality
        assets = self.tools.get_asset_details(inc["impacted_hosts"], inc["impacted_users"])
        tools_called.append("get_asset_details")
        raw_evidence["assets"] = assets

        # 5. MITRE ATT&CK Kill-Chain Analysis
        mitre = self.tools.get_mitre_analysis(incident_id)
        tools_called.append("get_mitre_analysis")
        raw_evidence["mitre_analysis"] = mitre

        # 6. Related Incidents Search
        related = self.tools.search_related_incidents(inc["impacted_hosts"], inc["impacted_users"], incident_id)
        tools_called.append("search_related_incidents")
        raw_evidence["related_incidents"] = related

        # 7. Containment History
        containment = self.tools.get_containment_history(incident_id)
        tools_called.append("get_containment_history")
        raw_evidence["containment_history"] = containment

        # 8. Analyst Decision Memory
        feedback_memory = self.tools.get_analyst_feedback_memory(inc["impacted_hosts"], inc["impacted_users"])
        tools_called.append("get_analyst_feedback_memory")
        raw_evidence["feedback_memory"] = feedback_memory

        # 9. Process Execution Tree
        process_tree = self.tools.get_process_tree(incident_id)
        tools_called.append("get_process_tree")
        raw_evidence["process_tree"] = process_tree

        # Build formatted prompt text blocks
        timeline_lines = []
        for idx, t in enumerate(timeline[:20], 1):
            cmd_part = f" | Command: `{t['command'][:100]}`" if t.get("command") else ""
            timeline_lines.append(
                f"[{idx}] {t['timestamp']} | Rule: {t['rule_name']} | Host: {t.get('host')} | User: {t.get('user')} | Tactic: {t.get('tactic')} ({t.get('technique_id')}){cmd_part}"
            )
        timeline_str = "\n".join(timeline_lines) if timeline_lines else "No timeline telemetry available."

        asset_lines = []
        for h in assets.get("hosts", []):
            asset_lines.append(f"- Host: {h['hostname']} (Tier: {h['tier']}, Criticality: {h['criticality']}, Dept: {h['department']})")
        for u in assets.get("users", []):
            asset_lines.append(f"- User: {u['username']} (Tier: {u['tier']}, Role: {u['role']}, Dept: {u['department']})")
        assets_str = "\n".join(asset_lines) if asset_lines else "Standard endpoint assets."

        mitre_str = f"Tactics in order: {' -> '.join(mitre.get('ordered_tactics', []))}\nStages observed: {mitre.get('stage_count', 0)} of 14 tactics ({mitre.get('kill_chain_coverage_pct', 0)}% kill-chain coverage). Advanced Campaign: {mitre.get('is_advanced_campaign', False)}"

        memory_lines = []
        feedback_items = feedback_memory.get("recent", []) if isinstance(feedback_memory, dict) else feedback_memory
        for m in feedback_items[:3]:
            memory_lines.append(f"- Previous incident {m['incident_id']} verdict: {m['verdict']} ({'Validated' if m['is_correct'] else 'Disputed'}) - {m['notes']}")
        memory_str = "\n".join(memory_lines) if memory_lines else "No previous analyst feedback found."

        proc_count = len(process_tree.get("processes", [])) if isinstance(process_tree, dict) else len(process_tree)

        context_dict = {
            "incident_id": inc["id"],
            "title": inc["title"],
            "risk_score": inc["risk_score"],
            "priority": inc["priority"],
            "alert_count": inc["alert_count"],
            "reduction_pct": inc["raw_alert_reduction_pct"],
            "impacted_hosts": inc["impacted_hosts"],
            "impacted_users": inc["impacted_users"],
            "impacted_ips": inc["impacted_ips"],
            "timeline_text": timeline_str,
            "assets_text": assets_str,
            "mitre_text": mitre_str,
            "memory_text": memory_str,
            "process_tree_count": proc_count,
            "has_tier_0": assets.get("contains_tier_0", False),
            "related_incidents_count": len(related),
            "containment_history_count": len(containment)
        }

        return context_dict, tools_called, raw_evidence

