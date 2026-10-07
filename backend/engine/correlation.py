"""
Graph-Based Correlation Engine using NetworkX
Consolidates raw alerts into cohesive incidents based on shared entities & 60-minute time window.
"""
import networkx as nx
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set
import math

class GraphCorrelationEngine:
    def __init__(self, time_window_minutes: int = 60):
        self.time_window = timedelta(minutes=time_window_minutes)

    def extract_entities_from_alert(self, alert: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extracts normalized entity identifiers from an alert record"""
        entities = {
            "hosts": [],
            "users": [],
            "ips": [],
            "hashes": [],
            "processes": [],
            "domains": []
        }
        
        # Host / Device
        src_h = alert.get("src_host") or alert.get("device_hostname")
        if src_h:
            entities["hosts"].append(src_h)
        if alert.get("dest_host") and alert["dest_host"] != src_h:
            entities["hosts"].append(alert["dest_host"])
        if alert.get("asset_id"):
            entities["hosts"].append(alert["asset_id"])
            
        # User (Normalize email e.g. meera.iyer@corp.example -> meera.iyer)
        raw_user = alert.get("username") or alert.get("user")
        if raw_user:
            norm_user = raw_user.split("@")[0].strip().lower()
            if norm_user not in ["system", "local", "n/a", "anonymous", "root", ""]:
                entities["users"].append(norm_user)
            
        # Only pivot on external non-private IPs or specific attacker infrastructure
        dest_ip = alert.get("dest_ip") or alert.get("dst_ip")
        if dest_ip and not self._is_private_or_loopback(dest_ip):
            entities["ips"].append(dest_ip)
        src_ip = alert.get("src_ip")
        if src_ip and not self._is_private_or_loopback(src_ip):
            entities["ips"].append(src_ip)
            
        if alert.get("file_hash"):
            entities["hashes"].append(alert["file_hash"])
            
        if alert.get("process_name") and alert["process_name"].lower() not in ["svchost.exe", "system", "idle"]:
            entities["processes"].append(alert["process_name"])
            
        domain = alert.get("domain") or alert.get("url_or_domain")
        if domain and not domain.endswith(".internal"):
            entities["domains"].append(domain)

        return entities


    def _is_private_or_loopback(self, ip: str) -> bool:
        if not ip:
            return True
        if ip in ["127.0.0.1", "::1", "localhost", "0.0.0.0"]:
            return True
        # Allow external IPs to act as correlation pivots
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
            return True
        return False

    def correlate_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Builds an Alert-to-Alert NetworkX Graph where an edge exists between Alert A and Alert B if:
        1. They share at least one entity (Host, User, External IP, FileHash, Specific Process, Domain)
        2. AND abs(timestamp(A) - timestamp(B)) <= 60 minutes
        """
        if not alerts:
            return []

        # Sort alerts chronologically
        sorted_alerts = sorted(alerts, key=lambda a: self._parse_dt(a.get("timestamp")))
        
        # Build an Entity -> List of (AlertID, Timestamp, AlertData) index
        entity_to_alerts: Dict[str, List[Dict[str, Any]]] = {}
        alert_map: Dict[str, Dict[str, Any]] = {}

        for a in sorted_alerts:
            aid = a["id"]
            a_time = self._parse_dt(a.get("timestamp"))
            a_copy = {**a, "_dt": a_time}
            alert_map[aid] = a_copy

            ents = self.extract_entities_from_alert(a)
            for etype, values in ents.items():
                for val in values:
                    key = f"{etype}:{val}"
                    if key not in entity_to_alerts:
                        entity_to_alerts[key] = []
                    entity_to_alerts[key].append(a_copy)

        # Construct NetworkX Graph of Alerts
        G = nx.Graph()
        for aid, a in alert_map.items():
            G.add_node(aid, data=a)

        # Add edges between alerts that share an entity within the 60-minute window
        for key, alert_list in entity_to_alerts.items():
            # For efficiency in sliding window
            n = len(alert_list)
            for i in range(n):
                a1 = alert_list[i]
                for j in range(i + 1, n):
                    a2 = alert_list[j]
                    delta = a2["_dt"] - a1["_dt"]
                    if delta <= self.time_window:
                        G.add_edge(a1["id"], a2["id"], entity_pivot=key)
                    else:
                        # Since list is chronologically sorted, further alerts will be even further apart
                        break

        # Connected components now represent exact consolidated incidents!
        components = list(nx.connected_components(G))
        incident_clusters = []

        for comp in components:
            comp_alerts = [alert_map[aid] for aid in comp]
            comp_alerts.sort(key=lambda x: x["_dt"])
            
            # Clean temporary _dt before packing
            cleaned_alerts = [{k: v for k, v in a.items() if k != "_dt"} for a in comp_alerts]
            
            incident_pkg = self._build_incident_package(cleaned_alerts)
            incident_clusters.append(incident_pkg)

        # Sort incidents by alert count & risk score descending
        incident_clusters.sort(key=lambda x: (x.get("alert_count", 0), x.get("max_asset_criticality", 0.5)), reverse=True)
        return incident_clusters

    def _build_incident_package(self, cluster_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Constructs incident metadata, attack narrative components, topology, and entity lists"""
        first_time = self._parse_dt(cluster_alerts[0]["timestamp"])
        last_time = self._parse_dt(cluster_alerts[-1]["timestamp"])
        duration_mins = max(1.0, round((last_time - first_time).total_seconds() / 60.0, 1))

        # Collect entities
        hosts = set()
        users = set()
        ips = set()
        hashes = set()
        tactics = []
        techniques = []
        max_crit = 0.5

        for a in cluster_alerts:
            ents = self.extract_entities_from_alert(a)
            hosts.update(ents["hosts"])
            users.update(ents["users"])
            ips.update(ents["ips"])
            hashes.update(ents["hashes"])
            
            if a.get("mitre_tactic"):
                tactics.append(a["mitre_tactic"])
            if a.get("mitre_technique_id"):
                techniques.append({
                    "id": a["mitre_technique_id"],
                    "name": a.get("mitre_technique_name", "Unknown Technique")
                })
            try:
                crit = float(a.get("asset_criticality") or 0.5)
                if crit > 1.0:
                    crit = crit / 5.0 # Normalize 1-5 dataset scale to 0.2-1.0
            except (ValueError, TypeError):
                crit = 0.5
                
            if crit > max_crit:
                max_crit = crit

        # Deduplicate techniques

        unique_techniques = []
        seen_t_ids = set()
        for t in techniques:
            if t["id"] not in seen_t_ids:
                seen_t_ids.add(t["id"])
                unique_techniques.append(t)

        unique_tactics = list(dict.fromkeys(tactics))

        # Generate topology graph for this incident
        topology = self._generate_incident_topology(cluster_alerts)

        # Primary pivot entities
        pivot_entities = []
        if hosts:
            pivot_entities.append(f"Host: {list(hosts)[0]}")
        if users:
            pivot_entities.append(f"Account: {list(users)[0]}")
        if ips:
            pivot_entities.append(f"IP: {list(ips)[0]}")

        raw_count = len(cluster_alerts)
        reduction_pct = round((1.0 - (1.0 / max(1, raw_count))) * 100.0, 1)
        title = self._generate_incident_title(cluster_alerts, list(hosts), list(users), unique_tactics)

        return {
            "title": title,
            "alerts": cluster_alerts,
            "alert_count": raw_count,
            "raw_alert_reduction_pct": reduction_pct,
            "first_alert_time": first_time,
            "last_alert_time": last_time,
            "duration_minutes": duration_mins,
            "impacted_hosts": list(hosts),
            "impacted_users": list(users),
            "impacted_ips": list(ips),
            "mitre_tactics": unique_tactics,
            "mitre_techniques": unique_techniques,
            "max_asset_criticality": max_crit,
            "pivot_entities": pivot_entities,
            "graph_topology": topology
        }

    def _generate_incident_title(self, alerts: List[Dict[str, Any]], hosts: List[str], users: List[str], tactics: List[str]) -> str:
        primary_host = hosts[0] if hosts else "Network Endpoint"
        primary_user = users[0] if users else "Service"
        
        tactic_set = set(tactics)
        if "Impact" in tactic_set and "Lateral Movement" in tactic_set:
            return f"Ransomware Propagation & Lateral Movement targeting {primary_host} via {primary_user}"
        elif "Exfiltration" in tactic_set or "Command and Control" in tactic_set:
            return f"Data Exfiltration & C2 Beaconing activity on {primary_host} [{primary_user}]"
        elif "Credential Access" in tactic_set and "Lateral Movement" in tactic_set:
            return f"Credential Dumping & Lateral Movement across Domain Assets starting from {primary_host}"
        elif "Initial Access" in tactic_set and "Execution" in tactic_set:
            return f"Phishing Ingress & Malicious Script Execution on {primary_host} ({primary_user})"
        elif "Privilege Escalation" in tactic_set:
            return f"Suspicious Privilege Escalation & Process Injection on {primary_host}"
        else:
            first_rule = alerts[0].get("rule_name", "Security Anomaly")
            return f"{first_rule} Cluster on {primary_host}"

    def _generate_incident_topology(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        nodes = []
        edges = []
        node_ids = set()

        def add_node(nid: str, label: str, ntype: str, icon: str, color: str, size: int, meta: Dict[str, Any] = None):
            if nid not in node_ids:
                node_ids.add(nid)
                nodes.append({
                    "id": nid,
                    "label": label,
                    "type": ntype,
                    "icon": icon,
                    "color": color,
                    "size": size,
                    "metadata": meta or {}
                })

        for a in alerts[:35]: # Cap to top 35 nodes for silky smooth visual performance
            aid = f"alert_{a['id']}"
            sev = a.get("severity", "Medium")
            sev_colors = {
                "Critical": "#ef4444",
                "High": "#f97316",
                "Medium": "#eab308",
                "Low": "#3b82f6",
                "Informational": "#06b6d4"
            }
            color = sev_colors.get(sev, "#eab308")
            
            add_node(aid, a.get("rule_name", "Alert")[:26], "alert", "shield-alert", color, 16, {
                "id": a["id"],
                "rule": a.get("rule_name"),
                "severity": sev,
                "tactic": a.get("mitre_tactic"),
                "time": str(a.get("timestamp"))
            })

            # Connect to Host
            if a.get("src_host"):
                hid = f"host_{a['src_host']}"
                add_node(hid, a["src_host"], "host", "server", "#38bdf8", 22, {"criticality": a.get("asset_criticality", 0.5)})
                edges.append({"source": aid, "target": hid, "label": "on host", "color": "#0284c7"})

            if a.get("dest_host") and a["dest_host"] != a.get("src_host"):
                dhid = f"host_{a['dest_host']}"
                add_node(dhid, a["dest_host"], "host", "server", "#38bdf8", 22, {"criticality": 0.8})
                edges.append({"source": aid, "target": dhid, "label": "targets", "color": "#0284c7"})

            if a.get("username") and a["username"].lower() not in ["system", "local", "n/a"]:
                uid = f"user_{a['username']}"
                add_node(uid, a["username"], "user", "user", "#a855f7", 20, {})
                edges.append({"source": aid, "target": uid, "label": "user", "color": "#9333ea"})

            if a.get("dest_ip") and not self._is_private_or_loopback(a["dest_ip"]):
                ipid = f"ip_{a['dest_ip']}"
                add_node(ipid, a["dest_ip"], "ip", "globe", "#f43f5e", 18, {"is_external": True})
                edges.append({"source": aid, "target": ipid, "label": "C2 IP", "color": "#e11d48"})

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges)
        }

    def _parse_dt(self, val: Any) -> datetime:
        if isinstance(val, datetime):
            return val
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val.replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                pass
        return datetime.utcnow()
