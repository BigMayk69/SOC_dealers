"""
3,000 Raw Alerts SOC Firehose Simulator for Dealers AI SOC Triage
Generates realistic heterogeneous security logs across CrowdStrike, Suricata, AWS, Okta, Windows Sysmon, and Palo Alto.
Produces ~35-45 cohesive incidents for an exact ~90-92% alert reduction benchmark.
"""
import random
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any

SOURCES = ["CrowdStrike Falcon", "Suricata NIDS", "AWS CloudTrail", "Okta Identity", "Windows Sysmon", "Palo Alto NGFW", "Azure Sentinel"]

HOSTS_POOL = [
    ("WORKSTATION-01", 0.5, "Tier 2 - Workstation", "Finance", "alice.smith"),
    ("WORKSTATION-02", 0.5, "Tier 2 - Workstation", "Engineering", "bob.chen"),
    ("WORKSTATION-03", 0.5, "Tier 2 - Workstation", "HR", "carol.white"),
    ("WORKSTATION-04", 0.6, "Tier 2 - Executive Workstation", "Executive", "david.kim"),
    ("WORKSTATION-05", 0.5, "Tier 2 - Workstation", "Marketing", "eva.green"),
    ("FILE-SRV-01", 0.8, "Tier 1 - Core App Server", "IT Infrastructure", "svc_fileshare"),
    ("APP-PROD-02", 0.8, "Tier 1 - Core App Server", "Cloud Engineering", "svc_appdeploy"),
    ("DB-PRIMARY-01", 0.95, "Tier 0 - Production DB", "Database Ops", "dba_admin"),
    ("DC-PROD-01", 1.0, "Tier 0 - Domain Controller", "Identity Infrastructure", "krbtgt"),
    ("BACKUP-SRV-01", 0.85, "Tier 1 - Backup Core", "Disaster Recovery", "svc_backup"),
    ("VPN-GW-01", 0.75, "Tier 1 - Network Gateway", "Network Ops", "svc_vpn"),
    ("AWS-PROD-CLUSTER", 0.9, "Tier 0 - Cloud Infrastructure", "DevOps", "cloud_admin")
]

class AlertSimulator:
    @staticmethod
    def generate_3000_alerts() -> List[Dict[str, Any]]:
        now = datetime.utcnow()
        start_time = now - timedelta(hours=3, minutes=30)
        alerts: List[Dict[str, Any]] = []

        alert_idx = 1000

        def create_alert(
            source: str,
            rule_name: str,
            event_type: str,
            severity: str,
            sev_score: float,
            src_host: str,
            dest_host: str = None,
            username: str = None,
            src_ip: str = None,
            dest_ip: str = None,
            process_name: str = None,
            cmd: str = None,
            tactic: str = None,
            tech_id: str = None,
            tech_name: str = None,
            domain: str = None,
            file_hash: str = None,
            time_offset_mins: int = 0,
            crit: float = 0.5,
            desc: str = None
        ) -> Dict[str, Any]:
            nonlocal alert_idx
            alert_idx += 1
            t_stamp = start_time + timedelta(minutes=time_offset_mins, seconds=random.randint(0, 59))
            
            return {
                "id": f"ALT-20261001-{alert_idx}",
                "timestamp": t_stamp.isoformat(),
                "source": source,
                "rule_name": rule_name,
                "event_type": event_type,
                "severity": severity,
                "severity_score": sev_score,
                "confidence": round(random.uniform(0.85, 0.99), 2),
                "src_host": src_host,
                "dest_host": dest_host,
                "username": username,
                "src_ip": src_ip or f"10.0.{random.randint(1, 5)}.{random.randint(10, 250)}",
                "dest_ip": dest_ip,
                "process_name": process_name,
                "process_path": f"C:\\Windows\\System32\\{process_name}" if process_name else None,
                "command_line": cmd,
                "parent_process": "explorer.exe" if process_name == "powershell.exe" else "cmd.exe",
                "file_hash": file_hash or (f"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852{random.randint(1000, 9999)}" if process_name else None),
                "domain": domain,
                "port": random.choice([443, 445, 80, 8443, 3389, 53]),
                "protocol": "TCP",
                "mitre_tactic": tactic,
                "mitre_technique_id": tech_id,
                "mitre_technique_name": tech_name,
                "asset_criticality": crit,
                "description": desc or f"Security telemetry detection: {rule_name} triggered on {src_host}",
                "raw_payload": {
                    "sensor_id": f"CS-AGENT-{random.randint(1000, 9999)}",
                    "event_id": str(uuid.uuid4())
                }
            }

        # ---------------------------------------------------------
        # MAJOR CAMPAIGN 1: Multi-Stage Ransomware (220 alerts)
        # ---------------------------------------------------------
        for i in range(220):
            stage = i % 5
            if stage == 0:
                alerts.append(create_alert("CrowdStrike Falcon", "Suspicious Office Document Spawning PowerShell", "ProcessCreation", "High", 80.0, "WORKSTATION-01", username="alice.smith", process_name="powershell.exe", cmd="powershell.exe -Enc SQBFAFgA...", tactic="Initial Access", tech_id="T1566.001", tech_name="Spearphishing Attachment", time_offset_mins=5 + (i%5), crit=0.5))
            elif stage == 1:
                alerts.append(create_alert("Suricata NIDS", "ET MALWARE Cobalt Strike Malleable C2 Beaconing", "NetworkBeacon", "Critical", 95.0, "WORKSTATION-01", dest_ip="185.220.101.5", domain="c2-sync-payload.xyz", tactic="Command and Control", tech_id="T1573.002", tech_name="Asymmetric Encrypted C2 Beacon", time_offset_mins=10 + (i%8), crit=0.5))
            elif stage == 2:
                alerts.append(create_alert("Windows Sysmon", "LSASS Memory Access / Mimikatz Sekurlsa Injection", "CredentialAccess", "Critical", 98.0, "WORKSTATION-01", username="alice.smith", process_name="lsass.exe", cmd="sekurlsa::logonpasswords full", tactic="Credential Access", tech_id="T1003.001", tech_name="LSASS Memory Dumping", time_offset_mins=18 + (i%5), crit=0.5))
            elif stage == 3:
                alerts.append(create_alert("CrowdStrike Falcon", "Remote Service Creation / PsExec across Admin Shares", "LateralMovement", "Critical", 96.0, "WORKSTATION-01", dest_host="DC-PROD-01", username="alice.smith", process_name="psexec.exe", cmd="psexec.exe \\\\DC-PROD-01 -u admin payload.dll", tactic="Lateral Movement", tech_id="T1021.002", tech_name="SMB Admin Shares", time_offset_mins=28 + (i%10), crit=1.0))
            else:
                alerts.append(create_alert("Windows Sysmon", "Shadow Copies Deletion & File Encryption (.locked)", "Impact", "Critical", 99.0, "DC-PROD-01", username="alice.smith", process_name="vssadmin.exe", cmd="vssadmin.exe delete shadows /all /quiet", tactic="Impact", tech_id="T1490", tech_name="Inhibit Recovery", time_offset_mins=40 + (i%10), crit=1.0))

        # ---------------------------------------------------------
        # MAJOR CAMPAIGN 2: Cloud Admin Token Abuse & S3 Exfiltration (180 alerts)
        # ---------------------------------------------------------
        for i in range(180):
            stage = i % 3
            if stage == 0:
                alerts.append(create_alert("AWS CloudTrail", "Console Login without MFA from Anomalous Country", "AuthAnomaly", "High", 82.0, "AWS-PROD-CLUSTER", username="cloud_admin", dest_ip="194.26.29.112", tactic="Initial Access", tech_id="T1078", tech_name="Valid Accounts", time_offset_mins=15 + (i%10), crit=0.9))
            elif stage == 1:
                alerts.append(create_alert("Azure Sentinel", "Mass Access to KeyVault Secrets & Encryption Keys", "CredentialAccess", "Critical", 94.0, "AWS-PROD-CLUSTER", username="cloud_admin", tactic="Credential Access", tech_id="T1003.001", tech_name="Credential Dumping", time_offset_mins=28 + (i%12), crit=0.9))
            else:
                alerts.append(create_alert("Palo Alto NGFW", "High-Volume S3 Bucket Data Sync to External Storage", "DataExfiltration", "Critical", 97.0, "AWS-PROD-CLUSTER", username="cloud_admin", dest_ip="194.26.29.112", tactic="Exfiltration", tech_id="T1048.003", tech_name="Exfiltration Over Alternative Protocol", time_offset_mins=42 + (i%15), crit=0.9))

        # ---------------------------------------------------------
        # MAJOR CAMPAIGN 3: Executive Workstation DLL Injection & C2 (150 alerts)
        # ---------------------------------------------------------
        for i in range(150):
            alerts.append(create_alert("CrowdStrike Falcon", "In-Memory DLL Injection into Explorer.exe", "ProcessInjection", "High", 86.0, "WORKSTATION-04", username="david.kim", process_name="rundll32.exe", cmd="rundll32.exe C:\\Temp\\update.dll,Run", tactic="Privilege Escalation", tech_id="T1055", tech_name="Process Injection", time_offset_mins=20 + (i%20), crit=0.6))

        # ---------------------------------------------------------
        # 32 MODERATE & SPECIFIC ENDPOINT INCIDENT CLUSTERS (~2,000 alerts)
        # Spanning unique hosts WORKSTATION-02..05, FILE-SRV-01, DB-PRIMARY-01, DEV-HOST-01..25
        # ---------------------------------------------------------
        moderate_clusters = [
            ("DB-PRIMARY-01", "dba_admin", "Database Query Spike: SELECT * from credit_cards", "Collection", "T1560.001", "Archive Collected Data", "Critical", 92.0, 0.95, 70),
            ("BACKUP-SRV-01", "svc_backup", "Unauthorized Snapshot Purge Command via PowerShell", "Impact", "T1490", "Inhibit System Recovery", "High", 84.0, 0.85, 60),
            ("APP-PROD-02", "svc_appdeploy", "Log4j / Remote Code Execution Probe against Web App", "Initial Access", "T1190", "Exploit Public Application", "High", 80.0, 0.8, 65),
            ("VPN-GW-01", "svc_vpn", "High-Velocity Password Spray against Corporate SSO", "CredentialAccess", "T1110.003", "Password Spraying", "High", 78.0, 0.75, 75),
            ("WORKSTATION-02", "bob.chen", "Suspicious GitHub Token Creation & Repository Clone", "Exfiltration", "T1048.003", "Exfiltration Over Non-C2", "Medium", 65.0, 0.5, 55),
            ("WORKSTATION-03", "carol.white", "Macro Execution in Word Document from External Email", "Execution", "T1059.003", "Windows Command Shell", "Medium", 58.0, 0.5, 50),
            ("WORKSTATION-05", "eva.green", "Anomalous USB Device Insertion with AutoRun Execution", "Initial Access", "T1078", "Valid Accounts", "Medium", 55.0, 0.5, 45),
        ]

        # Add 25 dedicated developer endpoint clusters
        for d in range(1, 26):
            dev_host = f"DEV-LAPTOP-{d:02d}"
            dev_user = f"developer.{d:02d}"
            rule = random.choice([
                "Anomalous Python Script Port Scanning Local Subnet",
                "Unsigned Kernel Driver Loaded via Dev Mode",
                "Excessive Failed SSH Logins to Internal Bastion",
                "Unusual Curl Download of Executable Shell Script",
                "DNS Tunneling Query Pattern Detected to Dynamic Zone",
                "Tampering with Security Agent Registry Keys"
            ])
            tactic = random.choice(["Discovery", "Execution", "Defense Evasion", "Command and Control", "Credential Access"])
            tid = "T1059.001" if tactic == "Execution" else "T1018"
            moderate_clusters.append((dev_host, dev_user, rule, tactic, tid, rule.split(":")[0], "Medium", 60.0, 0.45, random.randint(45, 75)))

        for h_name, user, rule, tactic, tid, tname, sev, s_score, crit, count in moderate_clusters:
            t_base = random.randint(10, 100)
            for j in range(count):
                alerts.append(create_alert(
                    source=random.choice(SOURCES),
                    rule_name=rule,
                    event_type="SecurityTelemetry",
                    severity=sev,
                    sev_score=s_score,
                    src_host=h_name,
                    username=user,
                    tactic=tactic,
                    tech_id=tid,
                    tech_name=tname,
                    time_offset_mins=t_base + (j % 25),
                    crit=crit
                ))

        # ---------------------------------------------------------
        # REMAINING: Fill up to exact 3,000 alerts with isolated noise
        # ---------------------------------------------------------
        cur_count = len(alerts)
        needed = 3000 - cur_count
        for k in range(needed):
            ephem_host = f"GUEST-NET-{k % 8:02d}"
            alerts.append(create_alert(
                source=random.choice(SOURCES),
                rule_name="Routine Vulnerability Scan / ICMP Ping Sweep",
                event_type="NoiseEvent",
                severity="Informational",
                sev_score=5.0,
                src_host=ephem_host,
                username=None,
                tactic="Discovery",
                tech_id="T1018",
                tech_name="Remote System Discovery",
                time_offset_mins=random.randint(5, 180),
                crit=0.2
            ))

        alerts.sort(key=lambda x: x["timestamp"])
        return alerts[:3000]
