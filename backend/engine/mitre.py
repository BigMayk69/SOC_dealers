"""
MITRE ATT&CK Mapping & Kill-Chain Engine for Dealers AI SOC Triage
"""
from typing import Dict, List, Any, Optional

TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]

MITRE_TECHNIQUES_DB: Dict[str, Dict[str, Any]] = {
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "severity": "High",
        "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems."
    },
    "T1566.002": {
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "severity": "High",
        "description": "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems."
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "severity": "Critical",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program."
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "secondary_tactic": "Initial Access",
        "severity": "High",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion."
    },
    "T1059.001": {
        "name": "PowerShell Execution",
        "tactic": "Execution",
        "severity": "High",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution."
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "severity": "Medium",
        "description": "Adversaries may abuse the Windows command shell for execution."
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "Persistence",
        "severity": "High",
        "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code."
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "severity": "Medium",
        "description": "Adversaries may achieve persistence by adding a program to a Run key in the Registry or the Startup folder."
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Privilege Escalation",
        "secondary_tactic": "Defense Evasion",
        "severity": "Critical",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges."
    },
    "T1003.001": {
        "name": "LSASS Memory Dumping",
        "tactic": "Credential Access",
        "severity": "Critical",
        "description": "Adversaries may attempt to access credential material stored in the process memory of Local Security Authority Subsystem Service (LSASS)."
    },
    "T1110.003": {
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "severity": "High",
        "description": "Adversaries may use a single or small list of commonly used passwords against many different accounts."
    },
    "T1087.002": {
        "name": "Domain Account Discovery",
        "tactic": "Discovery",
        "severity": "Low",
        "description": "Adversaries may attempt to get a listing of domain accounts."
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "severity": "Low",
        "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier."
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol (RDP)",
        "tactic": "Lateral Movement",
        "severity": "High",
        "description": "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol."
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "severity": "Critical",
        "description": "Adversaries may use Valid Accounts to interact with remote computers over Server Message Block (SMB) and Windows Admin Shares."
    },
    "T1071.001": {
        "name": "Web Protocols C2 (HTTPS)",
        "tactic": "Command and Control",
        "severity": "High",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering."
    },
    "T1573.002": {
        "name": "Asymmetric Encrypted C2 Beacon",
        "tactic": "Command and Control",
        "severity": "Critical",
        "description": "Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic."
    },
    "T1560.001": {
        "name": "Archive Collected Data (7-Zip/WinRAR)",
        "tactic": "Collection",
        "severity": "Medium",
        "description": "An adversary may compress or encrypt data that is collected prior to exfiltration."
    },
    "T1048.003": {
        "name": "Exfiltration Over Unencrypted/Encrypted Non-C2 Protocol",
        "tactic": "Exfiltration",
        "severity": "Critical",
        "description": "Adversaries may steal data by exfiltrating it over an alternative network protocol, such as HTTPS, SFTP or Cloud Storage."
    },
    "T1486": {
        "name": "Data Encrypted for Impact (Ransomware)",
        "tactic": "Impact",
        "severity": "Critical",
        "description": "Adversaries may encrypt data on target systems to interrupt availability to system and network resources."
    },
    "T1490": {
        "name": "Inhibit System Recovery (vssadmin delete shadows)",
        "tactic": "Impact",
        "severity": "Critical",
        "description": "Adversaries may delete or remove built-in data and operating system recovery features to prevent rollback."
    }
}

class MitreMapper:
    @staticmethod
    def get_tactic_order_index(tactic: str) -> int:
        try:
            return TACTIC_ORDER.index(tactic)
        except ValueError:
            return 99

    @staticmethod
    def map_alert_to_technique(rule_name: str, event_type: str, command_line: Optional[str] = None) -> Dict[str, Any]:
        """Automatically infers MITRE Tactic and Technique from alert metadata if not explicitly provided"""
        rule_lower = (rule_name or "").lower()
        event_lower = (event_type or "").lower()
        cmd_lower = (command_line or "").lower()

        # Match specific indicators
        if "ransomware" in rule_lower or "encrypt" in rule_lower or ".locked" in cmd_lower:
            return {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"}
        if "vssadmin" in cmd_lower or "shadow" in cmd_lower or "inhibit recovery" in rule_lower:
            return {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"}
        if "exfiltration" in rule_lower or "data transfer" in event_lower or "cloud storage upload" in rule_lower:
            return {"id": "T1048.003", "name": "Exfiltration Over Non-C2 Protocol", "tactic": "Exfiltration"}
        if "c2" in rule_lower or "beacon" in rule_lower or "cobalt" in rule_lower or "sliver" in cmd_lower:
            return {"id": "T1573.002", "name": "Asymmetric Encrypted C2 Beacon", "tactic": "Command and Control"}
        if "smb" in rule_lower or "psexec" in cmd_lower or "admin$" in cmd_lower or "wmic /node" in cmd_lower:
            return {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"}
        if "rdp" in rule_lower or "mstsc" in cmd_lower:
            return {"id": "T1021.001", "name": "Remote Desktop Protocol (RDP)", "tactic": "Lateral Movement"}
        if "lsass" in cmd_lower or "mimikatz" in cmd_lower or "sekurlsa" in cmd_lower or "procdump" in cmd_lower:
            return {"id": "T1003.001", "name": "LSASS Memory Dumping", "tactic": "Credential Access"}
        if "password spray" in rule_lower or "brute force" in rule_lower:
            return {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access"}
        if "powershell" in cmd_lower or "encodedcommand" in cmd_lower or "iex" in cmd_lower:
            return {"id": "T1059.001", "name": "PowerShell Execution", "tactic": "Execution"}
        if "process injection" in rule_lower or "hollow" in rule_lower or "inject" in event_lower:
            return {"id": "T1055", "name": "Process Injection", "tactic": "Privilege Escalation"}
        if "phish" in rule_lower or "macro" in cmd_lower or "malicious document" in rule_lower:
            return {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"}
        if "exploit" in rule_lower or "cve-" in rule_lower:
            return {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
        if "recon" in rule_lower or "net user" in cmd_lower or "nltest" in cmd_lower:
            return {"id": "T1087.002", "name": "Domain Account Discovery", "tactic": "Discovery"}

        # Default fallback
        return {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution"}

    @staticmethod
    def analyze_kill_chain_progression(tactics: List[str]) -> Dict[str, Any]:
        """Calculates stage progression and kill-chain depth"""
        unique_tactics = list(dict.fromkeys(tactics))
        sorted_tactics = sorted(unique_tactics, key=MitreMapper.get_tactic_order_index)
        
        stages_count = len(sorted_tactics)
        has_initial_access = "Initial Access" in sorted_tactics
        has_credential_access = "Credential Access" in sorted_tactics or "Privilege Escalation" in sorted_tactics
        has_lateral_movement = "Lateral Movement" in sorted_tactics
        has_c2_or_exfil = "Command and Control" in sorted_tactics or "Exfiltration" in sorted_tactics
        has_impact = "Impact" in sorted_tactics

        is_advanced_campaign = stages_count >= 3 or (has_initial_access and (has_lateral_movement or has_impact or has_c2_or_exfil))
        
        return {
            "ordered_tactics": sorted_tactics,
            "stage_count": stages_count,
            "max_stage_name": sorted_tactics[-1] if sorted_tactics else "None",
            "is_advanced_campaign": is_advanced_campaign,
            "kill_chain_coverage_pct": round((stages_count / len(TACTIC_ORDER)) * 100, 1),
            "stages_status": {
                t: (t in sorted_tactics) for t in TACTIC_ORDER
            }
        }
