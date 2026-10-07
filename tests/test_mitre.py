import pytest
from backend.engine.mitre import MitreMapper

def test_mitre_mapping_heuristics():
    # Test ransomware detection
    res1 = MitreMapper.map_alert_to_technique("WannaCry Mass File Encryption", "FileEvent")
    assert res1["tactic"] == "Impact"
    assert res1["id"] == "T1486"

    # Test LSASS Mimikatz
    res2 = MitreMapper.map_alert_to_technique("Memory Scan", "ProcessAccess", command_line="sekurlsa::logonpasswords")
    assert res2["tactic"] == "Credential Access"
    assert res2["id"] == "T1003.001"

    # Test lateral movement via psexec
    res3 = MitreMapper.map_alert_to_technique("Admin Share Connection", "NetworkShare", command_line="psexec.exe \\\\dc-01")
    assert res3["tactic"] == "Lateral Movement"
    assert res3["id"] == "T1021.002"

def test_kill_chain_progression():
    tactics = ["Lateral Movement", "Initial Access", "Impact", "Execution"]
    analysis = MitreMapper.analyze_kill_chain_progression(tactics)
    
    assert analysis["stage_count"] == 4
    assert analysis["ordered_tactics"][0] == "Initial Access"
    assert analysis["ordered_tactics"][-1] == "Impact"
    assert analysis["is_advanced_campaign"] is True
