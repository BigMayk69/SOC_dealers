# SOC Alert Dataset - Data Dictionary
Synthetic data. IPs are RFC 5737/1918, domains use the reserved .example TLD. Seeded and reproducible (generate_dataset.py).

## alerts.csv (model input)
alert_id (UUID) | timestamp (ISO 8601; ~1.5% carry a local UTC offset) | source (EDR, Azure AD, Firewall, Proxy, IDS, DNS, Windows Security, Cloud Audit, M365) | alert_name | description | severity (Low/Medium/High/Critical, deliberately noisy) | user | device_hostname | src_ip | dst_ip | dst_port | process_name | command_line | file_hash | url_or_domain | geo_country | asset_id | asset_criticality (1-5) | asset_type | mitre_tactic | mitre_technique_id | confidence (0-1) | is_duplicate_of (alert_id of original, ~8% rows) | threat_intel_match (bool) | anomaly_score (0-1)

## ground_truth.csv (evaluation only - do not feed to the model)
alert_id | label (benign / false_positive / attack) | incident_id (attack chains only) | scenario_name | attack_stage_order | duplicate_of

## assets.csv / users.csv
Asset inventory with criticality (domain controllers, finance DB, Key Vault = 5) and user directory (department, role, home country, privileged flag, workstation).

## Composition
70% benign, 20% false positive (includes 2 decoy chain types: patch night, authorized pentest), 10% attack (8 multi-stage scenarios: phishing, password spray, malware/C2/lateral/exfil, ransomware, insider theft, cloud identity compromise, web exploit, Kerberoast/DCSync). Includes one benign alert storm, ~8% duplicates, ~1.5% missing optional fields.
