# 🛡️ Dealers AI SOC Triage System & Autonomous AI Agent
### Solving the Alert Fatigue Crisis: 3,000 Raw Alerts &rarr; One Empowered Analyst

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)
[![NetworkX](https://img.shields.io/badge/Graph_Engine-NetworkX-005571?style=flat)](https://networkx.org/)
[![Ollama](https://img.shields.io/badge/AI_Engine-Ollama_Llama3-black?style=flat)](https://ollama.ai/)
[![MITRE ATT&CK](https://img.shields.io/badge/Matrix-MITRE_ATT%26CK-red?style=flat)](https://attack.mitre.org/)
[![Status](https://img.shields.io/badge/Alert_Reduction-98.6%25-brightgreen?style=flat)](#)
[![MTTT](https://img.shields.io/badge/MTTT-%3C_3_Minutes-cyan?style=flat)](#)
[![Tests](https://img.shields.io/badge/Tests-38%2F38_Passing-success?style=flat)](#)

---

## 📌 Executive Summary

Modern Security Operations Centers (SOCs) face an existential crisis: **alert fatigue**. A single security analyst is bombarded with **3,000+ un-correlated alerts per day** across disparate telemetry feeds (*CrowdStrike, Suricata, AWS CloudTrail, Okta, Windows Sysmon, Palo Alto*). 

The **Dealers AI SOC Triage Platform** resolves this crisis using:
1. **NetworkX Graph Correlation**: Merges 3,000 daily alerts into ~35–42 unified multi-stage incident clusters (**98.6% volume reduction**).
2. **Dynamic Multi-Factor Risk Scoring**: Evaluates threat severity, blast radius, asset criticality tiers (Tier 0 to Tier 3), and MITRE progression.
3. **Autonomous AI Investigation Agent**: Uses read-only tool invocation to gather multi-source evidence, reconstruct attack timelines, pinpoint patient zero, identify uncertainties, and synthesize structured forensic analyses.
4. **Deterministic Autonomy Policy Engine**: Enforces rigid safety gates (`AUTO_RESOLVE`, `REVIEW_NEEDED`, `HUMAN_REQUIRED`). The LLM does *not* grant itself permissions.
5. **Decision Memory & Human-in-the-Loop Feedback**: Captures analyst validations (`Correct [✓]` / `Wrong [✗]`) to build a high-signal fine-tuning dataset.

---

## 🏛️ End-to-End System Architecture

```text
                               3,000 Heterogeneous Raw Alerts
                (CrowdStrike, Suricata, AWS, Okta, Sysmon, Palo Alto, DNS)
                                              ↓
               ┌─────────────────────────────────────────────────────────────┐
               │         UNIVERSAL TELEMETRY INGESTION & NORMALIZATION       │
               └──────────────────────────────┬──────────────────────────────┘
                                              ↓
               ┌─────────────────────────────────────────────────────────────┐
               │          NETWORKX GRAPH CORRELATION ENGINE                  │
               │  • 60-Minute Temporal Sliding Window                        │
               │  • Multi-Hop Entity Pivots (Host, User, External IP, Hash)  │
               └──────────────────────────────┬──────────────────────────────┘
                                              ↓
                       ~35–42 Consolidated Incident Clusters (98.6% Reduction)
                                              ↓
               ┌─────────────────────────────────────────────────────────────┐
               │          MULTI-FACTOR DYNAMIC RISK SCORING ENGINE           │
               │  • Threat Severity + Asset Criticality (Tier 0-3)           │
               │  • Blast Radius + MITRE Kill-Chain Multiplier               │
               └──────────────────────────────┬──────────────────────────────┘
                                              ↓
               ┌─────────────────────────────────────────────────────────────┐
               │                AUTONOMOUS AI SOC AGENT PIPELINE             │
               │                                                             │
               │  1. Safe Tool Invocation (Read-Only Registry):              │
               │     get_incident() • get_timeline() • get_asset_details()   │
               │     get_mitre_analysis() • search_related_incidents()       │
               │                                                             │
               │  2. AI Context Builder (Graph + Asset + Timeline Synthesis) │
               │                                                             │
               │  3. Structured LLM Reasoning (Ollama / Embedded Cyber AI):  │
               │     Exec Summary • Patient Zero • Evidence • Gaps • Actions │
               └──────────────────────────────┬──────────────────────────────┘
                                              ↓
               ┌─────────────────────────────────────────────────────────────┐
               │             DETERMINISTIC AUTONOMY POLICY ENGINE            │
               ├──────────────────────┬──────────────────────┬───────────────┤
               │   LOW RISK NOISE &   │     MEDIUM RISK      │  HIGH RISK /  │
               │   HIGH CONFIDENCE    │      ANOMALIES       │ TIER-0 ASSETS │
               │          ↓           │          ↓           │       ↓       │
               │     AUTO_RESOLVE     │    REVIEW_NEEDED     │ HUMAN_REQUIRED│
               │  (Auto-Suppression)  │  (Analyst Queued)    │(Approval Gate)│
               └──────────────────────┴──────────┬───────────┴───────────────┘
                                                 ↓
               ┌─────────────────────────────────────────────────────────────┐
               │             DECISION MEMORY & ANALYST FEEDBACK              │
               │  • Immutable Audit Trail: Run ID, Tools, Evidence, Policy   │
               │  • Human Analyst Validation: Correct [✓] / Wrong [✗] + Notes│
               └─────────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Capabilities & Modules

### 1. NetworkX Graph Correlation Engine (`backend/engine/correlation.py`)
* Constructs an **Alert-to-Alert Graph** where an edge exists if alerts share an entity pivot (*Hostname, Identity, External IP, Process Tree, File Hash, Domain*) within a **60-minute temporal sliding window**.
* Computes connected graph components to form distinct multi-stage incident clusters.
* Generates interactive **Graph Topology Payloads** (`nodes` and `edges` with color codes and metadata) ready for frontend visualization.

### 2. Multi-Factor Dynamic Risk Scorer (`backend/engine/risk_scorer.py`)
* Composite risk formula ($0–100$):
  $$\text{Risk} = \text{Threat Severity} \times \text{Asset Weight} \times \text{Blast Multiplier} \times \text{MITRE Multiplier}$$
* **Asset Criticality Tiers**:
  * **Tier 0 (1.0)**: Domain Controllers (`DC-PROD-01`), Key Vaults, Production Databases.
  * **Tier 1 (0.8)**: Core Application Servers, API Gateways, Backup Cores.
  * **Tier 2 (0.5)**: Corporate Workstations, Developer Laptops, VPN Gateways.
  * **Tier 3 (0.2)**: Guest Subnets, Lab Sandboxes.
* Classifies priority tiers: `P1 - Critical`, `P2 - High`, `P3 - Medium`, `P4 - Low`.

### 3. MITRE ATT&CK Kill-Chain Engine (`backend/engine/mitre.py`)
* Maps alerts across the 14 MITRE tactics (*Initial Access &rarr; Execution &rarr; Persistence &rarr; Privilege Escalation &rarr; Defense Evasion &rarr; Credential Access &rarr; Discovery &rarr; Lateral Movement &rarr; Collection &rarr; Command and Control &rarr; Exfiltration &rarr; Impact*).
* Includes automated heuristic rule inferencing from command lines and process names.

### 4. Autonomous AI SOC Agent (`backend/agent/`)
* **Read-Only Tool Registry (`backend/agent/tools.py`)**: Safe data queries (`get_incident`, `get_related_alerts`, `get_timeline`, `get_asset_details`, `get_mitre_analysis`, `search_related_incidents`, `get_containment_history`).
* **Context Builder (`backend/agent/context_builder.py`)**: Synthesizes graph topology, asset tiers, and timeline telemetry into clean LLM prompts.
* **Structured Reasoning Engine (`backend/agent/orchestrator.py`)**: Direct integration with local/Azure **Ollama (Llama 3 / Mistral)** paired with an **Embedded Cyber AI Reasoning Fallback** ensuring 100% operational uptime.
* **Structured Output Schema (`backend/schemas/agent.py`)**:
  * `executive_summary`: Plain-English leadership briefing.
  * `what_happened`: Deep technical attack narrative.
  * `root_cause`: Patient zero entry vector and initial compromise mechanics.
  * `attack_progression`: Ordered step-by-step kill-chain timeline.
  * `supporting_evidence`: Concrete command lines, file hashes, and network callbacks.
  * `mitre_reasoning`: Contextual technique justifications.
  * `affected_assets`: Full list of impacted hosts/users with criticality tiers.
  * `recommended_actions`: Prioritized containment playbooks with shell/PowerShell commands.
  * `confidence_score`: Metric from $0.0$ to $1.0$.
  * `uncertainties_and_gaps`: Explicit list of what the AI cannot confirm or still doesn't know.

### 5. Deterministic Autonomy Policy Engine (`backend/agent/policy_engine.py`)
* **`HUMAN_REQUIRED`**: High Risk ($ \ge 65.0 $), Tier-0 asset involvement, destructive tactics (`Impact`, `Credential Access`, `Lateral Movement`), or active containment recommendations (*host isolation, token revocation*).
* **`AUTO_RESOLVE`**: Low Risk ($ \le 30.0 $) + High Confidence ($ \ge 0.90 $) + Benign noise/routine scanner probes.
* **`REVIEW_NEEDED`**: Medium risk anomalies queued for analyst validation.

### 6. Decision Memory & Analyst Feedback (`backend/models/agent_audit.py`)
* Persists every agent run in `agent_investigation_runs` (tools called, evidence gathered, raw AI output, confidence, policy decision).
* Stores analyst feedback in `analyst_feedback` (`Correct [✓]` / `Wrong [✗]`, verdict, notes).

---

## 🚀 Quickstart Guide

### 1. Prerequisites & Installation
* **Python 3.10+**
* Clone repository and install dependencies:
```bash
pip3 install -r requirements.txt
```

### 2. Start REST API Server
```bash
python3 run.py
```
* **Interactive Swagger UI**: `http://localhost:8000/docs`
* **ReDoc Documentation**: `http://localhost:8000/redoc`

### 3. Command-Line Interface (CLI)

```bash
# 1. List prioritized consolidated incident queue
python3 cli.py list

# 2. Run Autonomous AI SOC Agent investigation on an incident
python3 cli.py agent INC-20261001-001

# 3. Inspect deep incident briefing & attack chain
python3 cli.py inspect INC-20261001-001

# 4. Submit analyst feedback on AI decision
python3 cli.py feedback INC-20261001-001 correct "Accurate patient-zero root cause"

# 5. Run 3,000 alert firehose simulation benchmark
python3 cli.py simulate

# 6. Boot the REST API server via CLI
python3 cli.py serve
```

### 4. Run Automated Test Suite
```bash
python3 -m pytest tests/ -v
```
* **38/38 pytest test cases passing** (Agent tools, context builder, autonomy policy engine, scenario evaluations, cockpit endpoints, RBAC permissions, SSH forensics & containment, REST endpoints, graph correlation, MITRE heuristics, risk scoring).

---

## 🎯 Autonomous DFIR Workflow with Graduated Autonomy

The platform executes a dynamic **Digital Forensics and Incident Response (DFIR)** investigation workflow on correlated alert clusters:

```text
ALERT FIREHOSE (3,000 alerts)
         ↓
NETWORKX GRAPH CORRELATION (98.6% volume reduction)
         ↓
AI SOC INVESTIGATION AGENT
 ├─ Step 1: Query Parent-Child Process Lineage (collect_process_tree)
 ├─ Step 2: Enumerate Listening Sockets & Outbound C2 Beacons (collect_network_sockets)
 ├─ Step 3: Inspect Authentication Logs & Privileged Escalation (collect_auth_logs)
 ├─ Step 4: Cryptographic File Hash & VirusTotal Correlation (inspect_file_hash)
 ├─ Step 5: Multi-Hop Lateral Spread & Historical Incident Memory (search_related_incidents)
 └─ Step 6: 14-Stage MITRE ATT&CK Kill-Chain Mapping & Sigma Rule Generation
         ↓
DETERMINISTIC AUTONOMY POLICY ENGINE
         ↓
┌───────────────────────┬───────────────────────┬───────────────────────┐
│       LOW RISK        │      MEDIUM RISK      │       HIGH RISK       │
│  (Noise / Scanners)   │  (Internal Anomaly)   │ (Ransomware / Tier-0) │
│           ↓           │           ↓           │           ↓           │
│     AUTO_RESOLVE      │     REVIEW_NEEDED     │    HUMAN_REQUIRED     │
│   (Auto-Suppression)  │   (Senior Analyst)    │   (Approval Gate)     │
└───────────────────────┴───────────────────────┴───────────────────────┘
         ↓
RBAC & CONTAINMENT WALL (Remediation is NEVER directly executed by the LLM)
 ├─ Allowlisted Commands Staged for One-Click Approval (isolate_host_firewall, block_ip, kill_process)
 └─ Immutable Compliance Audit Log (SSHAuditRecord)
```

### 🧪 Dry-Run / Agent Simulation Mode
Pass `?dry_run=true` to demonstrate the complete autonomous investigation, forensic telemetry assembly, policy evaluation, and staged mitigation commands **without modifying live machine state**:

```bash
# Dry-Run Autonomous Investigation
curl -X POST "http://localhost:8000/api/agent/investigate/INC-20261001-001?dry_run=true" \
  -H "X-User-Email: senior.analyst@company.com" \
  -H "X-User-Role: SENIOR_ANALYST"
```

#### Complete Structured JSON Response Payload:
```json
{
  "incident_id": "INC-20261001-001",
  "dry_run": true,
  "autonomy_tier": "HUMAN_REQUIRED",
  "policy_reasoning": "High Composite Risk Score (88.5/100) involving Tier-0 Asset DC-PROD-01 and destructive Ransomware tactics.",
  "executive_summary": "Active multi-stage ransomware execution detected on DC-PROD-01 initiated via suspicious PowerShell download from 185.220.101.5.",
  "root_cause": "Phishing lure executed by user jdoe executing unvetted macro dropper.",
  "forensic_playbook_trace": [
    {
      "step": 1,
      "tool": "collect_process_tree",
      "target_host": "DC-PROD-01",
      "findings": "Detected powershell.exe -enc spawning vssadmin.exe delete shadows /all /quiet"
    },
    {
      "step": 2,
      "tool": "collect_network_sockets",
      "target_host": "DC-PROD-01",
      "findings": "Active outbound TCP socket on port 4444 connected to 185.220.101.5"
    },
    {
      "step": 3,
      "tool": "collect_auth_logs",
      "target_host": "DC-PROD-01",
      "findings": "Event 4624 Type 10 (RemoteInteractive) from unknown internal IP"
    },
    {
      "step": 4,
      "tool": "inspect_file_hash",
      "target_host": "DC-PROD-01",
      "findings": "SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 matches LockBit 3.0 IOC"
    }
  ],
  "staged_remediation_commands": [
    {
      "command": "isolate_host_firewall",
      "host": "DC-PROD-01",
      "description": "Block all inbound/outbound traffic except SSH/SOC management subnet",
      "requires_role": "SOC_LEAD_ADMIN / SENIOR_ANALYST"
    },
    {
      "command": "kill_process --pid 1842",
      "host": "DC-PROD-01",
      "description": "Terminate rogue encryptor process",
      "requires_role": "SOC_LEAD_ADMIN"
    },
    {
      "command": "block_remote_ip --ip 185.220.101.5",
      "host": "DC-PROD-01",
      "description": "Block external C2 communication at perimeter firewall",
      "requires_role": "SOC_LEAD_ADMIN"
    }
  ],
  "sigma_rule": "title: Detect Suspicious Encoded PowerShell C2\\nstatus: production\\nlogsource:\\n  category: process_creation\\n  product: windows\\ndetection:\\n  selection:\\n    CommandLine|contains: 'powershell -enc'\\n  condition: selection\\nlevel: high",
  "confidence_score": 0.96,
  "affected_assets": [
    {"name": "DC-PROD-01", "type": "host", "criticality_tier": "Tier 0 (Domain Controller)"}
  ]
}
```

---

## 👥 Role-Based Access Control (RBAC) Matrix

The backend enforces role-based permission scopes across all API endpoints:

| Permission Scope | `SOC_LEAD_ADMIN` | `SENIOR_ANALYST` (Tier 2) | `TIER1_ANALYST` | `AUDITOR` |
| :--- | :---: | :---: | :---: | :---: |
| **View Dashboard & Incident Queues** | ✅ | ✅ | ✅ | ✅ |
| **View Telemetry Alerts & Copilot Chat** | ✅ | ✅ | ✅ | ❌ |
| **Submit Analyst Decision Feedback** | ✅ | ✅ | ✅ | ❌ |
| **Trigger Autonomous AI Investigations** | ✅ | ✅ | ❌ | ❌ |
| **Execute Remote SSH Live Forensics** | ✅ | ✅ | ❌ | ❌ |
| **Execute One-Click Host Isolation & Containment** | ✅ | ✅ | ❌ | ❌ |
| **Execute Remote SSH Firewall / Process Kill Remediation** | ✅ | ❌ | ❌ | ❌ |
| **Manage SOC Analyst Accounts & Override Policy** | ✅ | ❌ | ❌ | ❌ |

*Authentication Headers*: Clients pass `X-User-Email` and `X-User-Role` (or `Authorization: Bearer <token>`).

---

## 🔐 SSH Remote DFIR & Remediation Engine

The platform features an enterprise remote SSH execution subsystem (`backend/engine/ssh_engine.py`) designed for secure, allowlisted endpoint diagnostics and containment:

* **Live Paramiko & High-Fidelity Simulated Telemetry**: Connects directly to enterprise endpoints or generates realistic host forensic states (`WORKSTATION-01`, `DC-PROD-01`, `APP-SRV-01`) matching active incident contexts.
* **Strict Command Allowlisting**: Only vetted diagnostic templates can be executed (`collect_process_tree`, `collect_network_sockets`, `collect_auth_logs`, `check_open_ports`, `inspect_file_hash`, `list_active_sessions`, `isolate_host_firewall`, `kill_process`, `block_remote_ip`).
* **Injection Defense & Parameter Sanitization**: Blocks metacharacters (`;`, `|`, `&`, `\``, `$`, `\n`) to prevent arbitrary command injection.
* **Immutable Compliance Audit Trail**: Every command executed remotely is logged into the `SSHAuditRecord` table with operator email, role, target host, exact raw command, stdout/stderr, and exit code.

---

## 🖥️ Frontend Cockpit Integration Guide

The backend provides tailored endpoints for the frontend team to build the 3-pane command center, live graphs, and real-time streams without calculating any metrics on the client:

### 1. Single-Call 3-Pane Dashboard Payload: `GET /api/cockpit/summary`
Delivers all required KPI cards, prioritized incidents list, recent containment actions, and telemetry breakdown in a single call.

### 2. Cytoscape / React Flow Graph Topology: `GET /api/cockpit/graph/{incident_id}`
Returns pre-styled node objects (with entity types, colors, and icons) and directed edge connections (`logged_in`, `executed_cmd`, `c2_beacon`, `lateral_pivot`).

### 3. Server-Sent Events (SSE) Live Feed: `GET /api/cockpit/stream`
Push notifications for live telemetry volume updates and autonomous agent milestones every 3 seconds:
```javascript
const eventSource = new EventSource("http://localhost:8000/api/cockpit/stream");
eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log("Live SOC Update:", data);
};
```

---

## 🔌 Complete REST API Reference

### Authentication & RBAC Roles
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/auth/me` | Retrieve authenticated user profile, role, and granted permission list |
| `GET` | `/api/auth/roles` | List all available SOC roles and permission scope matrix |
| `GET` | `/api/auth/users` | List registered enterprise SOC analysts and operators |

### SSH Remote Forensics & Remediation
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/ssh/commands` | List all allowlisted forensic and containment commands with required permissions |
| `GET` | `/api/ssh/hosts` | Discoverable enterprise assets with SSH status, OS fingerprint, and asset tiers |
| `POST` | `/api/ssh/execute` | Execute allowlisted SSH command on remote host (RBAC guarded: forensics vs remediation) |
| `GET` | `/api/ssh/audit` | Query immutable audit log of all remote SSH command executions |

### Frontend Cockpit Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/cockpit/summary` | Single-call 3-pane dashboard payload (KPIs, incident queue, containment queue, telemetry distributions, health) |
| `GET` | `/api/cockpit/graph/{id}` | Formatted graph topology nodes & edges for Cytoscape.js / React Flow |
| `GET` | `/api/cockpit/stream` | Real-time Server-Sent Events (SSE) live telemetry stream |

### Autonomous AI Agent Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/agent/investigate/{incident_id}` | Trigger autonomous AI Agent investigation (tools, structured analysis, Sigma rule synthesis, autonomy tier) |
| `POST` | `/api/agent/feedback` | Record human analyst feedback (`Correct`/`Wrong`) for decision memory |
| `GET` | `/api/agent/runs/{incident_id}` | Fetch all historical investigation runs for an incident |
| `GET` | `/api/agent/run/{run_id}` | Retrieve full structured evidence and LLM reasoning for a specific audit run |
| `GET` | `/api/agent/feedback` | Retrieve analyst feedback dataset |

### Incident Management & Containment
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/incidents` | List & filter consolidated incidents by risk score, priority, status, search |
| `GET` | `/api/incidents/{id}` | Deep incident dossier (alerts, graph topology, AI briefing, MITRE stages) |
| `PATCH`| `/api/incidents/{id}` | Update incident status (`New`, `Triaging`, `Contained`, `Closed`) or assigned analyst |
| `POST` | `/api/incidents/{id}/triage-ai` | Trigger on-demand LLM narrative synthesis |
| `POST` | `/api/incidents/{id}/contain` | Execute one-click containment action (host isolation, token revocation, IP block, process kill) |

### Telemetry Ingestion & Simulation
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/alerts` | Query raw ingested telemetry events with search & entity filters |
| `GET` | `/api/alerts/{id}` | Get specific raw telemetry alert by ID |
| `POST` | `/api/alerts/ingest` | Ingest single alert into the universal schema with auto MITRE mapping |
| `POST` | `/api/alerts/batch-ingest` | Ingest batch alert payloads into the database |
| `POST` | `/api/simulate/run-3000` | Ingest and correlate 3,000 heterogeneous raw alerts with benchmark verification |

### SOC KPIs & Copilot
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | System health, database connection, correlation settings |
| `GET` | `/api/stats` | Real-time SOC KPIs (Volume reduction %, average MTTT, distributions, top targets) |
| `GET` | `/api/stats/evaluation/benchmark`| Accuracy benchmark evaluation against `ground_truth.csv` |
| `POST` | `/api/copilot/chat` | Interactive AI analyst query console for forensic investigations |

---

## 📁 Repository Structure

```text
3000 alerts, one analyst/
├── backend/
│   ├── agent/                      # 🤖 Autonomous AI SOC Agent
│   │   ├── __init__.py             # Agent exports
│   │   ├── context_builder.py      # Multi-vector AI context synthesis
│   │   ├── orchestrator.py         # Agent execution loop & structured output
│   │   ├── policy_engine.py        # Deterministic autonomy gates (AUTO / REVIEW / HUMAN)
│   │   └── tools.py                # Safe read-only investigation & SSH forensics tool registry
│   ├── auth/                       # 👥 Role-Based Access Control (RBAC) & Permissions
│   │   ├── __init__.py             # Auth exports
│   │   ├── dependencies.py         # FastAPI dependency injection guards (require_permission, require_role)
│   │   └── models.py               # UserRole, Permission scopes & RBAC matrix
│   ├── engine/                     # 🛡️ Core Correlation & Cyber Analytics
│   │   ├── correlation.py          # NetworkX graph correlation (60m sliding window)
│   │   ├── dataset_loader.py       # CSV dataset ingestion & ground truth evaluation
│   │   ├── llm_triage.py           # LLM briefing engine & embedded cyber AI fallback
│   │   ├── mitre.py                # 14-stage MITRE ATT&CK kill-chain mapper
│   │   ├── risk_scorer.py          # Multi-factor composite risk scoring formula
│   │   ├── simulator.py            # 3,000 alert firehose generator
│   │   └── ssh_engine.py           # Remote SSH forensic execution & containment engine
│   ├── models/                     # 🗄️ SQLAlchemy Database Models
│   │   ├── agent_audit.py          # AgentInvestigationRun & AnalystFeedback models
│   │   ├── alert.py                # Normalized Universal Alert model
│   │   ├── containment.py          # ContainmentAction audit model
│   │   ├── entity.py               # Host & User Asset Inventory model
│   │   ├── incident.py             # Consolidated Incident model
│   │   └── ssh_audit.py            # SSHAuditRecord immutable remote command log
│   ├── routes/                     # 🔌 FastAPI REST API Routers
│   │   ├── agent.py                # /api/agent investigation & feedback endpoints
│   │   ├── alerts.py               # /api/alerts query & ingestion endpoints
│   │   ├── auth.py                 # /api/auth user profile & RBAC role endpoints
│   │   ├── cockpit.py              # /api/cockpit dashboard summary, SSE stream, graph topology
│   │   ├── copilot.py              # /api/copilot chat endpoint
│   │   ├── incidents.py            # /api/incidents triage & containment endpoints
│   │   ├── simulation.py           # /api/simulate/run-3000 endpoint
│   │   ├── ssh.py                  # /api/ssh host discovery, remote command execution & audit
│   │   └── stats.py                # /api/stats KPI endpoints
│   ├── schemas/                    # 📋 Pydantic Validation Schemas
│   │   ├── agent.py                # Structured forensic output & feedback schemas
│   │   ├── alert.py                # Alert request/response schemas
│   │   ├── auth.py                 # User & role schemas
│   │   ├── incident.py             # Incident & containment schemas
│   │   ├── ssh.py                  # SSH request & host summary schemas
│   │   └── triage.py               # Copilot & SOC stats schemas
│   ├── app.py                      # FastAPI Application entrypoint & CORS setup
│   ├── config.py                   # Pydantic Settings & Environment Variables
│   └── database.py                 # SQLAlchemy Engine & SessionLocal setup
├── data/                           # Evaluation & asset inventory datasets
│   ├── assets.csv                  # Enterprise asset inventory with criticality (1-5)
│   ├── ground_truth.csv            # Ground truth scenario labels for benchmark evaluation
│   └── users.csv                   # Identity directory (departments, privileged flags)
├── soc_alerts_10k/                 # Full 10,000 alert synthetic benchmark dataset
│   ├── alerts.csv                  # 10,000 raw telemetry logs
│   ├── data_dictionary.md          # Dataset schema and scenario documentation
│   └── ground_truth.csv            # 10k ground truth scenario labels
├── tests/                          # 🧪 Automated Test Suite (38 tests)
│   ├── test_agent.py               # Agent tools, context builder, policy engine, memory tests
│   ├── test_agent_scenarios.py     # End-to-end evaluation suite (Benign, Suspicious, Malicious, Dry-Run)
│   ├── test_api.py                 # REST API endpoints, cockpit summary/graph, alert ingestion tests
│   ├── test_auth_rbac.py           # RBAC permission matrix, user profiles, and role guards
│   ├── test_correlation.py         # NetworkX temporal graph correlation tests
│   ├── test_mitre.py               # Kill-chain progression & heuristic mapping tests
│   ├── test_risk_scorer.py         # Composite risk calculation & asset weighting tests
│   └── test_ssh.py                 # SSH remote diagnostics, containment, sanitization & audit
├── cli.py                          # 💻 Interactive Terminal CLI Tool
├── Dockerfile                      # Backend container configuration
├── docker-compose.yml              # Multi-container deployment (FastAPI + Postgres + Ollama)
├── requirements.txt                # Python dependencies
└── run.py                          # FastAPI server launcher
```

---

## ⚙️ Configuration & Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | `sqlite:///./soc_triage.db` | Database connection string (SQLite or PostgreSQL) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama LLM endpoint (Local or Azure VM) |
| `OLLAMA_MODEL` | `llama3` | Primary LLM model (`llama3`, `mistral`, `deepseek-r1`) |
| `OLLAMA_FALLBACK_MODEL` | `mistral` | Fallback model if primary model is unavailable |
| `CORRELATION_WINDOW_MINUTES` | `60` | Temporal correlation sliding window in minutes |
| `GRAPH_SIMILARITY_THRESHOLD` | `0.45` | Minimum similarity threshold for entity graph linkage |
| `TARGET_REDUCTION_PCT` | `90.0` | Minimum target alert reduction percentage benchmark |
| `TARGET_MTTT_SECONDS` | `180` | Maximum target Mean Time To Triage SLA benchmark (3 minutes) |

---

## 🐳 Docker & Production Deployment

To boot the complete stack with containerized PostgreSQL and Ollama:
```bash
docker-compose up --build
```
This deploys:
1. **FastAPI Backend Server** on `http://localhost:8000`
2. **PostgreSQL Database** on `localhost:5432`
3. **Ollama Service** on `http://localhost:11434`

To stop the stack:
```bash
docker-compose down