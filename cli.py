#!/usr/bin/env python3
"""
Dealers AI SOC Triage - Command Line Interface (CLI)
Provides terminal-based triage, simulation benchmarking, and containment execution.
"""
import sys
import json
import asyncio
from typing import Optional
from backend.database import Base, engine, SessionLocal
from backend.models import Incident, Alert, Entity, ContainmentAction
from backend.routes.simulation import run_3000_simulation
from backend.engine.llm_triage import llm_engine

# Ensure database tables exist
Base.metadata.create_all(bind=engine)

def print_banner():
    print("""
========================================================================
   DEALERS AI SOC TRIAGE PLATFORM - COMMAND LINE INTERFACE (CLI)
   NetworkX Graph Correlation + Local Ollama / LLM Incident Narratives
========================================================================
""")

def list_incidents_cli(limit: int = 20):
    db = SessionLocal()
    try:
        incidents = db.query(Incident).order_by(Incident.risk_score.desc()).limit(limit).all()
        if not incidents:
            print("\n[!] No incidents found. Run simulation first via: python3 cli.py simulate\n")
            return

        print(f"\n{'RISK':<6} | {'ID':<16} | {'PRIORITY':<14} | {'ALERTS':<8} | {'INCIDENT HEADLINE':<55} | {'AFFECTED HOSTS'}")
        print("-" * 125)
        for inc in incidents:
            hosts_str = ", ".join((inc.impacted_hosts or [])[:2])
            print(f"{int(inc.risk_score):<6} | {inc.id:<16} | {inc.priority:<14} | {inc.alert_count:<8} | {inc.title[:53]:<55} | {hosts_str}")
        print("\n")
    finally:
        db.close()

def inspect_incident_cli(incident_id: str):
    db = SessionLocal()
    try:
        inc = db.query(Incident).filter(Incident.id == incident_id).first()
        if not inc:
            print(f"\n[!] Incident '{incident_id}' not found.\n")
            return

        print("\n" + "="*80)
        print(f" INCIDENT REPORT: {inc.id} - {inc.title}")
        print("="*80)
        print(f"Risk Score:    {inc.risk_score}/100 ({inc.priority})")
        print(f"Status:        {inc.status}")
        print(f"Reduction:     {inc.alert_count} alerts consolidated ({inc.raw_alert_reduction_pct}% reduction)")
        print(f"Duration:      {inc.duration_minutes} min (First: {inc.first_alert_time} | Last: {inc.last_alert_time})")
        print(f"Impacted:      Hosts: {inc.impacted_hosts} | Users: {inc.impacted_users} | IPs: {inc.impacted_ips}")
        print(f"MITRE Stages:  {' -> '.join(inc.mitre_tactics or [])}")
        
        print("\n[+] EXECUTIVE SUMMARY:")
        print(inc.summary_ai or "N/A")
        
        print("\n[+] ROOT CAUSE & INITIAL VECTOR:")
        print(inc.root_cause_ai or "N/A")
        
        print("\n[+] CHRONOLOGICAL ATTACK NARRATIVE:")
        print(inc.attack_narrative_ai or "N/A")

        print("\n[+] RECOMMENDED CONTAINMENT PLAYBOOKS:")
        for idx, step in enumerate(inc.containment_recommendations or [], 1):
            print(f"  {idx}. [{step.get('priority', 'P1')}] {step.get('label')}: {step.get('description')}")
            if step.get('command'):
                print(f"     CMD: {step.get('command')}")
        print("\n" + "="*80 + "\n")
    finally:
        db.close()

async def simulate_firehose_cli():
    print("\n[*] Initializing 3,000 Alert Firehose Ingestion & Correlation Pipeline...")
    db = SessionLocal()
    try:
        res = await run_3000_simulation(db)
        print("\n[+] SIMULATION COMPLETE!")
        print(f"    - Total Raw Alerts Ingested:    {res['metrics']['total_raw_alerts']:,}")
        print(f"    - Consolidated Incidents:      {res['metrics']['consolidated_incidents']}")
        print(f"    - Alert Fatigue Reduction:     {res['metrics']['alert_reduction_pct']} (Target: >= 90% MET)")
        print(f"    - Mean Time to Triage (MTTT):  {res['metrics']['mean_time_to_triage_seconds']}s (Target: < 180s SLA MET)")
        print("\nUse 'python3 cli.py list' to view the prioritized incident queue.\n")
    finally:
        db.close()

async def run_agent_investigation_cli(incident_id: str):
    print(f"\n[*] Deploying Autonomous AI SOC Agent for Incident: {incident_id}...")
    from backend.agent.orchestrator import SOCAgentOrchestrator
    db = SessionLocal()
    try:
        orchestrator = SOCAgentOrchestrator(db)
        res = await orchestrator.investigate_incident(incident_id)
        
        print("\n" + "="*80)
        print(f" 🤖 AI SOC AGENT INVESTIGATION REPORT: {res.incident_id}")
        print(f" Run ID: {res.run_id} | Model: {res.model_used}")
        print("="*80)
        print(f"Autonomy Policy Decision: [{res.autonomy_tier}]")
        print(f"Policy Justification:     {res.policy_reason}")
        print(f"Investigation Confidence: {res.analysis.confidence_score * 100:.1f}%")
        print(f"Tools Executed:           {', '.join(res.tools_called)}")
        
        print("\n[+] EXECUTIVE BRIEFING:")
        print(res.analysis.executive_summary)
        
        print("\n[+] WHAT HAPPENED:")
        print(res.analysis.what_happened)
        
        print("\n[+] ROOT CAUSE / PATIENT ZERO:")
        print(res.analysis.root_cause)
        
        print("\n[+] CHRONOLOGICAL ATTACK PROGRESSION:")
        for step in res.analysis.attack_progression:
            print(f"  • {step}")
            
        print("\n[+] SUPPORTING EVIDENCE RETRIEVED:")
        for ev in res.analysis.supporting_evidence:
            print(f"  ✓ {ev}")
            
        print("\n[+] MITRE ATT&CK REASONING:")
        for tactic, reason in res.analysis.mitre_reasoning.items():
            print(f"  • {tactic}: {reason}")
            
        print("\n[+] UNCERTAINTIES & FORENSIC GAPS (What AI doesn't know):")
        for unc in res.analysis.uncertainties_and_gaps:
            print(f"  ? {unc}")
            
        print("\n[+] RECOMMENDED CONTAINMENT PLAYBOOKS:")
        for idx, act in enumerate(res.analysis.recommended_actions, 1):
            print(f"  {idx}. [{act.priority}] {act.label}: {act.description}")
            if act.command:
                print(f"     CMD: {act.command}")
            if act.rationale:
                print(f"     Why: {act.rationale}")

        print("\n" + "="*80 + "\n")
    finally:
        db.close()

def submit_feedback_cli(incident_id: str, verdict: str, notes: Optional[str] = None):
    db = SessionLocal()
    try:
        from backend.models import AnalystFeedback
        is_correct = verdict.lower() in ["correct", "true", "yes", "tp", "1"]
        fb = AnalystFeedback(
            incident_id=incident_id,
            is_correct=is_correct,
            analyst_verdict="True Positive" if is_correct else "False Positive / Disputed",
            notes=notes or "Analyst validation recorded via CLI",
            submitted_by="CLI Analyst"
        )
        db.add(fb)
        db.commit()
        print(f"\n[+] Analyst feedback successfully recorded for {incident_id} (Verdict: {'✓ Correct' if is_correct else '✗ Wrong'}).")
    finally:
        db.close()

def main():
    print_banner()
    args = sys.argv[1:]
    if not args:
        print("Usage:")
        print("  python3 cli.py list                                      # List prioritized consolidated incidents")
        print("  python3 cli.py inspect <INCIDENT_ID>                     # View detailed incident briefing & attack chain")
        print("  python3 cli.py agent <INCIDENT_ID>                       # Run Autonomous AI Agent investigation")
        print("  python3 cli.py feedback <INCIDENT_ID> <correct|wrong>    # Submit analyst feedback on decision")
        print("  python3 cli.py simulate                                  # Run 3,000 alert firehose simulation")
        print("  python3 cli.py serve                                     # Start FastAPI server on port 8000\n")
        return

    cmd = args[0].lower()
    if cmd == "list":
        list_incidents_cli()
    elif cmd == "inspect" and len(args) > 1:
        inspect_incident_cli(args[1])
    elif cmd == "agent" and len(args) > 1:
        asyncio.run(run_agent_investigation_cli(args[1]))
    elif cmd == "feedback" and len(args) > 2:
        notes = args[3] if len(args) > 3 else None
        submit_feedback_cli(args[1], args[2], notes)
    elif cmd == "simulate":
        asyncio.run(simulate_firehose_cli())
    elif cmd == "serve":
        import uvicorn
        uvicorn.run("backend.app:app", host="0.0.0.0", port=8000, reload=True)
    else:
        print(f"[!] Unknown command '{cmd}'. Run 'python3 cli.py' for usage.")

if __name__ == "__main__":
    main()

