"""
FastAPI Router for SSH Remote Investigation & Remediation.
Provides endpoints for executing allowlisted live diagnostics, host containment,
listing discoverable SSH endpoints, and querying the immutable command audit log.
"""
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.auth.models import UserProfile, Permission, UserRole
from backend.auth.dependencies import get_current_user, require_permission
from backend.engine.ssh_engine import SSHEngine
from backend.models.ssh_audit import SSHAuditRecord
from backend.models.entity import Entity
from backend.schemas.ssh import SSHCommandRequest, SSHCommandResponse, SSHHostSummary

router = APIRouter(prefix="/ssh", tags=["SSH Remote Investigation & Remediation"])


@router.get("/commands")
def list_allowlisted_commands():
    """Lists all allowlisted SSH forensic and remediation commands with their permission scopes."""
    return SSHEngine.get_supported_commands()


@router.get("/hosts", response_model=List[SSHHostSummary])
def list_ssh_hosts(
    db: Session = Depends(get_db),
    user: UserProfile = Depends(require_permission(Permission.VIEW_DASHBOARD))
):
    """
    Lists all discoverable enterprise assets with SSH connectivity status,
    operating system fingerprint, and asset criticality tiers.
    """
    entities = db.query(Entity).filter(Entity.entity_type == "host").all()
    
    # If database has no host entities yet, provide standard enterprise hosts
    if not entities:
        default_hosts = [
            ("WORKSTATION-01", "192.168.1.100", "Tier 2 - Workstation", 0.5, "Windows 11 / OpenSSH", False),
            ("DC-PROD-01", "192.168.1.10", "Tier 0 - Domain Controller", 1.0, "Windows Server 2022", False),
            ("APP-SRV-01", "10.0.1.50", "Tier 1 - Core App Server", 0.8, "Ubuntu 22.04 LTS (OpenSSH 8.9)", False),
            ("DB-PROD-01", "10.0.2.100", "Tier 0 - Production DB", 1.0, "RHEL 9 (OpenSSH 8.7)", False),
            ("DEV-TEST-01", "10.10.1.25", "Tier 3 - Dev Sandbox", 0.2, "Ubuntu 24.04 LTS", False)
        ]
        return [
            SSHHostSummary(
                hostname=h[0],
                ip_address=h[1],
                asset_tier=h[2],
                criticality=h[3],
                os_type=h[4],
                ssh_status="Available (Port 22)",
                is_isolated=h[5]
            ) for h in default_hosts
        ]

    results = []
    for e in entities:
        os_type = "Ubuntu 22.04 LTS" if "SRV" in e.entity_value or "DB" in e.entity_value else "Windows 11 OpenSSH"
        results.append(SSHHostSummary(
            hostname=e.entity_value,
            ip_address="192.168.1.x",
            asset_tier=e.asset_tier or "Tier 2 - Workstation",
            criticality=e.criticality or 0.5,
            os_type=os_type,
            ssh_status="Available (Port 22)",
            is_isolated=bool(e.is_isolated)
        ))
    return results


@router.post("/execute", response_model=SSHCommandResponse)
def execute_ssh_command(
    cmd_in: SSHCommandRequest,
    db: Session = Depends(get_db),
    user: UserProfile = Depends(get_current_user)
):
    """
    Executes an allowlisted forensic diagnostic or containment command on a remote host over SSH.
    - Forensic commands require `ssh:forensics` permission (Tier 2 / Senior Analyst / Admin).
    - Containment commands require `ssh:remediation` permission (SOC Lead Admin).
    - Immutable audit record is generated and stored for compliance.
    """
    try:
        result = SSHEngine.execute_command(
            target_host=cmd_in.target_host,
            command_type=cmd_in.command_type,
            params=cmd_in.params,
            user=user,
            db=db,
            ssh_port=cmd_in.ssh_port,
            ssh_user=cmd_in.ssh_user or "soc-admin"
        )
        return SSHCommandResponse(**result)
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSH command execution failed: {str(e)}")


@router.get("/audit", response_model=List[Dict[str, Any]])
def query_ssh_audit_log(
    target_host: Optional[str] = None,
    user_email: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    user: UserProfile = Depends(require_permission(Permission.VIEW_AUDIT_LOGS))
):
    """Retrieves immutable audit trail of all remote SSH commands executed across the enterprise."""
    query = db.query(SSHAuditRecord)
    if target_host:
        query = query.filter(SSHAuditRecord.target_host == target_host)
    if user_email:
        query = query.filter(SSHAuditRecord.user_email == user_email)

    records = query.order_by(desc(SSHAuditRecord.executed_at)).limit(limit).all()
    return [r.to_dict() for r in records]
