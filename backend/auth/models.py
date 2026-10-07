"""
Authentication & Role-Based Access Control (RBAC) Models & Permissions Matrix.
Defines SOC user roles, granular permission scopes, and user session profiles.
"""
from enum import Enum
from typing import List, Set, Dict
from pydantic import BaseModel, EmailStr, Field


class UserRole(str, Enum):
    SOC_LEAD_ADMIN = "SOC_LEAD_ADMIN"
    SENIOR_ANALYST = "SENIOR_ANALYST"
    TIER1_ANALYST = "TIER1_ANALYST"
    AUDITOR = "AUDITOR"


class Permission(str, Enum):
    # Read & Triage Scopes
    VIEW_DASHBOARD = "view:dashboard"
    VIEW_INCIDENTS = "view:incidents"
    VIEW_ALERTS = "view:alerts"
    VIEW_AUDIT_LOGS = "view:audit_logs"
    COPILOT_CHAT = "copilot:chat"
    SUBMIT_FEEDBACK = "agent:feedback"
    
    # Investigation Scopes
    INVESTIGATE_AGENT = "agent:investigate"
    EXECUTE_SSH_FORENSICS = "ssh:forensics"
    
    # High-Privilege Containment & Remediation Scopes
    EXECUTE_CONTAINMENT = "containment:execute"
    EXECUTE_SSH_REMEDIATION = "ssh:remediation"
    OVERRIDE_POLICY = "policy:override"
    MANAGE_USERS = "users:manage"


# Granular Permissions Matrix for Enterprise SOC Roles
ROLE_PERMISSIONS_MAP: Dict[UserRole, Set[Permission]] = {
    UserRole.SOC_LEAD_ADMIN: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_ALERTS,
        Permission.VIEW_AUDIT_LOGS,
        Permission.COPILOT_CHAT,
        Permission.SUBMIT_FEEDBACK,
        Permission.INVESTIGATE_AGENT,
        Permission.EXECUTE_SSH_FORENSICS,
        Permission.EXECUTE_CONTAINMENT,
        Permission.EXECUTE_SSH_REMEDIATION,
        Permission.OVERRIDE_POLICY,
        Permission.MANAGE_USERS
    },
    UserRole.SENIOR_ANALYST: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_ALERTS,
        Permission.VIEW_AUDIT_LOGS,
        Permission.COPILOT_CHAT,
        Permission.SUBMIT_FEEDBACK,
        Permission.INVESTIGATE_AGENT,
        Permission.EXECUTE_SSH_FORENSICS,
        Permission.EXECUTE_CONTAINMENT,  # Can execute standard containment
    },
    UserRole.TIER1_ANALYST: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_ALERTS,
        Permission.COPILOT_CHAT,
        Permission.SUBMIT_FEEDBACK,
    },
    UserRole.AUDITOR: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_ALERTS,
        Permission.VIEW_AUDIT_LOGS,
    }
}


class UserProfile(BaseModel):
    id: str
    email: str
    full_name: str
    role: UserRole
    department: str = "Cyber Security Operations"
    is_active: bool = True
    permissions: List[str] = Field(default_factory=list)

    @classmethod
    def create(cls, id: str, email: str, full_name: str, role: UserRole, department: str = "SOC"):
        perms = [p.value for p in ROLE_PERMISSIONS_MAP.get(role, set())]
        return cls(
            id=id,
            email=email,
            full_name=full_name,
            role=role,
            department=department,
            permissions=sorted(perms)
        )


# Seeded SOC Enterprise User Directory
DEMO_SOC_USERS: Dict[str, UserProfile] = {
    "admin@dealers.corp": UserProfile.create(
        id="USR-001",
        email="admin@dealers.corp",
        full_name="Alex Vance (SOC Commander)",
        role=UserRole.SOC_LEAD_ADMIN,
        department="SOC Operations & Incident Response"
    ),
    "senior.analyst@dealers.corp": UserProfile.create(
        id="USR-002",
        email="senior.analyst@dealers.corp",
        full_name="Sarah Connor (Senior Tier 2 DFIR)",
        role=UserRole.SENIOR_ANALYST,
        department="Incident Response & Threat Hunting"
    ),
    "tier1.analyst@dealers.corp": UserProfile.create(
        id="USR-003",
        email="tier1.analyst@dealers.corp",
        full_name="David Miller (Tier 1 Triage Analyst)",
        role=UserRole.TIER1_ANALYST,
        department="Frontline Triage"
    ),
    "auditor@dealers.corp": UserProfile.create(
        id="USR-004",
        email="auditor@dealers.corp",
        full_name="Elena Rostova (Compliance & Audit)",
        role=UserRole.AUDITOR,
        department="Governance, Risk & Compliance"
    ),
}
