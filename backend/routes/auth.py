"""
FastAPI Router for Authentication, User Directory & RBAC Roles.
"""
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException

from backend.auth.models import UserRole, Permission, UserProfile, DEMO_SOC_USERS, ROLE_PERMISSIONS_MAP
from backend.auth.dependencies import get_current_user, require_role, require_permission
from backend.schemas.auth import UserResponse, RoleDetailResponse, SwitchRoleRequest

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC Roles"])

ROLE_DESCRIPTIONS = {
    UserRole.SOC_LEAD_ADMIN: "Full administrative and incident commander access. Can execute containment, isolate hosts, approve human-in-the-loop gates, and run remote SSH remediation.",
    UserRole.SENIOR_ANALYST: "Tier 2 Senior Incident Responder. Can trigger AI investigations, execute remote live SSH diagnostics, propose mitigations, and submit feedback.",
    UserRole.TIER1_ANALYST: "Tier 1 Frontline Triage Analyst. Can view alerts and incidents, chat with Copilot, review AI briefings, and submit feedback.",
    UserRole.AUDITOR: "Read-only auditor. Can review dashboards, historical investigation runs, and containment audit trails without modification rights."
}


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(user: UserProfile = Depends(get_current_user)):
    """Returns the authenticated user's profile, role, and granted permissions."""
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        department=user.department,
        permissions=user.permissions,
        is_active=user.is_active
    )


@router.get("/roles", response_model=List[RoleDetailResponse])
def list_system_roles():
    """Lists all available SOC roles along with their descriptions and granular permission scopes."""
    roles_list = []
    for role in UserRole:
        perms = [p.value for p in ROLE_PERMISSIONS_MAP.get(role, set())]
        roles_list.append(RoleDetailResponse(
            role=role,
            description=ROLE_DESCRIPTIONS.get(role, "Standard role"),
            permissions=sorted(perms)
        ))
    return roles_list


@router.get("/users", response_model=List[UserResponse])
def list_soc_users(
    user: UserProfile = Depends(require_permission(Permission.VIEW_DASHBOARD))
):
    """Lists registered enterprise SOC analysts and operators."""
    return [
        UserResponse(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            role=u.role,
            department=u.department,
            permissions=u.permissions,
            is_active=u.is_active
        )
        for u in DEMO_SOC_USERS.values()
    ]
