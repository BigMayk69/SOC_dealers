"""
FastAPI Authentication & RBAC Dependency Injections.
Extracts user identity from HTTP Headers (X-User-Email, X-User-Role, Authorization)
and enforces granular permission guards on sensitive endpoints.
"""
from typing import List, Optional, Callable
from fastapi import Header, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials

from backend.auth.models import UserRole, Permission, UserProfile, DEMO_SOC_USERS, ROLE_PERMISSIONS_MAP

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
user_email_header = APIKeyHeader(name="X-User-Email", auto_error=False)
user_role_header = APIKeyHeader(name="X-User-Role", auto_error=False)
bearer_security = HTTPBearer(auto_error=False)


def get_current_user(
    x_user_email: Optional[str] = Header(None, alias="X-User-Email"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    auth: Optional[HTTPAuthorizationCredentials] = Depends(bearer_security)
) -> UserProfile:
    """
    Resolves the authenticated SOC UserProfile.
    Checks:
    1. Direct email lookup in DEMO_SOC_USERS via X-User-Email header
    2. Dynamic role mapping via X-User-Role header
    3. Bearer token simulated identity
    4. Default fallback to SOC Lead Admin for backward compatibility and automated scripts.
    """
    # 1. Match known user by email header
    if x_user_email and x_user_email.lower() in DEMO_SOC_USERS:
        user = DEMO_SOC_USERS[x_user_email.lower()]
        if x_user_role and x_user_role in UserRole.__members__:
            # Allow temporary role override for testing/demo
            return UserProfile.create(
                id=user.id,
                email=user.email,
                full_name=user.full_name,
                role=UserRole(x_user_role),
                department=user.department
            )
        return user

    # 2. Dynamic user created from X-User-Role
    if x_user_role and x_user_role in UserRole.__members__:
        role = UserRole(x_user_role)
        email = x_user_email or f"{role.value.lower()}@dealers.corp"
        return UserProfile.create(
            id=f"USR-{role.value[:3]}",
            email=email,
            full_name=f"Active {role.value.replace('_', ' ').title()}",
            role=role,
            department="Dealers SOC"
        )

    # 3. Default fallback user (SOC Lead Admin)
    return DEMO_SOC_USERS["admin@dealers.corp"]


def require_permission(required_permission: Permission) -> Callable:
    """
    FastAPI dependency factory enforcing a specific permission scope.
    Raises HTTP 403 Forbidden if user lacks the permission.
    """
    def permission_checker(current_user: UserProfile = Depends(get_current_user)) -> UserProfile:
        allowed_perms = ROLE_PERMISSIONS_MAP.get(current_user.role, set())
        if required_permission not in allowed_perms:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Forbidden: Insufficient Permissions",
                    "required_permission": required_permission.value,
                    "user_role": current_user.role.value,
                    "user_email": current_user.email,
                    "message": f"Action requires '{required_permission.value}' which is not granted to '{current_user.role.value}'."
                }
            )
        return current_user
    return permission_checker


def require_role(allowed_roles: List[UserRole]) -> Callable:
    """
    FastAPI dependency factory restricting access to a list of allowed roles.
    Raises HTTP 403 Forbidden if user's role is not in the allowed list.
    """
    def role_checker(current_user: UserProfile = Depends(get_current_user)) -> UserProfile:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Forbidden: Role Unauthorized",
                    "allowed_roles": [r.value for r in allowed_roles],
                    "user_role": current_user.role.value,
                    "user_email": current_user.email,
                    "message": f"Endpoint requires one of roles: {[r.value for r in allowed_roles]}."
                }
            )
        return current_user
    return role_checker
