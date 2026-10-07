"""
Unit and Integration Tests for Role-Based Access Control (RBAC) and Auth System.
"""
import pytest
from fastapi.testclient import TestClient
from backend.app import app
from backend.auth.models import UserRole, Permission, ROLE_PERMISSIONS_MAP, DEMO_SOC_USERS
from backend.auth.dependencies import get_current_user

client = TestClient(app)


def test_rbac_permission_matrix():
    # Admin has all permissions
    admin_perms = ROLE_PERMISSIONS_MAP[UserRole.SOC_LEAD_ADMIN]
    assert Permission.EXECUTE_CONTAINMENT in admin_perms
    assert Permission.EXECUTE_SSH_REMEDIATION in admin_perms
    assert Permission.EXECUTE_SSH_FORENSICS in admin_perms
    assert Permission.MANAGE_USERS in admin_perms

    # Senior analyst has forensic SSH and containment, but not user management
    senior_perms = ROLE_PERMISSIONS_MAP[UserRole.SENIOR_ANALYST]
    assert Permission.EXECUTE_SSH_FORENSICS in senior_perms
    assert Permission.EXECUTE_CONTAINMENT in senior_perms
    assert Permission.MANAGE_USERS not in senior_perms

    # Tier 1 analyst has read / triage only
    tier1_perms = ROLE_PERMISSIONS_MAP[UserRole.TIER1_ANALYST]
    assert Permission.VIEW_INCIDENTS in tier1_perms
    assert Permission.COPILOT_CHAT in tier1_perms
    assert Permission.EXECUTE_SSH_FORENSICS not in tier1_perms
    assert Permission.EXECUTE_CONTAINMENT not in tier1_perms

    # Auditor has view only
    auditor_perms = ROLE_PERMISSIONS_MAP[UserRole.AUDITOR]
    assert Permission.VIEW_DASHBOARD in auditor_perms
    assert Permission.VIEW_AUDIT_LOGS in auditor_perms
    assert Permission.SUBMIT_FEEDBACK not in auditor_perms


def test_auth_me_default_admin():
    response = client.get("/api/auth/me")
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "SOC_LEAD_ADMIN"
    assert data["email"] == "admin@dealers.corp"
    assert "containment:execute" in data["permissions"]


def test_auth_me_header_tier1_analyst():
    headers = {
        "X-User-Email": "tier1.analyst@dealers.corp",
        "X-User-Role": "TIER1_ANALYST"
    }
    response = client.get("/api/auth/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "TIER1_ANALYST"
    assert data["email"] == "tier1.analyst@dealers.corp"
    assert "view:incidents" in data["permissions"]
    assert "containment:execute" not in data["permissions"]


def test_auth_roles_endpoint():
    response = client.get("/api/auth/roles")
    assert response.status_code == 200
    roles = response.json()
    assert len(roles) >= 4
    role_names = [r["role"] for r in roles]
    assert "SOC_LEAD_ADMIN" in role_names
    assert "SENIOR_ANALYST" in role_names
    assert "TIER1_ANALYST" in role_names
    assert "AUDITOR" in role_names


def test_auth_users_directory():
    response = client.get("/api/auth/users")
    assert response.status_code == 200
    users = response.json()
    assert len(users) >= 4
    emails = [u["email"] for u in users]
    assert "admin@dealers.corp" in emails
    assert "senior.analyst@dealers.corp" in emails
