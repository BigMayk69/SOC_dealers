"""
Pydantic Schemas for Authentication & User Profile Management.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, EmailStr
from backend.auth.models import UserRole


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: UserRole
    department: str
    permissions: List[str]
    is_active: bool


class RoleDetailResponse(BaseModel):
    role: UserRole
    description: str
    permissions: List[str]


class SwitchRoleRequest(BaseModel):
    role: UserRole
    email: Optional[str] = None
