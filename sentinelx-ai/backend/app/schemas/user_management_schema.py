"""
SentinelX AI – User Management Pydantic v2 Schemas
Validation and serialization schemas for user CRUD operations.
"""

from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RoleSchema(BaseModel):
    """Schema for user role details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None = None


class UserCreate(BaseModel):
    """Payload for creating a new user."""

    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    display_name: str | None = Field(default=None, max_length=150)
    email: EmailStr = Field(...)
    password: str = Field(..., min_length=8, description="Plaintext password to be hashed")
    role_name: str = Field(default="SOC Analyst", description="Name of role to assign")
    phone: str | None = Field(default=None)
    department: str | None = Field(default=None)


class UserUpdate(BaseModel):
    """Payload for updating user profile and role."""

    first_name: str | None = Field(default=None)
    last_name: str | None = Field(default=None)
    display_name: str | None = Field(default=None)
    email: EmailStr | None = Field(default=None)
    role_name: str | None = Field(default=None)
    phone: str | None = Field(default=None)
    department: str | None = Field(default=None)
    is_active: bool | None = Field(default=None)


class UserResetPassword(BaseModel):
    """Payload for resetting user password."""

    new_password: str = Field(..., min_length=8)


class UserResponse(BaseModel):
    """Public user profile response schema."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    first_name: str
    last_name: str
    display_name: str | None = None
    role_id: UUID
    role: RoleSchema | None = None
    phone: str | None = None
    department: str | None = None
    is_active: bool
    mfa_enabled: bool = False
    last_login: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class PaginatedUserList(BaseModel):
    """Paginated list of user accounts."""

    total: int
    page: int
    page_size: int
    items: list[UserResponse]
