"""
SentinelX AI – User Pydantic v2 Schemas
Validation and serialization schemas for sentinelx.users.
"""

from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.schemas.role_schema import RoleResponse


class UserBase(BaseModel):
    """Base User attributes."""

    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr = Field(..., description="Unique email address")
    phone: str | None = Field(None, max_length=50)
    avatar_url: str | None = Field(None)
    is_active: bool = Field(default=True)
    mfa_enabled: bool = Field(default=False)


class UserCreate(UserBase):
    """Schema for user creation."""

    role_id: UUID
    password: str = Field(..., min_length=8, max_length=128, description="Raw password before hashing")


class UserUpdate(BaseModel):
    """Schema for updating user details."""

    first_name: str | None = Field(None, min_length=1, max_length=100)
    last_name: str | None = Field(None, min_length=1, max_length=100)
    email: EmailStr | None = None
    role_id: UUID | None = None
    phone: str | None = None
    avatar_url: str | None = None
    is_active: bool | None = None
    mfa_enabled: bool | None = None


class UserResponse(UserBase):
    """Schema for returning user data (excluding password_hash)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    role_id: UUID
    role: RoleResponse | None = None
    last_login: datetime | None = None
    created_at: datetime
    updated_at: datetime
