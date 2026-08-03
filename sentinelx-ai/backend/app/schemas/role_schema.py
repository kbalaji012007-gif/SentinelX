"""
SentinelX AI – Role Pydantic v2 Schemas
Validation and serialization schemas for sentinelx.roles.
"""

from uuid import UUID
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class RoleBase(BaseModel):
    """Base Role attributes."""

    name: str = Field(..., min_length=2, max_length=50, description="Unique role name")
    description: str | None = Field(None, max_length=500, description="Role description")
    permissions: dict[str, Any] = Field(default_factory=dict, description="Permission matrix JSON")
    is_system_role: bool = Field(default=False, description="System-level immutable role flag")


class RoleCreate(RoleBase):
    """Schema for creating a new role."""

    pass


class RoleUpdate(BaseModel):
    """Schema for updating an existing role."""

    name: str | None = Field(None, min_length=2, max_length=50)
    description: str | None = Field(None, max_length=500)
    permissions: dict[str, Any] | None = None
    is_system_role: bool | None = None


class RoleResponse(RoleBase):
    """Schema for role response serialization."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime
