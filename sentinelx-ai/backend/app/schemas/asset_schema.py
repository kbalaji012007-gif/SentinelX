"""
SentinelX AI – Asset & AssetGroup Pydantic v2 Schemas
Validation and serialization schemas for sentinelx.asset_groups and sentinelx.assets.
"""

from uuid import UUID
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

AssetTypeEnum = Literal["Server", "Workstation", "Cloud Resource", "Router", "Switch", "Firewall", "Network Device"]
CriticalityEnum = Literal["Critical", "High", "Medium", "Low"]
StatusEnum = Literal["Active", "Inactive", "Maintenance", "Decommissioned"]


# ── Asset Group Schemas ──────────────────────────────────────────────

class AssetGroupBase(BaseModel):
    """Base AssetGroup attributes."""

    name: str = Field(..., min_length=2, max_length=100, description="Unique asset group name")
    description: str | None = Field(None, max_length=500)


class AssetGroupCreate(AssetGroupBase):
    """Schema for creating a new asset group."""

    pass


class AssetGroupUpdate(BaseModel):
    """Schema for updating an asset group."""

    name: str | None = Field(None, min_length=2, max_length=100)
    description: str | None = Field(None, max_length=500)


class AssetGroupResponse(AssetGroupBase):
    """Schema for returning asset group details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


# ── Asset Schemas ───────────────────────────────────────────────────

class AssetBase(BaseModel):
    """Base Asset attributes."""

    hostname: str = Field(..., min_length=1, max_length=255, description="Unique network hostname")
    asset_name: str = Field(..., min_length=1, max_length=255, description="Human-readable asset name")
    asset_type: AssetTypeEnum = Field(..., description="Asset type classification")
    operating_system: str | None = Field(None, max_length=100)
    ip_address: str = Field(..., min_length=7, max_length=45, description="IPv4 or IPv6 address")
    mac_address: str | None = Field(None, max_length=17)
    owner: str | None = Field(None, max_length=100)
    department: str | None = Field(None, max_length=100)
    criticality: CriticalityEnum = Field(default="Medium")
    status: StatusEnum = Field(default="Active")
    location: str | None = Field(None, max_length=100)
    serial_number: str | None = Field(None, max_length=100)
    tags: list[Any] = Field(default_factory=list)


class AssetCreate(AssetBase):
    """Schema for creating a new asset."""

    asset_group_id: UUID


class AssetUpdate(BaseModel):
    """Schema for updating an asset."""

    asset_group_id: UUID | None = None
    hostname: str | None = Field(None, min_length=1, max_length=255)
    asset_name: str | None = Field(None, min_length=1, max_length=255)
    asset_type: AssetTypeEnum | None = None
    operating_system: str | None = Field(None, max_length=100)
    ip_address: str | None = Field(None, min_length=7, max_length=45)
    mac_address: str | None = Field(None, max_length=17)
    owner: str | None = Field(None, max_length=100)
    department: str | None = Field(None, max_length=100)
    criticality: CriticalityEnum | None = None
    status: StatusEnum | None = None
    location: str | None = Field(None, max_length=100)
    serial_number: str | None = Field(None, max_length=100)
    tags: list[Any] | None = None
    last_seen: datetime | None = None


class AssetResponse(AssetBase):
    """Schema for returning asset details."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_group_id: UUID
    asset_group: AssetGroupResponse | None = None
    last_seen: datetime | None = None
    created_at: datetime
    updated_at: datetime
