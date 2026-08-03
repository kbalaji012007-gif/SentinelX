"""
SentinelX AI – Repositories Package
Exposes BaseRepository, RoleRepository, UserRepository, AssetGroupRepository, AssetRepository, and DashboardRepository.
"""

from app.repositories.base_repo import BaseRepository
from app.repositories.role_repo import RoleRepository
from app.repositories.user_repo import UserRepository
from app.repositories.asset_repo import AssetGroupRepository, AssetRepository
from app.repositories.dashboard_repo import DashboardRepository

__all__ = [
    "BaseRepository",
    "RoleRepository",
    "UserRepository",
    "AssetGroupRepository",
    "AssetRepository",
    "DashboardRepository",
]
