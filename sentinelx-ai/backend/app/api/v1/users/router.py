"""
SentinelX AI – User Management REST API Router
JWT-protected, RBAC-enforced CRUD endpoints for user administration.
"""

from uuid import UUID
from typing import Annotated
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, RequireRole, get_current_user
from app.models.user import User
from app.schemas.user_management_schema import (
    UserCreate,
    UserUpdate,
    UserResetPassword,
    UserResponse,
    PaginatedUserList,
)
from app.services.user_management_service import UserManagementService

router = APIRouter(prefix="/users", tags=["User Management"])

# RBAC Permissions
_ADMIN_ROLES = ["Super Administrator", "Administrator", "Admin"]
_SUPER_ADMIN_ROLE = ["Super Administrator"]


@router.get(
    "",
    response_model=PaginatedUserList,
    status_code=status.HTTP_200_OK,
    summary="List All Users with Search and Filters",
)
async def list_users(
    search: Annotated[str | None, Query(description="Search by name or email")] = None,
    role: Annotated[str | None, Query(description="Filter by role name")] = None,
    is_active: Annotated[bool | None, Query(description="Filter by active status")] = None,
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMIN_ROLES)),
) -> PaginatedUserList:
    """Fetch paginated list of user accounts with search and filters."""
    service = UserManagementService(db)
    return await service.list_users(
        search=search, role_name=role, is_active=is_active, page=page, page_size=page_size
    )


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create New User Account",
)
async def create_user(
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMIN_ROLES)),
) -> UserResponse:
    """Create a new user with hashed password and role assignment."""
    service = UserManagementService(db)
    return await service.create_user(payload, operator=current_user)


@router.get(
    "/{id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get User Details by ID",
)
async def get_user(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMIN_ROLES)),
) -> UserResponse:
    """Fetch single user account details by ID."""
    service = UserManagementService(db)
    return await service.get_user_by_id(id)


@router.put(
    "/{id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update User Profile / Role",
)
async def update_user(
    id: UUID,
    payload: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMIN_ROLES)),
) -> UserResponse:
    """Update user profile, active status, or role."""
    service = UserManagementService(db)
    return await service.update_user(id, payload, operator=current_user)


@router.delete(
    "/{id}",
    status_code=status.HTTP_200_OK,
    summary="Delete User Account",
)
async def delete_user(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMIN_ROLES)),
) -> dict[str, str]:
    """Delete a user account."""
    service = UserManagementService(db)
    return await service.delete_user(id, operator=current_user)


@router.post(
    "/{id}/reset-password",
    status_code=status.HTTP_200_OK,
    summary="Reset User Password",
)
async def reset_password(
    id: UUID,
    payload: UserResetPassword,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMIN_ROLES)),
) -> dict[str, str]:
    """Reset password for a user using existing bcrypt hashing."""
    service = UserManagementService(db)
    return await service.reset_password(id, payload, operator=current_user)


@router.post(
    "/{id}/enable",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Enable User Account",
)
async def enable_user(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMIN_ROLES)),
) -> UserResponse:
    """Enable a deactivated user account."""
    service = UserManagementService(db)
    return await service.set_user_status(id, is_active=True, operator=current_user)


@router.post(
    "/{id}/disable",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Disable User Account",
)
async def disable_user(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMIN_ROLES)),
) -> UserResponse:
    """Deactivate/disable a user account."""
    service = UserManagementService(db)
    return await service.set_user_status(id, is_active=False, operator=current_user)
