"""
SentinelX AI – User Management Service
Service layer for User CRUD, Password Resets, Role Assignments, and Status Toggles.
"""

from uuid import UUID
from typing import Sequence, Tuple
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.repositories.user_repo import UserRepository
from app.schemas.user_management_schema import (
    UserCreate,
    UserUpdate,
    UserResetPassword,
    UserResponse,
    PaginatedUserList,
)
from app.core.security import get_password_hash


class UserManagementService:
    """Service layer managing user accounts, permissions, and security RBAC checks."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_repo = UserRepository(session)

    async def create_user(self, payload: UserCreate, operator: User) -> UserResponse:
        """Create a new user account with hashed password and role assignment."""
        # 1. Check existing email
        existing = await self.user_repo.get_by_email(payload.email)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User with email '{payload.email}' already exists.",
            )

        # 2. Get target role
        role = await self.user_repo.get_role_by_name(payload.role_name)
        if not role:
            # Fallback to SOC Analyst
            role = await self.user_repo.get_role_by_name("SOC Analyst")
            if not role:
                roles = await self.user_repo.list_roles()
                role = roles[0]

        # 3. Hash password using existing security module
        hashed_pwd = get_password_hash(payload.password)

        # 4. Instantiate and save User
        user = User(
            email=payload.email,
            password_hash=hashed_pwd,
            first_name=payload.first_name,
            last_name=payload.last_name,
            role_id=role.id,
            phone=payload.phone,
            is_active=True,
            mfa_enabled=False,
        )
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)

        user_with_role = await self.user_repo.get_by_id_with_role(user.id)
        return UserResponse.model_validate(user_with_role)

    async def get_user_by_id(self, user_id: UUID) -> UserResponse:
        """Fetch user by ID."""
        user = await self.user_repo.get_by_id_with_role(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with ID '{user_id}' not found.",
            )
        return UserResponse.model_validate(user)

    async def update_user(self, user_id: UUID, payload: UserUpdate, operator: User) -> UserResponse:
        """Update user profile, status, or role with RBAC enforcement."""
        user = await self.user_repo.get_by_id_with_role(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with ID '{user_id}' not found.",
            )

        # RBAC Check: Administrators cannot modify Super Administrators unless operator is Super Administrator
        op_role = operator.role.name if operator.role else "ReadOnly"
        target_role = user.role.name if user.role else "ReadOnly"

        if target_role == "Super Administrator" and op_role != "Super Administrator":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only Super Administrators can modify a Super Administrator account.",
            )

        if payload.first_name is not None:
            user.first_name = payload.first_name
        if payload.last_name is not None:
            user.last_name = payload.last_name
        if payload.email is not None:
            user.email = payload.email
        if payload.phone is not None:
            user.phone = payload.phone
        if payload.is_active is not None:
            user.is_active = payload.is_active

        if payload.role_name is not None:
            # Only Super Admin or Admin can change roles
            if op_role not in ("Super Administrator", "Administrator"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Role changes require Super Administrator privileges.",
                )
            new_role = await self.user_repo.get_role_by_name(payload.role_name)
            if new_role:
                user.role_id = new_role.id

        await self.session.commit()
        await self.session.refresh(user)
        updated_user = await self.user_repo.get_by_id_with_role(user.id)
        return UserResponse.model_validate(updated_user)

    async def reset_password(self, user_id: UUID, payload: UserResetPassword, operator: User) -> dict[str, str]:
        """Reset user password using existing bcrypt hashing."""
        user = await self.user_repo.get_by_id_with_role(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with ID '{user_id}' not found.",
            )

        op_role = operator.role.name if operator.role else "ReadOnly"
        target_role = user.role.name if user.role else "ReadOnly"

        if target_role == "Super Administrator" and op_role != "Super Administrator":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only Super Administrators can reset password for a Super Administrator.",
            )

        user.password_hash = get_password_hash(payload.new_password)
        await self.session.commit()
        return {"message": f"Password for user '{user.email}' reset successfully."}

    async def set_user_status(self, user_id: UUID, is_active: bool, operator: User) -> UserResponse:
        """Enable or disable user account."""
        user = await self.user_repo.get_by_id_with_role(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with ID '{user_id}' not found.",
            )

        op_role = operator.role.name if operator.role else "ReadOnly"
        target_role = user.role.name if user.role else "ReadOnly"

        if target_role == "Super Administrator" and op_role != "Super Administrator":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only Super Administrators can modify a Super Administrator account.",
            )

        user.is_active = is_active
        await self.session.commit()
        await self.session.refresh(user)
        updated = await self.user_repo.get_by_id_with_role(user.id)
        return UserResponse.model_validate(updated)

    async def delete_user(self, user_id: UUID, operator: User) -> dict[str, str]:
        """Delete user account."""
        user = await self.user_repo.get_by_id_with_role(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with ID '{user_id}' not found.",
            )

        op_role = operator.role.name if operator.role else "ReadOnly"
        target_role = user.role.name if user.role else "ReadOnly"

        if target_role == "Super Administrator" and op_role != "Super Administrator":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only Super Administrators can delete a Super Administrator account.",
            )

        await self.session.delete(user)
        await self.session.commit()
        return {"message": f"User '{user.email}' deleted successfully."}

    async def list_users(
        self,
        search: str | None = None,
        role_name: str | None = None,
        is_active: bool | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> PaginatedUserList:
        """List users with pagination and filters."""
        items, total = await self.user_repo.list_users_paginated(
            search=search, role_name=role_name, is_active=is_active, page=page, page_size=page_size
        )
        return PaginatedUserList(
            total=total,
            page=page,
            page_size=page_size,
            items=[UserResponse.model_validate(u) for u in items],
        )
