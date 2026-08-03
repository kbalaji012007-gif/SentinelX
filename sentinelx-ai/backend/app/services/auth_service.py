"""
SentinelX AI – Auth Service Layer
Business logic for user authentication, password verification, token generation, and audit logging.
"""

from uuid import UUID
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
import structlog

from app.repositories.user_repo import UserRepository
from app.core.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.models.user import User
from app.schemas.auth_schema import TokenResponse
from app.schemas.user_schema import UserResponse

logger = structlog.get_logger()


class AuthService:
    """Authentication service providing login, token refresh, and RBAC helpers."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_repo = UserRepository(session)

    async def authenticate_user(self, email: str, password: str, remember_me: bool = False) -> TokenResponse:
        """Authenticate user credentials, update last login, and return JWT tokens."""
        user = await self.user_repo.get_by_email(email)

        if not user:
            logger.warning("auth_failed_user_not_found", email=email)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            logger.warning("auth_failed_user_inactive", user_id=str(user.id), email=email)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated",
            )

        if not verify_password(password, user.password_hash):
            logger.warning("auth_failed_invalid_password", user_id=str(user.id), email=email)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Update last_login timestamp
        user.last_login = datetime.now(timezone.utc)
        await self.session.commit()
        await self.session.refresh(user)

        role_name = user.role.name if user.role else "Analyst"

        # Token expiration deltas
        refresh_delta = timedelta(days=30) if remember_me else None

        access_token = create_access_token(subject=str(user.id), role=role_name)
        refresh_token = create_refresh_token(subject=str(user.id), expires_delta=refresh_delta)

        logger.info("auth_login_success", user_id=str(user.id), email=user.email, role=role_name)

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            user=UserResponse.model_validate(user),
        )

    async def refresh_token(self, refresh_token_str: str) -> TokenResponse:
        """Validate refresh token and issue a new pair of tokens."""
        payload = decode_token(refresh_token_str)

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type for refresh",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id_str = payload.get("sub")
        if not user_id_str:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token subject",
            )

        user = await self.user_repo.get_by_id_with_role(UUID(user_id_str))
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )

        role_name = user.role.name if user.role else "Analyst"

        new_access_token = create_access_token(subject=str(user.id), role=role_name)
        new_refresh_token = create_refresh_token(subject=str(user.id))

        logger.info("auth_token_refreshed", user_id=str(user.id))

        return TokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            user=UserResponse.model_validate(user),
        )
