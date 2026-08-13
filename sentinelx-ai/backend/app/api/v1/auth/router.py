"""
SentinelX AI – Auth API Router
Endpoints for login, refresh token, logout, and current user profile.
"""

from typing import Annotated
from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.schemas.auth_schema import (
    LoginRequest,
    TokenResponse,
    OAuth2TokenResponse,
    RefreshTokenRequest,
)
from app.schemas.user_schema import UserResponse
from app.services.auth_service import AuthService
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def login(
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user credentials and issue JWT Access and Refresh Tokens."""
    auth_service = AuthService(db)
    return await auth_service.authenticate_user(
        email=payload.email,
        password=payload.password,
        remember_me=payload.remember_me,
    )


@router.post("/token", response_model=OAuth2TokenResponse, status_code=status.HTTP_200_OK)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: AsyncSession = Depends(get_db),
) -> OAuth2TokenResponse:
    """OAuth2 password flow token endpoint for Swagger UI authorization and OAuth2 clients."""
    auth_service = AuthService(db)
    tokens = await auth_service.authenticate_user(
        email=form_data.username,
        password=form_data.password,
    )
    return OAuth2TokenResponse(
        access_token=tokens.access_token,
        token_type=tokens.token_type,
    )


@router.post("/refresh", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def refresh_token(
    payload: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    """Obtain a new access token using a valid refresh token."""
    auth_service = AuthService(db)
    return await auth_service.refresh_token(payload.refresh_token)


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    current_user: User = Depends(get_current_user),
):
    """Log out current user (session termination)."""
    return {"message": "Successfully logged out", "user_id": str(current_user.id)}


@router.get("/me", response_model=UserResponse, status_code=status.HTTP_200_OK)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
):
    """Fetch current authenticated user profile details with role."""
    return UserResponse.model_validate(current_user)
