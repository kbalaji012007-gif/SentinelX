"""
SentinelX AI – Auth API Router
Endpoints for login, refresh token, logout, and current user profile.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.schemas.auth_schema import LoginRequest, TokenResponse, RefreshTokenRequest
from app.schemas.user_schema import UserResponse
from app.services.auth_service import AuthService
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


import traceback
from fastapi import APIRouter, Depends, status, HTTPException

@router.post("/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def login(
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user credentials and issue JWT Access and Refresh Tokens."""
    auth_service = AuthService(db)
    try:
        return await auth_service.authenticate_user(
            email=payload.email,
            password=payload.password,
            remember_me=payload.remember_me,
        )
    except HTTPException:
        raise
    except Exception as e:
        tb = traceback.format_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Auth Error: {str(e)} | Trace: {tb[-500:]}"
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
