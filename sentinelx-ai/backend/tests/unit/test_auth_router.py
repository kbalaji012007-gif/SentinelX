"""
SentinelX AI – Unit Tests for Auth API Router
Tests JSON login (/auth/login) and OAuth2 password flow token endpoint (/auth/token).
"""

import pytest
from unittest.mock import AsyncMock, patch
from uuid import uuid4
from datetime import datetime, timezone
from fastapi import HTTPException, status

from app.schemas.auth_schema import TokenResponse
from app.schemas.user_schema import UserResponse
from app.schemas.role_schema import RoleResponse


@pytest.mark.asyncio
async def test_auth_login_json_success():
    """Test standard JSON payload login via POST /api/v1/auth/login."""
    mock_user_id = uuid4()
    mock_role_id = uuid4()
    now = datetime.now(timezone.utc)
    mock_token_response = TokenResponse(
        access_token="mock_access_token_123",
        refresh_token="mock_refresh_token_456",
        token_type="bearer",
        user=UserResponse(
            id=mock_user_id,
            role_id=mock_role_id,
            email="admin@sentinelx.ai",
            first_name="Super",
            last_name="Admin",
            role=RoleResponse(
                id=mock_role_id,
                name="Super Administrator",
                description="Super Admin Role",
                permissions={},
                created_at=now,
                updated_at=now,
            ),
            is_active=True,
            created_at=now,
            updated_at=now,
        ),
    )

    with patch("app.api.v1.auth.router.AuthService") as MockAuthService:
        instance = MockAuthService.return_value
        instance.authenticate_user = AsyncMock(return_value=mock_token_response)

        from app.api.v1.auth.router import login
        from app.schemas.auth_schema import LoginRequest

        payload = LoginRequest(
            email="admin@sentinelx.ai",
            password="SecurePassword123!",
            remember_me=True,
        )
        mock_db = AsyncMock()

        result = await login(payload=payload, db=mock_db)

        assert result.access_token == "mock_access_token_123"
        assert result.token_type == "bearer"
        assert result.user.email == "admin@sentinelx.ai"
        instance.authenticate_user.assert_called_once_with(
            email="admin@sentinelx.ai",
            password="SecurePassword123!",
            remember_me=True,
        )


@pytest.mark.asyncio
async def test_auth_token_oauth2_form_success():
    """Test OAuth2 password request form login via POST /api/v1/auth/token for Swagger UI."""
    mock_user_id = uuid4()
    mock_role_id = uuid4()
    now = datetime.now(timezone.utc)
    mock_token_response = TokenResponse(
        access_token="mock_oauth2_access_token_789",
        refresh_token="mock_oauth2_refresh_token_012",
        token_type="bearer",
        user=UserResponse(
            id=mock_user_id,
            role_id=mock_role_id,
            email="admin@sentinelx.ai",
            first_name="Super",
            last_name="Admin",
            role=RoleResponse(
                id=mock_role_id,
                name="Super Administrator",
                description="Super Admin Role",
                permissions={},
                created_at=now,
                updated_at=now,
            ),
            is_active=True,
            created_at=now,
            updated_at=now,
        ),
    )

    with patch("app.api.v1.auth.router.AuthService") as MockAuthService:
        instance = MockAuthService.return_value
        instance.authenticate_user = AsyncMock(return_value=mock_token_response)

        from app.api.v1.auth.router import login_for_access_token
        from fastapi.security import OAuth2PasswordRequestForm

        form_data = OAuth2PasswordRequestForm(
            username="admin@sentinelx.ai",
            password="SecurePassword123!",
            scope="",
            client_id=None,
            client_secret=None,
        )
        mock_db = AsyncMock()

        result = await login_for_access_token(form_data=form_data, db=mock_db)

        assert result.access_token == "mock_oauth2_access_token_789"
        assert result.token_type == "bearer"
        instance.authenticate_user.assert_called_once_with(
            email="admin@sentinelx.ai",
            password="SecurePassword123!",
        )


@pytest.mark.asyncio
async def test_auth_token_invalid_credentials():
    """Test invalid credentials error handling on /auth/token."""
    with patch("app.api.v1.auth.router.AuthService") as MockAuthService:
        instance = MockAuthService.return_value
        instance.authenticate_user = AsyncMock(
            side_effect=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        )

        from app.api.v1.auth.router import login_for_access_token
        from fastapi.security import OAuth2PasswordRequestForm

        form_data = OAuth2PasswordRequestForm(
            username="wrong@sentinelx.ai",
            password="WrongPassword",
            scope="",
            client_id=None,
            client_secret=None,
        )
        mock_db = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await login_for_access_token(form_data=form_data, db=mock_db)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Incorrect email or password"
