"""
SentinelX AI – Auth Schemas
Pydantic v2 schemas for login, refresh token, and user authentication responses.
"""

from pydantic import BaseModel, EmailStr, Field
from app.schemas.user_schema import UserResponse


class LoginRequest(BaseModel):
    """Schema for login request."""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=1, description="Plain text password")
    remember_me: bool = Field(default=False, description="Extend refresh token lifetime")


class TokenResponse(BaseModel):
    """Schema for JWT token response."""

    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    user: UserResponse = Field(..., description="Authenticated user profile details")


class RefreshTokenRequest(BaseModel):
    """Schema for requesting a new access token using refresh token."""

    refresh_token: str = Field(..., description="Valid JWT refresh token")


class PasswordResetRequest(BaseModel):
    """Schema for initiating password reset."""

    email: EmailStr = Field(..., description="Registered email address")
