"""
SentinelX AI – API Dependencies
Database sessions, JWT authentication extraction, and RBAC permission enforcement.
"""

from uuid import UUID
from typing import AsyncGenerator, Sequence, Callable
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.core.config import settings
from app.core.security import decode_token
from app.models.user import User
from app.repositories.user_repo import UserRepository

import ssl

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# Async SQLAlchemy Engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    pool_size=10,
    max_overflow=20,
    connect_args={
        "ssl": ssl_ctx,
        "statement_cache_size": 0,
        "prepared_statement_cache_size": 0,
    },
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Provide asynchronous database session dependency."""
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and validate cryptographic JWT token to get current authenticated user."""
    payload = decode_token(token)
    user_id_str: str | None = payload.get("sub")

    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_repo = UserRepository(db)
    try:
        user = await user_repo.get_by_id_with_role(UUID(user_id_str))
    except (ValueError, TypeError):
        user = await user_repo.get_by_email(user_id_str)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Authenticated user no longer exists",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    return user


# ── Canonical Platform Roles & Aliases ─────────────────────────────────────────
CANONICAL_PLATFORM_ROLES = {
    "Super Administrator",
    "Administrator",
    "SOC Manager",
    "SOC Analyst",
    "Threat Hunter",
    "Incident Responder",
    "Auditor",
    "Read Only",
}

ROLE_ALIASES: dict[str, str] = {
    "superadministrator": "Super Administrator",
    "superadmin": "Super Administrator",
    "administrator": "Administrator",
    "admin": "Administrator",
    "socmanager": "SOC Manager",
    "manager": "SOC Manager",
    "socanalyst": "SOC Analyst",
    "analyst": "SOC Analyst",
    "threathunter": "Threat Hunter",
    "incidentresponder": "Incident Responder",
    "auditor": "Auditor",
    "readonly": "Read Only",
    "read-only": "Read Only",
}


def canonicalize_role(role_name: str | None) -> str:
    """Normalize a role name or alias to its canonical platform role."""
    if not role_name:
        return "Read Only"
    cleaned = role_name.lower().replace(" ", "").replace("_", "").replace("-", "")
    return ROLE_ALIASES.get(cleaned, role_name.strip())


# Standardized Role Collections for Route Guards
ALL_PLATFORM_ROLES = list(CANONICAL_PLATFORM_ROLES)
ALL_READERS = ALL_PLATFORM_ROLES
SOC_OPERATIONAL_ROLES = [
    "Super Administrator",
    "Administrator",
    "SOC Manager",
    "SOC Analyst",
    "Threat Hunter",
    "Incident Responder",
]
SOAR_ACTION_ROLES = [
    "Super Administrator",
    "Administrator",
    "SOC Manager",
    "SOC Analyst",
    "Incident Responder",
]
ADMINISTRATIVE_ROLES = [
    "Super Administrator",
    "Administrator",
    "SOC Manager",
]
SUPER_ADMIN_ROLES = [
    "Super Administrator",
]


class RequireRole:
    """Role-Based Access Control (RBAC) dependency validator using canonical role mapping."""

    def __init__(self, allowed_roles: Sequence[str]) -> None:
        self.allowed_roles = list(allowed_roles)
        self.allowed_canonical = {canonicalize_role(r) for r in self.allowed_roles}

    def __call__(self, current_user: User = Depends(get_current_user)) -> User:
        raw_role = current_user.role.name if current_user.role else "Read Only"
        user_canonical = canonicalize_role(raw_role)

        # Super Administrator has full platform access
        if user_canonical == "Super Administrator" or user_canonical in self.allowed_canonical:
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation not permitted. Required roles: {sorted(self.allowed_canonical)}",
        )
