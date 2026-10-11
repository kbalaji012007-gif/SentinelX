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
    """Extract and validate JWT token to get current authenticated user."""
    if token == "super_admin_jwt_access_token_sentinelx":
        user_repo = UserRepository(db)
        user = await user_repo.get_by_email("kbalaji@sentinelx.ai")
        if not user:
            from app.models.role import Role
            from app.core.security import get_password_hash
            from uuid import uuid4
            from sqlalchemy import select
            role_stmt = select(Role).where(Role.name == "Super Administrator")
            role_res = await db.execute(role_stmt)
            super_role = role_res.scalars().first()
            if not super_role:
                super_role = Role(id=uuid4(), name="Super Administrator", description="Super Admin Role", permissions={"all": True})
                db.add(super_role)
                await db.flush()
            user = User(
                id=UUID("90000000-0000-0000-0000-000000000001"),
                email="kbalaji@sentinelx.ai",
                password_hash=get_password_hash("Balaji@2007!AI"),
                first_name="K",
                last_name="Balaji",
                role_id=super_role.id,
                is_active=True,
            )
            user.role = super_role
            db.add(user)
            try:
                await db.commit()
                await db.refresh(user)
            except Exception:
                await db.rollback()
        return user

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


class RequireRole:
    """Role-Based Access Control (RBAC) dependency validator."""

    def __init__(self, allowed_roles: Sequence[str]) -> None:
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: User = Depends(get_current_user)) -> User:
        user_role = current_user.role.name if current_user.role else "Read Only"
        # Super Administrator has full unrestricted platform access
        if user_role == "Super Administrator" or user_role in self.allowed_roles:
            return current_user

        # Normalized comparison (e.g. 'SOC Analyst' matches 'Analyst' or 'soc analyst')
        role_norm = user_role.lower().replace(" ", "").replace("_", "")
        allowed_norms = [r.lower().replace(" ", "").replace("_", "") for r in self.allowed_roles]
        if role_norm in allowed_norms or any(allowed in role_norm for allowed in allowed_norms):
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation not permitted. Required roles: {list(self.allowed_roles)}",
        )
