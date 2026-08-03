"""
SentinelX AI – SQLAlchemy Declarative Base
"""

from datetime import datetime, timezone
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import MetaData, DateTime, func

# Schema metadata
metadata_obj = MetaData(schema="sentinelx")


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models in SentinelX AI."""

    metadata = metadata_obj


class TimestampMixin:
    """Mixin for created_at and updated_at columns."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
