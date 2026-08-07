"""
SentinelX AI – Correlation Repositories
Data access layer for Threat Correlations, Attack Chains, MITRE Mappings, and Correlation Rules.
"""

from uuid import UUID
from datetime import datetime, timezone
from typing import Sequence, Dict, Any
from sqlalchemy import select, func, or_, and_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.correlation import (
    CorrelationRule,
    ThreatCorrelation,
    AttackChain,
    MitreMapping,
)
from app.repositories.base_repo import BaseRepository


class CorrelationRuleRepository(BaseRepository[CorrelationRule]):
    """Repository managing CorrelationRule entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(CorrelationRule, session)

    async def get_by_name(self, rule_name: str) -> CorrelationRule | None:
        """Fetch correlation rule by unique rule_name."""
        result = await self.session.execute(
            select(CorrelationRule).where(CorrelationRule.rule_name == rule_name)
        )
        return result.scalar_one_or_none()

    async def list_active_rules(self) -> Sequence[CorrelationRule]:
        """Fetch all currently active correlation rules."""
        result = await self.session.execute(
            select(CorrelationRule).where(CorrelationRule.is_active == True)
        )
        return result.scalars().all()


class ThreatCorrelationRepository(BaseRepository[ThreatCorrelation]):
    """Repository managing ThreatCorrelation entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(ThreatCorrelation, session)

    async def list_correlations(
        self,
        skip: int = 0,
        limit: int = 100,
        correlation_type: str | None = None,
        severity: str | None = None,
        asset_id: UUID | None = None,
        incident_id: UUID | None = None,
        threat_id: UUID | None = None,
        min_risk_score: int | None = None,
        min_confidence_score: int | None = None,
        search: str | None = None,
    ) -> Sequence[ThreatCorrelation]:
        """Fetch paginated list of threat correlations with optional filters."""
        stmt = select(ThreatCorrelation)

        if correlation_type:
            stmt = stmt.where(ThreatCorrelation.correlation_type == correlation_type)
        if severity:
            stmt = stmt.where(ThreatCorrelation.severity == severity)
        if asset_id:
            stmt = stmt.where(ThreatCorrelation.asset_id == asset_id)
        if incident_id:
            stmt = stmt.where(ThreatCorrelation.incident_id == incident_id)
        if threat_id:
            stmt = stmt.where(ThreatCorrelation.threat_id == threat_id)
        if min_risk_score is not None:
            stmt = stmt.where(ThreatCorrelation.risk_score >= min_risk_score)
        if min_confidence_score is not None:
            stmt = stmt.where(ThreatCorrelation.confidence_score >= min_confidence_score)
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    ThreatCorrelation.title.ilike(pattern),
                    ThreatCorrelation.correlation_type.ilike(pattern),
                    ThreatCorrelation.ioc_value.ilike(pattern),
                )
            )

        stmt = stmt.order_by(ThreatCorrelation.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_correlations(
        self,
        correlation_type: str | None = None,
        severity: str | None = None,
        asset_id: UUID | None = None,
        incident_id: UUID | None = None,
        threat_id: UUID | None = None,
        search: str | None = None,
    ) -> int:
        """Count total threat correlations matching filters."""
        stmt = select(func.count(ThreatCorrelation.id))

        if correlation_type:
            stmt = stmt.where(ThreatCorrelation.correlation_type == correlation_type)
        if severity:
            stmt = stmt.where(ThreatCorrelation.severity == severity)
        if asset_id:
            stmt = stmt.where(ThreatCorrelation.asset_id == asset_id)
        if incident_id:
            stmt = stmt.where(ThreatCorrelation.incident_id == incident_id)
        if threat_id:
            stmt = stmt.where(ThreatCorrelation.threat_id == threat_id)
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    ThreatCorrelation.title.ilike(pattern),
                    ThreatCorrelation.correlation_type.ilike(pattern),
                    ThreatCorrelation.ioc_value.ilike(pattern),
                )
            )

        result = await self.session.execute(stmt)
        return result.scalar() or 0

    async def get_timeline(self, limit: int = 50) -> Sequence[ThreatCorrelation]:
        """Fetch recent correlation events ordered chronologically."""
        result = await self.session.execute(
            select(ThreatCorrelation).order_by(ThreatCorrelation.created_at.desc()).limit(limit)
        )
        return result.scalars().all()

    async def get_averages(self) -> Dict[str, float]:
        """Compute average risk_score and confidence_score."""
        result = await self.session.execute(
            select(
                func.avg(ThreatCorrelation.risk_score),
                func.avg(ThreatCorrelation.confidence_score),
            )
        )
        row = result.first()
        avg_risk = float(row[0]) if row and row[0] is not None else 50.0
        avg_conf = float(row[1]) if row and row[1] is not None else 80.0
        return {"avg_risk_score": round(avg_risk, 1), "avg_confidence_score": round(avg_conf, 1)}


class AttackChainRepository(BaseRepository[AttackChain]):
    """Repository managing AttackChain entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(AttackChain, session)

    async def list_chains(
        self,
        skip: int = 0,
        limit: int = 50,
        status: str | None = None,
        severity: str | None = None,
    ) -> Sequence[AttackChain]:
        """Fetch paginated attack chains."""
        stmt = select(AttackChain)
        if status:
            stmt = stmt.where(AttackChain.status == status)
        if severity:
            stmt = stmt.where(AttackChain.severity == severity)
        stmt = stmt.order_by(AttackChain.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count_active_chains(self) -> int:
        """Count active attack chains."""
        result = await self.session.execute(
            select(func.count(AttackChain.id)).where(AttackChain.status == "Active")
        )
        return result.scalar() or 0


class MitreMappingRepository(BaseRepository[MitreMapping]):
    """Repository managing MitreMapping entity database operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(MitreMapping, session)

    async def list_by_entity(self, entity_type: str, entity_id: UUID) -> Sequence[MitreMapping]:
        """Fetch all MITRE technique mappings for a given entity."""
        result = await self.session.execute(
            select(MitreMapping).where(
                and_(
                    MitreMapping.entity_type == entity_type,
                    MitreMapping.entity_id == entity_id,
                )
            )
        )
        return result.scalars().all()

    async def count_mappings(self) -> int:
        """Count total MITRE technique mappings."""
        result = await self.session.execute(select(func.count(MitreMapping.id)))
        return result.scalar() or 0
