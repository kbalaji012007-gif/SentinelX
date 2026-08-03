"""
SentinelX AI – Dashboard API Router
Endpoints for summary metrics, system health, recent activity, risk scores, and statistics.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.models.user import User
from app.schemas.dashboard_schema import (
    DashboardSummaryResponse,
    SystemHealthResponse,
    ActivityItem,
    RiskScoreResponse,
    DashboardStatisticsResponse,
)
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse, status_code=status.HTTP_200_OK)
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch high-level SOC summary metrics."""
    service = DashboardService(db)
    return await service.get_summary()


@router.get("/system-health", response_model=SystemHealthResponse, status_code=status.HTTP_200_OK)
async def get_system_health(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch subsystem health and latency status."""
    service = DashboardService(db)
    return await service.get_system_health()


@router.get("/recent-activity", response_model=list[ActivityItem], status_code=status.HTTP_200_OK)
async def get_recent_activity(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch active threats and security activity feed."""
    service = DashboardService(db)
    return await service.get_recent_activity()


@router.get("/risk-score", response_model=RiskScoreResponse, status_code=status.HTTP_200_OK)
async def get_risk_score(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch risk score and primary contributing factors."""
    service = DashboardService(db)
    return await service.get_risk_score()


@router.get("/statistics", response_model=DashboardStatisticsResponse, status_code=status.HTTP_200_OK)
async def get_dashboard_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch velocity timeline and severity distribution statistics."""
    service = DashboardService(db)
    return await service.get_statistics()
