"""
SentinelX AI – AI SOC Analyst API Router
JWT-protected, RBAC-enforced endpoints for AI Investigations, Threat Hunting, Risk Assessment, Recommendations, and History.
"""

from typing import Annotated
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, RequireRole
from app.models.user import User
from app.schemas.ai_soc_schema import (
    InvestigationRequest,
    InvestigationResponse,
    InvestigationListResponse,
    ThreatHuntRequest,
    ThreatHuntResponse,
    RiskAssessmentResponse,
    RecommendationResponse,
)
from app.services.ai_soc import (
    AIInvestigationService,
    AIThreatHuntingService,
    AIRiskAssessmentService,
    AIRecommendationService,
)

router = APIRouter(prefix="/ai", tags=["AI SOC Analyst"])

# RBAC roles
_READERS = ["Admin", "Manager", "Analyst", "ReadOnly"]
_WRITERS = ["Admin", "Manager", "Analyst"]


@router.post(
    "/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger AI SOC Investigation",
)
async def trigger_investigation(
    payload: InvestigationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> InvestigationResponse:
    """Trigger an AI investigation for an incident, threat, asset, log query, or IOC."""
    service = AIInvestigationService(db)
    operator = f"{current_user.first_name} {current_user.last_name}"

    inv_type = payload.investigation_type.upper()
    if inv_type == "INCIDENT":
        return await service.investigate_incident(payload.target_id, operator_name=operator)
    elif inv_type == "THREAT":
        return await service.investigate_threat(payload.target_id, operator_name=operator)
    elif inv_type == "ASSET":
        return await service.investigate_asset(payload.target_id, operator_name=operator)
    else:
        return await service.investigate_incident(payload.target_id, operator_name=operator)


@router.post(
    "/hunt",
    response_model=ThreatHuntResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Proactive AI Threat Hunt",
)
async def execute_threat_hunt(
    payload: ThreatHuntRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> ThreatHuntResponse:
    """Run proactive threat hunt by IP, domain, hash, username, asset, or MITRE technique."""
    service = AIThreatHuntingService(db)
    operator = f"{current_user.first_name} {current_user.last_name}"
    return await service.execute_hunt(
        hunt_type=payload.hunt_type, query_value=payload.query_value, operator_name=operator
    )


@router.post(
    "/risk-assessment",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="AI Business Risk & Predictive Assessment",
)
async def get_risk_assessment(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> RiskAssessmentResponse:
    """Compute platform-wide AI risk score and attack spread predictions."""
    service = AIRiskAssessmentService(db)
    return await service.calculate_risk_assessment()


@router.post(
    "/recommend",
    response_model=RecommendationResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate AI Response Recommendations",
)
async def get_ai_recommendations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> RecommendationResponse:
    """Generate Playbook, remediation, containment, and recovery recommendations."""
    service = AIRecommendationService(db)
    return await service.generate_recommendations()


@router.post(
    "/summary",
    response_model=InvestigationResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate Executive AI Summary",
)
async def get_executive_summary(
    payload: InvestigationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> InvestigationResponse:
    """Generate high-level executive security summary."""
    service = AIInvestigationService(db)
    operator = f"{current_user.first_name} {current_user.last_name}"
    return await service.investigate_incident(payload.target_id, operator_name=operator)


@router.get(
    "/history",
    response_model=InvestigationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List AI Investigation Audit History",
)
async def list_investigation_history(
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 25,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> InvestigationListResponse:
    """Fetch paginated AI investigation audit history logs."""
    service = AIInvestigationService(db)
    items = await service.list_investigations(page=page, page_size=page_size)
    return InvestigationListResponse(total=len(items), items=items)
