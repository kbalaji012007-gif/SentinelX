"""
SentinelX AI – AI SOC Analyst & Copilot API Router
JWT-protected, RBAC-enforced endpoints for AI Investigations, Threat Hunting, Copilot Natural Language Chat, Explainability, Multi-Format Report Generation, and History.
"""

from uuid import UUID
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
from app.schemas.ai_copilot_schema import (
    AIChatRequest,
    AIChatMessageResponse,
    AIChatConversationResponse,
    ConversationListResponse,
    AIExplainRequest,
    AIExplainResponse,
    AIReportRequest,
    AIReportResponse,
)
from app.services.ai_soc import (
    AIInvestigationService,
    AIThreatHuntingService,
    AIRiskAssessmentService,
    AIRecommendationService,
    AICopilotService,
    AIReportGeneratorService,
)

router = APIRouter(prefix="/ai", tags=["AI SOC Analyst & Copilot"])

# RBAC roles
_READERS = ["Admin", "Manager", "Analyst", "ReadOnly"]
_WRITERS = ["Admin", "Manager", "Analyst"]
_ADMINS = ["Admin", "Manager"]


# ────────────────────────────────────────────────────────────────────────
# Copilot Natural Language Chat & Explainability Endpoints
# ────────────────────────────────────────────────────────────────────────

@router.post(
    "/chat",
    response_model=AIChatMessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Copilot Natural Language Security Chat",
)
async def copilot_chat(
    payload: AIChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> AIChatMessageResponse:
    """Interact with Enterprise AI Copilot using natural language security queries."""
    service = AICopilotService(db)
    user_name = f"{current_user.first_name} {current_user.last_name}"
    return await service.chat_interaction(payload, user_name=user_name)


@router.post(
    "/explain",
    response_model=AIExplainResponse,
    status_code=status.HTTP_200_OK,
    summary="AI Explainability Breakdown",
)
async def explain_entity(
    payload: AIExplainRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_READERS)),
) -> AIExplainResponse:
    """Generate deep AI explainability for Incidents, Correlations, Attack Chains, MITRE, or Playbooks."""
    service = AICopilotService(db)
    return await service.explain_entity(entity_type=payload.entity_type, entity_id=payload.entity_id)


@router.post(
    "/report",
    response_model=AIReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate AI Security Report",
)
async def generate_report(
    payload: AIReportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_WRITERS)),
) -> AIReportResponse:
    """Generate security report in Markdown, JSON, or PDF structure."""
    service = AIReportGeneratorService(db)
    user_name = f"{current_user.first_name} {current_user.last_name}"
    return await service.generate_report(payload, user_name=user_name)


# ────────────────────────────────────────────────────────────────────────
# Investigation & Threat Hunting Endpoints
# ────────────────────────────────────────────────────────────────────────

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


@router.delete(
    "/history/{id}",
    status_code=status.HTTP_200_OK,
    summary="Delete Investigation / Chat History",
)
async def delete_history_item(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(RequireRole(_ADMINS)),
) -> dict[str, str]:
    """Delete investigation history item or chat conversation."""
    service = AICopilotService(db)
    await service.chat_repo.delete_conversation(id)
    return {"message": f"History item '{id}' deleted successfully."}
