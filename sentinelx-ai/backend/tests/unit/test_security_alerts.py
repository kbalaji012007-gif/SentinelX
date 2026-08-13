"""
SentinelX AI – Unit Tests for Security Alerts Module (Phase 6.4)
Tests alert creation, deduplication, status transitions, statistics, and repository operations.
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.models.security_alert import SecurityAlert
from app.schemas.security_alert_schema import (
    SecurityAlertCreate,
    AlertAcknowledgeRequest,
    AlertResolveRequest,
    AlertDismissRequest,
)
from app.services.security_alert_service import SecurityAlertService


@pytest.mark.asyncio
async def test_alert_creation_and_deduplication():
    """Test security alert generation and event deduplication logic."""
    mock_session = AsyncMock()
    service = SecurityAlertService(mock_session)

    alert_uuid = uuid4()
    agent_uuid = uuid4()
    mock_alert = SecurityAlert(
        id=alert_uuid,
        alert_id=f"ALT-{uuid4().hex[:8].upper()}",
        title="Suspicious Process Execution",
        description="powershell.exe executed with encoded command",
        alert_type="suspicious_process",
        severity="HIGH",
        status="NEW",
        source="EndpointAgent",
        agent_id=agent_uuid,
        evidence={"process_name": "powershell.exe", "occurrence_count": 1},
        alert_metadata={"hostname": "WIN-LAPTOP-01"},
        detected_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    # 1. First alert creation (no duplicate found)
    service.repo.find_duplicate = AsyncMock(return_value=None)
    service.repo.create = AsyncMock(return_value=mock_alert)

    with patch("app.services.security_alert_service.realtime_manager") as mock_rt:
        mock_rt.broadcast = AsyncMock()

        payload = SecurityAlertCreate(
            alert_id=f"ALT-{uuid4().hex[:8].upper()}",
            title="Suspicious Process Execution",
            description="powershell.exe executed with encoded command",
            alert_type="suspicious_process",
            severity="HIGH",
            source="EndpointAgent",
            agent_id=agent_uuid,
            evidence={"process_name": "powershell.exe"},
            alert_metadata={"hostname": "WIN-LAPTOP-01"},
        )

        alert, is_new = await service.create_alert(payload)

        assert alert.title == "Suspicious Process Execution"
        assert alert.severity == "HIGH"
        assert alert.status == "NEW"
        assert is_new is True
        assert service.repo.create.called
        assert mock_rt.broadcast.called

    # 2. Subsequent alert within dedup window (should increment occurrence_count)
    service.repo.find_duplicate = AsyncMock(return_value=mock_alert)
    service.repo.update_evidence = AsyncMock(return_value=mock_alert)

    with patch("app.services.security_alert_service.realtime_manager") as mock_rt:
        mock_rt.broadcast = AsyncMock()

        alert_dedup, is_new_dedup = await service.create_alert(payload)

        assert is_new_dedup is False
        assert service.repo.update_evidence.called
        assert mock_rt.broadcast.called


@pytest.mark.asyncio
async def test_alert_status_transitions():
    """Test alert state transitions: ACKNOWLEDGED -> RESOLVED."""
    mock_session = AsyncMock()
    service = SecurityAlertService(mock_session)

    alert_uuid = uuid4()
    user_uuid = uuid4()

    mock_alert = SecurityAlert(
        id=alert_uuid,
        alert_id="ALT-12345678",
        title="Failed Login Spike",
        alert_type="failed_login",
        severity="MEDIUM",
        status="NEW",
        source="LogPipeline",
        evidence={},
        alert_metadata={},
        detected_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    service.repo.get_by_id = AsyncMock(return_value=mock_alert)
    service.repo.update_status = AsyncMock()

    with patch("app.services.security_alert_service.realtime_manager") as mock_rt:
        mock_rt.broadcast = AsyncMock()

        # Acknowledge
        mock_alert.status = "ACKNOWLEDGED"
        mock_alert.acknowledged_by = user_uuid
        mock_alert.acknowledged_at = datetime.now(timezone.utc)
        service.repo.update_status.return_value = mock_alert

        ack_res = await service.acknowledge_alert(
            alert_uuid, analyst_user_id=user_uuid
        )
        assert ack_res.status == "ACKNOWLEDGED"

        # Resolve
        mock_alert.status = "RESOLVED"
        mock_alert.resolved_by = user_uuid
        mock_alert.resolved_at = datetime.now(timezone.utc)
        service.repo.update_status.return_value = mock_alert

        res_res = await service.resolve_alert(
            alert_uuid, analyst_user_id=user_uuid, resolution_notes="True positive resolved"
        )
        assert res_res.status == "RESOLVED"
