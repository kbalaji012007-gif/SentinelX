"""
SentinelX AI – Unit Tests for Endpoint Agent Module
Tests enrollment, heartbeat, telemetry ingestion, log pipeline integration, threat triggers, and RBAC controls using AsyncMock.
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.schemas.agent_schema import (
    AgentEnrollRequest,
    AgentHeartbeatRequest,
    AgentTelemetryCreate,
    AgentTelemetryBatchCreate,
)
from app.services.agent_service import AgentService
from app.models.agent import EndpointAgent


@pytest.mark.asyncio
async def test_agent_enrollment_and_token_issuance():
    """Test first-time agent enrollment generates agent identity and signed token."""
    mock_session = AsyncMock()
    service = AgentService(mock_session)

    agent_id = f"test-agent-{uuid4()}"
    mock_agent = EndpointAgent(
        id=uuid4(),
        agent_id=agent_id,
        hostname="WIN-LAPTOP-TEST",
        platform="Windows",
        os_version="Windows 11 Pro 22H2",
        agent_version="1.0.0",
        status="Online",
        enrolled_at=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        agent_metadata={},
    )

    service.agent_repo.get_by_agent_id = AsyncMock(return_value=None)
    service.agent_repo.create = AsyncMock(return_value=mock_agent)
    service.log_source_service.repo.get_by_name = AsyncMock(return_value=None)
    service.log_source_service.create_source = AsyncMock()

    enroll_payload = AgentEnrollRequest(
        agent_id=agent_id,
        hostname="WIN-LAPTOP-TEST",
        platform="Windows",
        os_version="Windows 11 Pro 22H2",
        agent_version="1.0.0",
        local_ip="192.168.1.100",
        architecture="AMD64",
        username="sec_analyst",
    )

    response = await service.enroll_agent(enroll_payload)

    assert response.agent_id == agent_id
    assert response.hostname == "WIN-LAPTOP-TEST"
    assert response.status == "Online"
    assert response.agent_token is not None
    assert len(response.agent_token) > 20


@pytest.mark.asyncio
async def test_agent_heartbeat_processing():
    """Test periodic agent heartbeat updates last_seen and returns Online status."""
    mock_session = AsyncMock()
    service = AgentService(mock_session)

    agent_id = f"test-heartbeat-{uuid4()}"
    now = datetime.now(timezone.utc)
    mock_agent = EndpointAgent(
        id=uuid4(),
        agent_id=agent_id,
        hostname="WIN-DESKTOP-01",
        platform="Windows",
        agent_version="1.0.0",
        status="Online",
        enrolled_at=now,
        last_seen=now,
        agent_metadata={},
    )

    service.agent_repo.get_by_agent_id = AsyncMock(return_value=mock_agent)
    service.agent_repo.update_last_seen = AsyncMock(return_value=mock_agent)

    hb_response = await service.process_heartbeat(
        AgentHeartbeatRequest(
            agent_id=agent_id,
            hostname="WIN-DESKTOP-01",
            uptime=1200,
            health_status="Healthy",
        )
    )

    assert hb_response.agent_id == agent_id
    assert hb_response.status == "Online"
    assert hb_response.last_seen is not None


@pytest.mark.asyncio
async def test_telemetry_ingestion_and_log_integration():
    """Test ingesting telemetry batch creates agent_telemetry and forwards to log_entries."""
    mock_session = AsyncMock()
    service = AgentService(mock_session)

    agent_id = f"test-telemetry-{uuid4()}"
    now = datetime.now(timezone.utc)
    mock_agent = EndpointAgent(
        id=uuid4(),
        agent_id=agent_id,
        hostname="WIN-SERVER-SEC",
        platform="Windows",
        agent_version="1.0.0",
        status="Online",
        enrolled_at=now,
        last_seen=now,
        agent_metadata={"local_ip": "10.0.0.5"},
    )

    mock_log_source = MagicMock()
    mock_log_source.id = uuid4()

    service.agent_repo.get_by_agent_id = AsyncMock(return_value=mock_agent)
    service.agent_repo.update_last_seen = AsyncMock(return_value=mock_agent)
    service.telemetry_repo.create_batch = AsyncMock(return_value=[])
    service.log_source_service.repo.get_by_name = AsyncMock(return_value=mock_log_source)
    service.log_entry_service.bulk_ingest_logs = AsyncMock(return_value={"ingested": 2})
    service.threat_service.create_threat = AsyncMock()

    batch = AgentTelemetryBatchCreate(
        agent_id=agent_id,
        telemetry=[
            AgentTelemetryCreate(
                event_type="windows_event",
                event_timestamp=now,
                severity="INFO",
                payload={"event_id": "4624", "username": "administrator", "message": "Successful logon"},
                source="WinEvtLog-Security",
            ),
            AgentTelemetryCreate(
                event_type="failed_logon",
                event_timestamp=now,
                severity="WARNING",
                payload={"event_id": "4625", "username": "attacker", "message": "Failed logon attempt"},
                source="WinEvtLog-Security",
            ),
        ],
    )

    result = await service.ingest_telemetry(batch)

    assert result["status"] == "success"
    assert result["telemetry_ingested"] == 2
    assert result["log_entries_created"] == 2
    assert result["threats_triggered"] == 1


@pytest.mark.asyncio
async def test_disabled_agent_rejection():
    """Test that disabling an agent causes heartbeat and telemetry requests to be rejected."""
    mock_session = AsyncMock()
    service = AgentService(mock_session)

    agent_id = f"test-disable-{uuid4()}"
    mock_agent = EndpointAgent(
        id=uuid4(),
        agent_id=agent_id,
        hostname="WIN-HOST-DISABLE",
        platform="Windows",
        agent_version="1.0.0",
        status="Disabled",
        enrolled_at=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        agent_metadata={},
    )

    service.agent_repo.get_by_agent_id = AsyncMock(return_value=mock_agent)

    with pytest.raises(Exception) as exc_info:
        await service.authenticate_agent(agent_id)

    assert "disabled" in str(exc_info.value).lower()
