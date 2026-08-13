"""
SentinelX AI – Unit Tests for Real-Time Monitoring & WebSockets (Phase 6.4)
Tests connection manager registration, event broadcasting, and event type definitions.
"""

import pytest
import json
from uuid import uuid4
from unittest.mock import AsyncMock

from app.realtime.manager import RealtimeConnectionManager
from app.realtime.events import RealtimeEventType


@pytest.mark.asyncio
async def test_connection_manager_lifecycle():
    """Test connecting, tracking, and disconnecting WebSockets in manager."""
    manager = RealtimeConnectionManager()
    assert manager.connection_count == 0

    user_id_1 = str(uuid4())
    mock_ws_1 = AsyncMock()

    # Connect WS 1
    await manager.connect(mock_ws_1, user_id=user_id_1)
    assert manager.connection_count == 1
    assert user_id_1 in manager.connected_users

    # Disconnect WS 1
    await manager.disconnect(user_id=user_id_1)
    assert manager.connection_count == 0
    assert user_id_1 not in manager.connected_users


@pytest.mark.asyncio
async def test_broadcast_event():
    """Test broadcasting real-time event to all active user connections."""
    manager = RealtimeConnectionManager()

    user_1 = str(uuid4())
    user_2 = str(uuid4())

    ws1 = AsyncMock()
    ws2 = AsyncMock()

    await manager.connect(ws1, user_id=user_1)
    await manager.connect(ws2, user_id=user_2)

    sent_count = await manager.broadcast(
        RealtimeEventType.ALERT_CREATED,
        {
            "alert_id": "ALT-9999",
            "title": "Malware Detected",
            "alert_type": "malware_detected",
            "severity": "CRITICAL",
            "status": "NEW",
        },
    )

    assert sent_count == 2
    assert ws1.send_text.called
    assert ws2.send_text.called

    sent_data_1 = json.loads(ws1.send_text.call_args[0][0])
    assert sent_data_1["event"] == RealtimeEventType.ALERT_CREATED
    assert sent_data_1["payload"]["title"] == "Malware Detected"
    assert sent_data_1["payload"]["severity"] == "CRITICAL"


def test_realtime_event_type_constants():
    """Test structure of RealtimeEventType constants."""
    assert RealtimeEventType.ALERT_CREATED == "alert.created"
    assert RealtimeEventType.TELEMETRY_RECEIVED == "telemetry.received"
    assert RealtimeEventType.ENDPOINT_ONLINE == "endpoint.online"
    assert RealtimeEventType.ENDPOINT_OFFLINE == "endpoint.offline"
