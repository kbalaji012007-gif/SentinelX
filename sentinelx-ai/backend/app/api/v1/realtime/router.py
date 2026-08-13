"""
SentinelX AI – Real-Time WebSocket API Router (Phase 6.4)
Provides authenticated WebSocket connection for SOC clients to receive live events.
"""

import asyncio
from typing import Optional

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status

from app.api.deps import async_session_factory
from app.core.security import decode_token
from app.repositories.user_repo import UserRepository
from app.realtime.manager import realtime_manager

logger = structlog.get_logger()

router = APIRouter(prefix="/realtime", tags=["Real-Time SOC"])

# Heartbeat interval in seconds
_HEARTBEAT_INTERVAL = 30


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None, description="JWT access token for authentication"),
) -> None:
    """
    Authenticated WebSocket endpoint for real-time SOC event streaming.

    Connection: wss://<backend>/api/v1/realtime/ws?token=<jwt>

    Events streamed:
    - connection.established
    - ping (every 30s)
    - alert.created / alert.updated / alert.acknowledged / etc.
    - endpoint.status_changed
    - telemetry.received (HIGH/CRITICAL only)
    - threat.detected
    - incident.created
    - soar.execution_* events
    """
    # ── 1. Authenticate before accepting ─────────────────────────────────────
    if not token:
        await websocket.close(code=4001, reason="Authentication required: missing token")
        logger.warning("realtime_ws_rejected_no_token", client=str(websocket.client))
        return

    # Decode JWT using the existing security module
    try:
        payload = decode_token(token)
        user_id_str: Optional[str] = payload.get("sub")
        if not user_id_str:
            await websocket.close(code=4001, reason="Invalid token: missing subject")
            return
    except HTTPException:
        await websocket.close(code=4001, reason="Authentication failed: invalid or expired token")
        logger.warning("realtime_ws_rejected_invalid_token", client=str(websocket.client))
        return

    # ── 2. Verify user still exists and is active ─────────────────────────────
    try:
        from uuid import UUID
        user_uuid = UUID(user_id_str)
        async with async_session_factory() as session:
            user_repo = UserRepository(session)
            user = await user_repo.get_by_id_with_role(user_uuid)
            if not user or not user.is_active:
                await websocket.close(code=4003, reason="User account inactive or not found")
                return
            user_role = user.role.name if user.role else "Read Only"
    except Exception as exc:
        logger.error("realtime_ws_user_verification_failed", error=str(exc))
        await websocket.close(code=4001, reason="Authentication error")
        return

    # ── 3. Accept connection ──────────────────────────────────────────────────
    await realtime_manager.connect(websocket, user_id_str)
    logger.info(
        "realtime_ws_connected",
        user_id=user_id_str,
        user_role=user_role,
        active_connections=realtime_manager.connection_count,
    )

    # ── 4. Main message loop with heartbeat ───────────────────────────────────
    heartbeat_task = asyncio.create_task(_heartbeat_loop(websocket, user_id_str))

    try:
        while True:
            # Wait for client messages (pong responses, etc.)
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=_HEARTBEAT_INTERVAL + 5)
                # Handle pong or client-initiated messages
                if data.strip() == "pong" or '"event":"pong"' in data:
                    pass  # Acknowledged
            except asyncio.TimeoutError:
                # No message received – client may be gone, heartbeat loop handles it
                pass

    except WebSocketDisconnect:
        logger.info("realtime_ws_client_disconnected", user_id=user_id_str)
    except Exception as exc:
        logger.warning("realtime_ws_unexpected_error", user_id=user_id_str, error=str(exc))
    finally:
        heartbeat_task.cancel()
        await realtime_manager.disconnect(user_id_str)


async def _heartbeat_loop(websocket: WebSocket, user_id: str) -> None:
    """Send periodic pings to keep the WebSocket alive and detect dead connections."""
    import json
    from datetime import datetime, timezone

    while True:
        try:
            await asyncio.sleep(_HEARTBEAT_INTERVAL)
            ping_msg = json.dumps({
                "event": "ping",
                "payload": {"server_time": datetime.now(timezone.utc).isoformat()},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            await websocket.send_text(ping_msg)
        except (WebSocketDisconnect, Exception):
            break


@router.get(
    "/status",
    status_code=status.HTTP_200_OK,
    summary="Real-time connection status",
    tags=["Real-Time SOC"],
)
async def get_realtime_status() -> dict:
    """Returns the current number of active WebSocket connections."""
    return {
        "active_connections": realtime_manager.connection_count,
        "connected_users": realtime_manager.connection_count,
        "realtime_enabled": True,
    }
