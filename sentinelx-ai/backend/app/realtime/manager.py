"""
SentinelX AI – Real-Time Connection Manager (Phase 6.4)
Manages authenticated WebSocket connections and broadcasts events to SOC clients.
Thread-safe in-memory connection pool for single-worker Render deployment.
"""

import json
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import structlog
from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

logger = structlog.get_logger()


class RealtimeConnectionManager:
    """
    Manages all active authenticated WebSocket connections.

    One connection per user_id is maintained. If the same user
    reconnects, the old connection is closed and the new one replaces it.
    """

    def __init__(self) -> None:
        # Keyed by user_id string → WebSocket
        self._connections: Dict[str, WebSocket] = {}
        # Track last ping time to detect dead connections
        self._last_ping: Dict[str, datetime] = {}

    # ── Connection Lifecycle ──────────────────────────────────────────────────

    async def connect(self, websocket: WebSocket, user_id: str) -> None:
        """Accept a new WebSocket connection and register it."""
        await websocket.accept()

        # If user already has a connection, close the old one
        if user_id in self._connections:
            old_ws = self._connections[user_id]
            try:
                if old_ws.client_state != WebSocketState.DISCONNECTED:
                    await old_ws.close(code=1001, reason="New connection established")
            except Exception:
                pass

        self._connections[user_id] = websocket
        self._last_ping[user_id] = datetime.now(timezone.utc)

        logger.info(
            "realtime_client_connected",
            user_id=user_id,
            total_connections=len(self._connections),
        )

        # Send connection established event
        await self._send_to_socket(
            websocket,
            {
                "event": "connection.established",
                "payload": {
                    "user_id": user_id,
                    "server_time": datetime.now(timezone.utc).isoformat(),
                    "ping_interval_seconds": 30,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def disconnect(self, user_id: str) -> None:
        """Remove a disconnected user from the connection pool."""
        self._connections.pop(user_id, None)
        self._last_ping.pop(user_id, None)
        logger.info(
            "realtime_client_disconnected",
            user_id=user_id,
            total_connections=len(self._connections),
        )

    # ── Broadcasting ──────────────────────────────────────────────────────────

    async def broadcast(
        self,
        event_type: str,
        payload: Dict[str, Any],
        exclude_user_id: Optional[str] = None,
    ) -> int:
        """
        Broadcast an event to ALL connected SOC clients.
        Returns the count of clients successfully notified.
        Silently drops messages to disconnected clients and removes them.
        """
        if not self._connections:
            return 0

        message = {
            "event": event_type,
            "payload": payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        disconnected: list[str] = []
        sent_count = 0

        for uid, ws in list(self._connections.items()):
            if uid == exclude_user_id:
                continue
            try:
                await self._send_to_socket(ws, message)
                sent_count += 1
            except (WebSocketDisconnect, Exception):
                disconnected.append(uid)

        # Cleanup stale connections
        for uid in disconnected:
            await self.disconnect(uid)

        if sent_count > 0:
            logger.debug(
                "realtime_event_broadcast",
                event_type=event_type,
                recipients=sent_count,
            )

        return sent_count

    async def send_to_user(
        self, user_id: str, event_type: str, payload: Dict[str, Any]
    ) -> bool:
        """Send an event to a specific connected user. Returns True if delivered."""
        ws = self._connections.get(user_id)
        if not ws:
            return False
        try:
            await self._send_to_socket(
                ws,
                {
                    "event": event_type,
                    "payload": payload,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
            return True
        except Exception:
            await self.disconnect(user_id)
            return False

    async def ping_all(self) -> None:
        """Send a ping to all connected clients to keep connections alive."""
        await self.broadcast(
            "ping",
            {"server_time": datetime.now(timezone.utc).isoformat()},
        )

    # ── Internal ─────────────────────────────────────────────────────────────

    @staticmethod
    async def _send_to_socket(ws: WebSocket, data: Dict[str, Any]) -> None:
        """Send JSON data to a specific WebSocket, raising on failure."""
        if ws.client_state == WebSocketState.DISCONNECTED:
            raise WebSocketDisconnect(code=1001)
        await ws.send_text(json.dumps(data, default=str))

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    @property
    def connected_users(self) -> list[str]:
        return list(self._connections.keys())


# ── Singleton Instance ────────────────────────────────────────────────────────
# Shared across the FastAPI application for the lifetime of the process.
realtime_manager = RealtimeConnectionManager()
