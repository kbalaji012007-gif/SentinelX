"""
SentinelX Endpoint Agent – Network Telemetry Collector
Collects active network socket connections (local/remote addresses, ports, protocol, associated PID).
Does NOT perform packet capture or network scanning.
"""

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
import psutil

from src.models.telemetry import TelemetryItem

logger = logging.getLogger("sentinelx-agent")


class NetworkCollector:
    """Collector gathering active network connection metadata."""

    def __init__(self, test_mode: bool = False) -> None:
        self.test_mode = test_mode

    def collect(self) -> List[TelemetryItem]:
        """Collect active socket connections."""
        items: List[TelemetryItem] = []
        now = datetime.now(timezone.utc)

        try:
            connections = psutil.net_connections(kind="inet")
            for conn in connections[:25]:
                if not conn.raddr:
                    continue  # Focus on connected remote sockets

                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                proto = "TCP" if conn.type == 1 else "UDP"

                payload = {
                    "local_address": conn.laddr.ip if conn.laddr else None,
                    "local_port": conn.laddr.port if conn.laddr else None,
                    "remote_address": conn.raddr.ip if conn.raddr else None,
                    "remote_port": conn.raddr.port if conn.raddr else None,
                    "protocol": proto,
                    "pid": conn.pid,
                    "connection_state": conn.status,
                }

                if self.test_mode:
                    payload["is_simulated"] = True

                items.append(
                    TelemetryItem(
                        event_type="network_connection",
                        event_timestamp=now,
                        severity="INFO",
                        payload=payload,
                        source="NetworkCollector",
                        is_simulated=self.test_mode,
                    )
                )

                if len(items) >= 20:
                    break
        except (psutil.AccessDenied, PermissionError):
            logger.warning("Permission denied reading active network connections. Elevation may be required.")
        except Exception as exc:
            logger.error(f"Network telemetry collection error: {exc}")

        return items
