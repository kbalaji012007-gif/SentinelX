"""
SentinelX Endpoint Agent – System Health Collector
Collects host performance metrics (CPU, RAM, Disk, Uptime, IP) for endpoint health monitoring.
"""

import time
import socket
import platform
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
import psutil

from src.models.telemetry import TelemetryItem

logger = logging.getLogger("sentinelx-agent")


class SystemCollector:
    """Collector gathering system performance and health metrics."""

    def __init__(self, test_mode: bool = False) -> None:
        self.test_mode = test_mode

    def collect(self) -> List[TelemetryItem]:
        """Collect current system metrics."""
        now = datetime.now(timezone.utc)

        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            boot_time = psutil.boot_time()
            uptime_seconds = int(time.time() - boot_time)

            local_ip = self._get_local_ip()

            payload = {
                "hostname": socket.gethostname(),
                "os": platform.system(),
                "os_version": platform.version(),
                "architecture": platform.machine(),
                "cpu_usage_percent": cpu_percent,
                "memory_total_bytes": mem.total,
                "memory_used_percent": mem.percent,
                "disk_total_bytes": disk.total,
                "disk_used_percent": disk.percent,
                "uptime_seconds": uptime_seconds,
                "local_ip": local_ip,
            }

            if self.test_mode:
                payload["is_simulated"] = True

            return [
                TelemetryItem(
                    event_type="system_health",
                    event_timestamp=now,
                    severity="INFO",
                    payload=payload,
                    source="SystemCollector",
                    is_simulated=self.test_mode,
                )
            ]
        except Exception as exc:
            logger.error(f"System health collection error: {exc}")
            return []

    @staticmethod
    def _get_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
