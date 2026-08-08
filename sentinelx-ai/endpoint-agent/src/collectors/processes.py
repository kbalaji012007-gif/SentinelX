"""
SentinelX Endpoint Agent – Process Telemetry Collector
Gathers active running process metadata, parent PIDs, executable paths, and SHA256 hashes safely.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import psutil

from src.models.telemetry import TelemetryItem

logger = logging.getLogger("sentinelx-agent")


class ProcessCollector:
    """Collector gathering active running process information."""

    def __init__(self, compute_hashes: bool = False, test_mode: bool = False) -> None:
        self.compute_hashes = compute_hashes
        self.test_mode = test_mode

    def collect(self) -> List[TelemetryItem]:
        """Collect top active process metadata."""
        items: List[TelemetryItem] = []
        now = datetime.now(timezone.utc)

        try:
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'username', 'create_time']):
                try:
                    info = proc.info
                    name = info.get('name') or 'unknown'
                    exe = info.get('exe') or ''

                    # Filter out system low-level idle process noise
                    if name.lower() in ('system idle process', 'idle'):
                        continue

                    file_hash = None
                    if self.compute_hashes and exe:
                        file_hash = self._hash_file(exe)

                    payload = {
                        "pid": info.get('pid'),
                        "parent_pid": info.get('ppid'),
                        "process_name": name,
                        "executable_path": exe,
                        "username": info.get('username'),
                        "start_time": datetime.fromtimestamp(info.get('create_time', 0), tz=timezone.utc).isoformat() if info.get('create_time') else None,
                        "sha256_hash": file_hash,
                    }

                    if self.test_mode:
                        payload["is_simulated"] = True

                    items.append(
                        TelemetryItem(
                            event_type="process",
                            event_timestamp=now,
                            severity="INFO",
                            payload=payload,
                            source="ProcessCollector",
                            is_simulated=self.test_mode,
                        )
                    )

                    # Cap batch size to top 25 processes per poll to avoid excessive traffic
                    if len(items) >= 25:
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as exc:
            logger.error(f"Process collection error: {exc}")

        return items

    @staticmethod
    def _hash_file(filepath: str) -> Optional[str]:
        """Safely compute SHA256 hash of an executable file."""
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                chunk = f.read(8192)
                while chunk:
                    h.update(chunk)
                    chunk = f.read(8192)
            return h.hexdigest()
        except Exception:
            return None
