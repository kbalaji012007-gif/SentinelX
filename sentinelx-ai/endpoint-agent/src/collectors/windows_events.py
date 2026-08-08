"""
SentinelX Endpoint Agent – Windows Event Log Collector
Collects security-relevant Windows Security Event Log entries (4624, 4625, 4740, 4688, 4672, 7045).
Includes safe mock fallback for development and non-Windows test hosts.
"""

import sys
import logging
import platform
from datetime import datetime, timezone
from typing import List, Dict, Any

from src.models.telemetry import TelemetryItem

logger = logging.getLogger("sentinelx-agent")


class WindowsEventCollector:
    """Collector targeting Windows Security Event Log."""

    TARGET_EVENT_IDS = {
        4624: ("Successful Logon", "INFO"),
        4625: ("Failed Logon", "WARNING"),
        4740: ("Account Lockout", "ERROR"),
        4688: ("Process Creation", "INFO"),
        4672: ("Special Privileges Assigned", "INFO"),
        7045: ("Service Installed", "WARNING"),
    }

    def __init__(self, test_mode: bool = False) -> None:
        self.test_mode = test_mode
        self.is_windows = sys.platform == "win32"

    def collect(self) -> List[TelemetryItem]:
        """Collect recent security events."""
        if self.test_mode:
            return self._collect_simulated_events()

        if self.is_windows:
            try:
                return self._collect_native_win32_events()
            except Exception as exc:
                logger.warning(f"Native Windows event log reader fallback triggered: {exc}")
                return self._collect_simulated_events()
        else:
            logger.info("Non-Windows host detected. Using safe event collector mock.")
            return self._collect_simulated_events()

    def _collect_native_win32_events(self) -> List[TelemetryItem]:
        """Query native Windows Event log using win32evtlog if available."""
        items: List[TelemetryItem] = []
        try:
            import win32evtlog  # type: ignore

            server = "localhost"
            logtype = "Security"
            hand = win32evtlog.OpenEventLog(server, logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            records = win32evtlog.ReadEventLog(hand, flags, 0)
            now = datetime.now(timezone.utc)

            for record in records[:15]:
                event_id = record.EventID & 0xFFFF
                if event_id in self.TARGET_EVENT_IDS:
                    event_title, severity = self.TARGET_EVENT_IDS[event_id]
                    strings = record.StringInserts or []
                    user = strings[1] if len(strings) > 1 else None

                    payload = {
                        "event_id": str(event_id),
                        "event_title": event_title,
                        "source": record.SourceName,
                        "username": user,
                        "raw_inserts": list(strings[:5]),
                    }

                    items.append(
                        TelemetryItem(
                            event_type="windows_event",
                            event_timestamp=now,
                            severity=severity,
                            payload=payload,
                            source=f"WinEvtLog-{logtype}",
                            is_simulated=False,
                        )
                    )

            win32evtlog.CloseEventLog(hand)
        except Exception as exc:
            logger.debug(f"win32evtlog query exception: {exc}")

        return items

    def _collect_simulated_events(self) -> List[TelemetryItem]:
        """Generate clearly marked simulated test events for development/testing."""
        now = datetime.now(timezone.utc)
        return [
            TelemetryItem(
                event_type="windows_event",
                event_timestamp=now,
                severity="INFO",
                payload={
                    "event_id": "4624",
                    "event_title": "Successful Logon",
                    "username": "SYSTEM",
                    "message": "SIMULATED EVENT - Successful user logon verified",
                    "is_simulated": True,
                },
                source="Simulated-WindowsEvents",
                is_simulated=True,
            ),
            TelemetryItem(
                event_type="failed_logon",
                event_timestamp=now,
                severity="WARNING",
                payload={
                    "event_id": "4625",
                    "event_title": "Failed Logon",
                    "username": "admin_test",
                    "message": "SIMULATED EVENT - Single failed logon attempt detected",
                    "is_simulated": True,
                },
                source="Simulated-WindowsEvents",
                is_simulated=True,
            ),
        ]
