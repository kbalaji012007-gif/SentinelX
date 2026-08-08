"""
SentinelX Endpoint Agent – Heartbeat Service
Periodic background worker sending heartbeat status signals to the SentinelX backend.
"""

import time
import logging
import threading
from typing import Callable, Optional

from src.config import AgentConfig
from src.transport import Transport

logger = logging.getLogger("sentinelx-agent")


class HeartbeatService:
    """Manages periodic background heartbeat dispatching."""

    def __init__(self, transport: Transport, agent_id: str, hostname: str) -> None:
        self.transport = transport
        self.agent_id = agent_id
        self.hostname = hostname
        self.interval = AgentConfig.HEARTBEAT_INTERVAL
        self.start_time = time.time()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start heartbeat worker thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="SentinelX-Heartbeat")
        self._thread.start()
        logger.info(f"Heartbeat worker started (Interval: {self.interval}s)")

    def stop(self) -> None:
        """Stop heartbeat worker thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        logger.info("Heartbeat worker stopped.")

    def _run_loop(self) -> None:
        """Background execution loop."""
        while self._running:
            uptime = int(time.time() - self.start_time)
            res = self.transport.send_heartbeat(self.agent_id, self.hostname, uptime)
            if res:
                logger.debug(f"Heartbeat OK. Status: {res.get('status')}")
            time.sleep(self.interval)
