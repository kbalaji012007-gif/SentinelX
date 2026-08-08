"""
SentinelX Endpoint Agent – Main Agent Manager
Orchestrates agent enrollment, heartbeat thread, collector scheduling, and HTTPS telemetry transport.
"""

import time
import logging
from typing import List, Optional

from src.config import AgentConfig
from src.identity import IdentityManager
from src.transport import Transport
from src.heartbeat import HeartbeatService
from src.collectors.windows_events import WindowsEventCollector
from src.collectors.processes import ProcessCollector
from src.collectors.network import NetworkCollector
from src.collectors.system import SystemCollector
from src.models.telemetry import TelemetryItem, TelemetryBatch

logger = logging.getLogger("sentinelx-agent")


class SentinelXAgent:
    """Main Agent class orchestrating identity, collectors, heartbeat, and transport."""

    def __init__(self, test_mode: bool = False, once: bool = False) -> None:
        self.test_mode = test_mode or AgentConfig.TEST_MODE
        self.once = once
        self.identity_mgr = IdentityManager()
        self.transport = Transport()

        self.win_collector = WindowsEventCollector(test_mode=self.test_mode)
        self.proc_collector = ProcessCollector(test_mode=self.test_mode)
        self.net_collector = NetworkCollector(test_mode=self.test_mode)
        self.sys_collector = SystemCollector(test_mode=self.test_mode)

        self.heartbeat_svc: Optional[HeartbeatService] = None
        self._running = False

    def setup(self) -> bool:
        """Enroll or restore agent identity credentials."""
        logger.info("Initializing SentinelX Endpoint Telemetry Agent...")
        host_id = self.identity_mgr.collect_host_identity()

        if self.test_mode:
            logger.info("Running agent in TEST MODE. Events will be tagged as SIMULATED.")

        # Enroll with SentinelX backend if token missing
        if not AgentConfig.AGENT_TOKEN:
            logger.info(f"Enrolling agent '{host_id.agent_id}' with backend at {AgentConfig.SENTINELX_API_URL}...")
            res = self.transport.enroll(host_id)
            if res and "agent_token" in res:
                self.identity_mgr.save_credentials(res["agent_id"], res["agent_token"])
                logger.info("Agent enrollment complete!")
            else:
                logger.warning("Enrollment response did not yield a valid token. Operating with local fallback token.")
                # Fallback to local offline signature token if backend unavailable
                token = f"agent-offline-token-{host_id.agent_id}"
                self.identity_mgr.save_credentials(host_id.agent_id, token)

        # Initialize Heartbeat service
        self.heartbeat_svc = HeartbeatService(self.transport, host_id.agent_id, host_id.hostname)
        return True

    def collect_all_telemetry(self) -> List[TelemetryItem]:
        """Run all collectors and aggregate telemetry events."""
        items: List[TelemetryItem] = []

        # System health
        sys_items = self.sys_collector.collect()
        items.extend(sys_items)

        # Windows Event Log
        win_items = self.win_collector.collect()
        items.extend(win_items)

        # Process metadata
        proc_items = self.proc_collector.collect()
        items.extend(proc_items)

        # Network connections
        net_items = self.net_collector.collect()
        items.extend(net_items)

        # Ensure agent_id is populated on all items
        agent_id = self.identity_mgr.get_or_create_agent_id()
        for item in items:
            item.agent_id = agent_id
            if self.test_mode:
                item.is_simulated = True
                item.payload["is_simulated"] = True
                item.payload["tag"] = "SIMULATED_TEST_EVENT"

        return items

    def run_once(self) -> int:
        """Collect and dispatch a single telemetry batch."""
        self.setup()

        # Send heartbeat
        host_id = self.identity_mgr.collect_host_identity()
        self.transport.send_heartbeat(host_id.agent_id, host_id.hostname, uptime=0)

        items = self.collect_all_telemetry()
        if not items:
            logger.info("No telemetry items collected.")
            return 0

        batch = TelemetryBatch(agent_id=host_id.agent_id, telemetry=items)
        res = self.transport.send_telemetry_batch(batch)

        if res:
            logger.info(f"Successfully transmitted batch of {len(items)} telemetry items.")
            return len(items)
        else:
            logger.warning(f"Failed to transmit telemetry batch ({len(items)} items queued).")
            return 0

    def start(self) -> None:
        """Start agent main loop and heartbeat thread."""
        if not self.setup():
            logger.error("Agent setup failed. Exiting.")
            return

        if self.once:
            self.run_once()
            return

        if self.heartbeat_svc:
            self.heartbeat_svc.start()

        self._running = True
        logger.info(f"Agent telemetry collection loop active (Interval: {AgentConfig.TELEMETRY_INTERVAL}s). Press Ctrl+C to exit.")

        try:
            while self._running:
                host_id = self.identity_mgr.collect_host_identity()
                items = self.collect_all_telemetry()
                if items:
                    batch = TelemetryBatch(agent_id=host_id.agent_id, telemetry=items)
                    self.transport.send_telemetry_batch(batch)
                time.sleep(AgentConfig.TELEMETRY_INTERVAL)
        except KeyboardInterrupt:
            logger.info("Agent shutdown requested by user.")
        finally:
            self.stop()

    def stop(self) -> None:
        """Gracefully shutdown agent."""
        self._running = False
        if self.heartbeat_svc:
            self.heartbeat_svc.stop()
        logger.info("SentinelX Endpoint Agent shutdown complete.")
