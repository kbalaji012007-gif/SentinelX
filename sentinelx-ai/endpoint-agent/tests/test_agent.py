"""
SentinelX Endpoint Agent – Python Unit Tests
Tests host identity collection, collector execution, and test-mode simulated event tagging.
"""

import sys
import unittest
from pathlib import Path

# Add package root to python search path
pkg_root = Path(__file__).resolve().parent.parent
if str(pkg_root) not in sys.path:
    sys.path.insert(0, str(pkg_root))

from src.identity import IdentityManager
from src.collectors.windows_events import WindowsEventCollector
from src.collectors.processes import ProcessCollector
from src.collectors.network import NetworkCollector
from src.collectors.system import SystemCollector


class TestEndpointAgent(unittest.TestCase):
    """Test suite for endpoint agent collectors and identity manager."""

    def test_identity_manager_metadata(self):
        id_mgr = IdentityManager()
        identity = id_mgr.collect_host_identity()

        self.assertIsNotNone(identity.agent_id)
        self.assertIsNotNone(identity.hostname)
        self.assertIsNotNone(identity.platform)
        self.assertEqual(identity.agent_version, "1.0.0")

    def test_windows_events_collector_test_mode(self):
        collector = WindowsEventCollector(test_mode=True)
        items = collector.collect()

        self.assertGreaterEqual(len(items), 1)
        for item in items:
            self.assertTrue(item.is_simulated)
            self.assertTrue(item.payload.get("is_simulated"))

    def test_process_collector(self):
        collector = ProcessCollector(test_mode=True)
        items = collector.collect()

        self.assertGreaterEqual(len(items), 1)
        for item in items:
            self.assertEqual(item.event_type, "process")
            self.assertTrue(item.is_simulated)

    def test_network_collector(self):
        collector = NetworkCollector(test_mode=True)
        items = collector.collect()

        # May return zero or more depending on socket permissions
        self.assertIsInstance(items, list)

    def test_system_collector(self):
        collector = SystemCollector(test_mode=True)
        items = collector.collect()

        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item.event_type, "system_health")
        self.assertIn("cpu_usage_percent", item.payload)
        self.assertIn("memory_used_percent", item.payload)


if __name__ == "__main__":
    unittest.main()
