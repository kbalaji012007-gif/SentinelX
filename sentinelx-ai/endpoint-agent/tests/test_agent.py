"""
SentinelX Endpoint Agent – Python Unit Tests
Tests host identity collection, collector execution, test-mode simulated event tagging,
strict enrollment enforcement, and identity restoration.
"""

import sys
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

# Add package root to python search path
pkg_root = Path(__file__).resolve().parent.parent
if str(pkg_root) not in sys.path:
    sys.path.insert(0, str(pkg_root))

from src.config import AgentConfig
from src.agent import SentinelXAgent
from src.identity import IdentityManager
from src.collectors.windows_events import WindowsEventCollector
from src.collectors.processes import ProcessCollector
from src.collectors.network import NetworkCollector
from src.collectors.system import SystemCollector


class TestEndpointAgent(unittest.TestCase):
    """Test suite for endpoint agent collectors, identity manager, and strict enrollment."""

    def setUp(self):
        # Save original config credentials
        self.orig_agent_id = AgentConfig.AGENT_ID
        self.orig_agent_token = AgentConfig.AGENT_TOKEN

    def tearDown(self):
        # Restore original config credentials
        AgentConfig.update_credentials(self.orig_agent_id, self.orig_agent_token)

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

        self.assertIsInstance(items, list)

    def test_system_collector(self):
        collector = SystemCollector(test_mode=True)
        items = collector.collect()

        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item.event_type, "system_health")
        self.assertIn("cpu_usage_percent", item.payload)
        self.assertIn("memory_used_percent", item.payload)

    @patch("src.agent.Transport.enroll")
    @patch("src.identity.SecureStorage.save_identity")
    def test_successful_enrollment(self, mock_save, mock_enroll):
        AgentConfig.update_credentials("agent-test-uuid", "")
        mock_enroll.return_value = {
            "agent_id": "agent-test-uuid",
            "agent_token": "bearer-backend-jwt-token-12345",
        }

        agent = SentinelXAgent(test_mode=True)
        success = agent.setup()

        self.assertTrue(success)
        self.assertEqual(AgentConfig.AGENT_TOKEN, "bearer-backend-jwt-token-12345")
        self.assertIsNotNone(agent.heartbeat_svc)
        mock_enroll.assert_called_once()
        mock_save.assert_called_once()

    @patch("src.agent.Transport.enroll")
    @patch("src.identity.SecureStorage.save_identity")
    def test_failed_enrollment_no_offline_token(self, mock_save, mock_enroll):
        AgentConfig.update_credentials("agent-test-uuid", "")
        mock_enroll.return_value = None  # Backend enrollment failure

        agent = SentinelXAgent(test_mode=True)
        success = agent.setup()

        self.assertFalse(success)
        self.assertEqual(AgentConfig.AGENT_TOKEN, "")
        self.assertIsNone(agent.heartbeat_svc)
        # Ensure offline fallback token was NOT generated or saved
        mock_save.assert_not_called()
        self.assertNotIn("offline-token", AgentConfig.AGENT_TOKEN)

    @patch("src.agent.Transport.enroll")
    @patch("src.identity.SecureStorage.save_identity")
    def test_missing_or_invalid_agent_token(self, mock_save, mock_enroll):
        AgentConfig.update_credentials("agent-test-uuid", "")
        mock_enroll.return_value = {"agent_id": "agent-test-uuid", "agent_token": ""}  # Invalid empty token

        agent = SentinelXAgent(test_mode=True)
        success = agent.setup()

        self.assertFalse(success)
        self.assertEqual(AgentConfig.AGENT_TOKEN, "")
        self.assertIsNone(agent.heartbeat_svc)
        mock_save.assert_not_called()

    @patch("src.agent.Transport.enroll")
    @patch("src.identity.SecureStorage.save_identity")
    def test_forced_reenrollment(self, mock_save, mock_enroll):
        AgentConfig.update_credentials("agent-test-uuid", "old-token-999")
        mock_enroll.return_value = {
            "agent_id": "agent-test-uuid",
            "agent_token": "new-backend-token-888",
        }

        agent = SentinelXAgent(test_mode=True, force_enroll=True)
        success = agent.setup()

        self.assertTrue(success)
        self.assertEqual(AgentConfig.AGENT_TOKEN, "new-backend-token-888")
        mock_enroll.assert_called_once()
        mock_save.assert_called_once()

    @patch("src.agent.Transport.enroll")
    @patch("src.identity.SecureStorage.load_identity")
    def test_restoration_of_existing_valid_identity(self, mock_load, mock_enroll):
        mock_load.return_value = {
            "agent_id": "restored-agent-uuid",
            "agent_token": "restored-backend-token-777",
        }
        AgentConfig.update_credentials("", "")

        agent = SentinelXAgent(test_mode=True, force_enroll=False)
        success = agent.setup()

        self.assertTrue(success)
        self.assertEqual(AgentConfig.AGENT_TOKEN, "restored-backend-token-777")
        self.assertEqual(AgentConfig.AGENT_ID, "restored-agent-uuid")
        # Ensure transport.enroll was NOT called since stored valid identity was restored
        mock_enroll.assert_not_called()


if __name__ == "__main__":
    unittest.main()
