"""
SentinelX Endpoint Telemetry Agent – CLI Entry Point
Main entry point for starting the background agent or executing test-mode runs.
"""

import sys
import logging
import argparse
from pathlib import Path

# Add package root to python search path
pkg_root = Path(__file__).resolve().parent.parent
if str(pkg_root) not in sys.path:
    sys.path.insert(0, str(pkg_root))

from src.config import AgentConfig
from src.agent import SentinelXAgent


def configure_logging(level_name: str) -> None:
    """Configure stdout logging format."""
    log_level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def main() -> None:
    """CLI Argument parser and execution entry point."""
    parser = argparse.ArgumentParser(
        description="SentinelX Endpoint Telemetry Agent for Windows/Linux hosts."
    )
    parser.add_argument(
        "--test-mode",
        action="store_true",
        help="Run agent in local test mode (marks all events explicitly as SIMULATED).",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Perform a single telemetry collection cycle and exit.",
    )
    parser.add_argument(
        "--enroll",
        action="store_true",
        help="Force re-enrollment with SentinelX backend.",
    )
    parser.add_argument(
        "--server",
        type=str,
        default=None,
        help="Override SentinelX backend API URL (e.g. http://localhost:8000/api/v1).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=None,
        help="Override telemetry collection interval in seconds.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set logging verbosity level.",
    )

    args = parser.parse_args()

    configure_logging(args.log_level)
    logger = logging.getLogger("sentinelx-agent")

    logger.info("Starting SentinelX Endpoint Telemetry Agent v1.0.0")

    if args.server:
        AgentConfig.SENTINELX_API_URL = args.server.rstrip("/")
    if args.interval:
        AgentConfig.TELEMETRY_INTERVAL = args.interval
    if args.test_mode:
        AgentConfig.TEST_MODE = True
        logger.info("=== LOCAL TEST MODE ACTIVE ===")
        logger.info("No fake security events will be presented as real production events.")
        logger.info("All events will be explicitly tagged with is_simulated: True and SIMULATED_TEST_EVENT.")

    agent = SentinelXAgent(test_mode=AgentConfig.TEST_MODE, once=args.once)
    agent.start()


if __name__ == "__main__":
    main()
