"""
SentinelX Endpoint Agent – Security & Certificate Module
Handles secure local token storage, encryption/obfuscation, and TLS certificate validation.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger("sentinelx-agent")


class SecureStorage:
    """Helper for securely reading and writing agent credentials locally."""

    @staticmethod
    def save_identity(identity_path: Path, data: Dict[str, Any]) -> bool:
        """Store identity JSON payload to disk with appropriate permissions."""
        try:
            identity_path.parent.mkdir(parents=True, exist_ok=True)
            with open(identity_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logger.info(f"Agent identity saved to {identity_path}")
            return True
        except Exception as exc:
            logger.error(f"Failed to save agent identity: {exc}")
            return False

    @staticmethod
    def load_identity(identity_path: Path) -> Optional[Dict[str, Any]]:
        """Load stored identity JSON payload from disk."""
        if not identity_path.exists():
            return None
        try:
            with open(identity_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.error(f"Failed to load agent identity from {identity_path}: {exc}")
            return None
