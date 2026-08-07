"""
SentinelX AI – Base Response Action Interface
Abstract base class for all SOAR automated response actions.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple


class BaseResponseAction(ABC):
    """Abstract base class establishing standard response action interface."""

    def __init__(self, action_name: str, action_type: str, supports_rollback: bool = True, supports_dry_run: bool = True) -> None:
        self.action_name = action_name
        self.action_type = action_type
        self.supports_rollback = supports_rollback
        self.supports_dry_run = supports_dry_run

    @abstractmethod
    async def validate(self, parameters: Dict[str, Any]) -> Tuple[bool, str | None]:
        """Validate input parameters before execution."""
        pass

    @abstractmethod
    async def execute(
        self, target: str, parameters: Dict[str, Any], is_dry_run: bool = False
    ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        """
        Execute the response action.
        Returns tuple: (status, output_payload, rollback_data)
        """
        pass

    @abstractmethod
    async def rollback(self, target: str, rollback_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """
        Rollback/revert a previously executed response action.
        Returns tuple: (status, output_payload)
        """
        pass

    async def dry_run(self, target: str, parameters: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Simulate response action execution without producing side effects."""
        valid, msg = await self.validate(parameters)
        if not valid:
            return "Failed", {"error": msg, "dry_run": True}
        return "Success", {
            "dry_run": True,
            "simulated": True,
            "action": self.action_name,
            "target": target,
            "parameters": parameters,
            "message": f"Dry-run simulation for '{self.action_name}' on target '{target}' succeeded.",
        }
