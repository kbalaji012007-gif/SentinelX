"""
SentinelX AI – Custom Exception Handlers
Application-specific domain exceptions with structured error detail support.
"""


class SentinelXError(Exception):
    """Base exception for all SentinelX AI domain errors."""

    def __init__(self, message: str, detail: str | None = None) -> None:
        self.message = message
        self.detail = detail or message
        super().__init__(self.message)


class EntityNotFoundError(SentinelXError):
    """Raised when a requested entity does not exist."""

    def __init__(self, entity: str, entity_id: str) -> None:
        super().__init__(
            message=f"{entity} not found: {entity_id}",
            detail=f"The requested {entity} with ID '{entity_id}' does not exist.",
        )
        self.entity = entity
        self.entity_id = entity_id


class ValidationError(SentinelXError):
    """Raised when input data fails business-rule validation."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(
            message=f"Validation failed on '{field}': {reason}",
            detail=reason,
        )
        self.field = field
        self.reason = reason


class DuplicateEntityError(SentinelXError):
    """Raised when attempting to create an entity that already exists."""

    def __init__(self, entity: str, identifier: str) -> None:
        super().__init__(
            message=f"Duplicate {entity}: {identifier}",
            detail=f"A {entity} with identifier '{identifier}' already exists.",
        )
        self.entity = entity
        self.identifier = identifier


class LogIngestionError(SentinelXError):
    """Raised when one or more log entries fail ingestion validation."""

    def __init__(self, message: str, failed_count: int = 0, errors: list[str] | None = None) -> None:
        super().__init__(message=message, detail=message)
        self.failed_count = failed_count
        self.errors = errors or []

