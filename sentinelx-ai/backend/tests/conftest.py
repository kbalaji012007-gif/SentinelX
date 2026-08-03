"""
SentinelX AI – Pytest Configuration
Shared fixtures and test configuration.
"""

import pytest


@pytest.fixture
def app_settings():
    """Provide test settings override."""
    from app.core.config import Settings
    return Settings(
        ENVIRONMENT="testing",
        DEBUG=True,
        DATABASE_URL="sqlite+aiosqlite:///./test.db",
    )
