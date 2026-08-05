"""
SentinelX AI – Core Configuration
Pydantic Settings for environment-based configuration.
"""

from typing import Any
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────
    APP_NAME: str = "SentinelX AI"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    # ── Server ───────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 1

    # ── CORS ─────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = [
        "https://sentinel-x-gray.vercel.app",
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> list[str]:
        default_origins = [
            "https://sentinel-x-gray.vercel.app",
            "http://localhost:5173",
            "http://localhost:3000",
            "http://127.0.0.1:5173",
        ]
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        for d in default_origins:
                            if d not in parsed:
                                parsed.append(d)
                        return parsed
                except Exception:
                    pass
            origins = [i.strip() for i in v.split(",") if i.strip()]
            for d in default_origins:
                if d not in origins:
                    origins.append(d)
            return origins
        elif isinstance(v, list):
            origins = list(v)
            for d in default_origins:
                if d not in origins:
                    origins.append(d)
            return origins
        return default_origins

    # ── Supabase Database ────────────────────────────────────────
    SUPABASE_URL: str = ""
    SUPABASE_ANON_KEY: str = ""
    SUPABASE_SERVICE_ROLE_KEY: str = ""
    DATABASE_URL: str = "postgresql+asyncpg://sentinelx_dev.epxtwnulvkmtxwfesxnc:SentinelX2026Pass!@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres"

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: str | None) -> str:
        default_url = "postgresql+asyncpg://sentinelx_dev.epxtwnulvkmtxwfesxnc:SentinelX2026Pass!@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres"
        if not v:
            return default_url
        v = v.strip().strip("'\"")
        if not v or v.lower() in ("none", "null", "undefined"):
            return default_url
        if v.startswith("postgres://"):
            v = v.replace("postgres://", "postgresql+asyncpg://", 1)
        elif v.startswith("postgresql://") and not v.startswith("postgresql+asyncpg://"):
            v = v.replace("postgresql://", "postgresql+asyncpg://", 1)

        if "?" in v:
            v = v.split("?")[0]

        try:
            from sqlalchemy.engine.url import make_url
            make_url(v)
            return v
        except Exception:
            return default_url

    # ── JWT Authentication ───────────────────────────────────────
    JWT_SECRET_KEY: str = "sentinelx-dev-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── Google Gemini AI ─────────────────────────────────────────
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"

    # ── Redis ────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── External Integrations ────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    SHODAN_API_KEY: str = ""

    # ── Notification Channels ────────────────────────────────────
    SLACK_WEBHOOK_URL: str = ""
    PAGERDUTY_API_KEY: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""


settings = Settings()
