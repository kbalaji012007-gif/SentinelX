"""
SentinelX AI – Autonomous Security Operations Platform
FastAPI Application Entry Point
"""

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings

import structlog
import logging


# Configure structured logging
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle manager."""
    logger.info(
        "sentinelx_startup",
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        debug=settings.DEBUG,
    )
    # Startup: initialize connections, caches, etc.
    yield
    # Shutdown: cleanup connections
    logger.info("sentinelx_shutdown")


app = FastAPI(
    title=settings.APP_NAME,
    description="SentinelX AI – Autonomous Security Operations Platform. "
    "Intelligent threat detection, incident management, and AI-powered security analytics.",
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.api.v1.auth.router import router as auth_router
from app.api.v1.dashboard.router import router as dashboard_router
from app.api.v1.threats.router import router as threats_router, alerts_router, ioc_router
from app.api.v1.incidents.router import router as incidents_router

app.include_router(auth_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(threats_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(ioc_router, prefix="/api/v1")
app.include_router(incidents_router, prefix="/api/v1")


@app.get("/", tags=["Health"])
async def root():
    """Root endpoint – platform info."""
    return {
        "platform": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "environment": settings.ENVIRONMENT,
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for Render and monitoring."""
    return {
        "status": "healthy",
        "service": "sentinelx-api",
        "version": settings.APP_VERSION,
    }
