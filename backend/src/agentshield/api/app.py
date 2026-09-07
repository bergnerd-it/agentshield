"""FastAPI application factory, lifespan management, and router assembly."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from agentshield import __version__
from agentshield.api.middleware import LoopbackSecurityMiddleware, SecurityHeadersMiddleware
from agentshield.api.routes import health, proxy, static
from agentshield.core.auth import get_or_create_admin_token, get_or_create_proxy_token
from agentshield.core.config import Settings, get_settings
from agentshield.core.errors import (
    AgentShieldError,
    agentshield_error_handler,
    unhandled_exception_handler,
)
from agentshield.core.logging import get_logger, setup_logging
from agentshield.persistence.db import run_migrations

logger = get_logger("agentshield.app")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app_settings = settings or get_settings()
    setup_logging(level=app_settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        # Startup
        logger.info(
            "Starting AgentShield v%s on %s:%d",
            __version__,
            app_settings.host,
            app_settings.port,
        )
        run_migrations(app_settings.effective_database_url)
        # Ensure administrative and proxy tokens exist with 0600 permissions
        get_or_create_admin_token(app_settings.effective_admin_token_path)
        get_or_create_proxy_token(app_settings.effective_proxy_token_path)
        yield
        # Shutdown
        logger.info("Shutting down AgentShield")

    app = FastAPI(
        title="AgentShield",
        description="Local security reverse proxy for coding-agent traffic",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    # 1. Register exception handlers for RFC 7807 Problem Details
    app.add_exception_handler(AgentShieldError, agentshield_error_handler)  # pyright: ignore[reportArgumentType]
    app.add_exception_handler(Exception, unhandled_exception_handler)

    # 2. Register security middleware (Outer to Inner)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(LoopbackSecurityMiddleware, settings=app_settings)

    # 3. Mount API routers
    app.include_router(health.router)
    app.include_router(proxy.router)
    app.include_router(static.router)

    return app
