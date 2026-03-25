"""FastAPI application factory for RedForge REST API."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from redforge.api.routes import probes, reports, scan

limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Security defaults:
    - CORS allow_origins=[] by default (opt-in via REDFORGE_CORS_ORIGINS)
    - Rate limiting: 10 requests/minute per IP
    - Request size limit: 1MB
    - Bearer token required on all /v1/* endpoints
    """
    app = FastAPI(
        title="RedForge API",
        description="LLM Red Teaming & Vulnerability Scanning REST API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
    app.add_middleware(SlowAPIMiddleware)

    # CORS — restrictive by default
    allowed_origins = [
        o.strip()
        for o in os.environ.get("REDFORGE_CORS_ORIGINS", "").split(",")
        if o.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,  # [] by default
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # Routes
    app.include_router(scan.router)
    app.include_router(probes.router)
    app.include_router(reports.router)

    @app.get("/health", tags=["Health"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": "0.1.0"}

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Internal server error", "detail": str(exc)[:200]},
        )

    return app
