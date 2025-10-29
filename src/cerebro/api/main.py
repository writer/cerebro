"""Main FastAPI application."""

import asyncio
from contextlib import suppress

from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import logging
import structlog
from fastapi.responses import Response

from cerebro.core.config import settings
from cerebro.core.logging import configure_structlog
from cerebro.core.observability import configure_agent_observability
from cerebro.core.database import async_session_factory
from cerebro.core.security.key_store import JWTKeyStore
from cerebro.metrics.jwt_metrics import jwt_metrics
from cerebro.agents.metrics import get_registry
from .routers import auth, organizations, accounts, resources, principals, rules, findings, collectors, analysis, query, identity_governance, oauth_risk, attack_path, vendors, tests, websockets, analytics, compliance, compliance_unified, agents, slack, email, webhooks, forklift_webhooks, telemetry, automation, packs, integrations
from .routers import jwks
from .auth import User, get_current_user

# Configure logging
configure_structlog()
logger = structlog.get_logger(__name__)

# Create FastAPI app
app = FastAPI(
    title=settings.api_title,
    description=settings.api_description,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

configure_agent_observability()

# Configure rate limiter
default_limits = [limit for limit in settings.get_default_rate_limits() if limit]
if default_limits:
    limiter = Limiter(key_func=get_remote_address, default_limits=default_limits)
else:
    limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

if default_limits:
    logger.info("Rate limiting enabled", default_limits=default_limits)
else:
    logger.info("Rate limiting configured without default limits")

# Add CORS middleware (restricted for production)
allowed_origins = settings.get_allowed_origins()

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=settings.api_cors_allow_credentials,
    allow_methods=settings.api_cors_allow_methods,
    allow_headers=settings.api_cors_allow_headers,
)

# Include routers
app.include_router(
    auth.router,
    prefix=f"{settings.api_v1_prefix}/auth",
    tags=["authentication"]
)

app.include_router(
    organizations.router, 
    prefix=f"{settings.api_v1_prefix}/organizations",
    tags=["organizations"]
)

app.include_router(
    accounts.router,
    prefix=f"{settings.api_v1_prefix}/accounts", 
    tags=["accounts"]
)

app.include_router(
    resources.router,
    prefix=f"{settings.api_v1_prefix}/resources",
    tags=["resources"]
)

app.include_router(
    principals.router,
    prefix=f"{settings.api_v1_prefix}/principals", 
    tags=["principals"]
)

app.include_router(
    rules.router,
    prefix=f"{settings.api_v1_prefix}/rules",
    tags=["rules"]
)

app.include_router(
    findings.router,
    prefix=f"{settings.api_v1_prefix}/findings",
    tags=["findings"]
)

app.include_router(
    collectors.router,
    prefix=f"{settings.api_v1_prefix}/collectors",
    tags=["collectors"]
)

app.include_router(
    analysis.router,
    prefix=f"{settings.api_v1_prefix}/analysis",
    tags=["analysis"]
)

app.include_router(
    agents.router,
    prefix=f"{settings.api_v1_prefix}/agents",
    tags=["agents"]
)

app.include_router(
    query.router,
    prefix=f"{settings.api_v1_prefix}",
    tags=["query"]
)

app.include_router(
    identity_governance.router,
    prefix=f"{settings.api_v1_prefix}/identity-governance",
    tags=["identity-governance"]
)

app.include_router(
    oauth_risk.router,
    prefix=f"{settings.api_v1_prefix}/oauth-risk",
    tags=["oauth-risk"]
)

app.include_router(
    attack_path.router,
    prefix=f"{settings.api_v1_prefix}/attack-path",
    tags=["attack-path"]
)

app.include_router(
    vendors.router,
    prefix=f"{settings.api_v1_prefix}/vendors",
    tags=["vendors"]
)

app.include_router(
    tests.router,
    prefix=f"{settings.api_v1_prefix}/tests", 
    tags=["tests"]
)

app.include_router(
    analytics.router,
    prefix=f"{settings.api_v1_prefix}/analytics",
    tags=["analytics"]
)

app.include_router(
    websockets.router,
    tags=["websockets"]
)

# JWKS and OpenID Connect endpoints (no prefix - served at root)
app.include_router(
    jwks.router,
    tags=["authentication"]
)

app.include_router(
    compliance.router,
    prefix=f"{settings.api_v1_prefix}/compliance",
    tags=["compliance"]
)

# Unified compliance API with new architecture
app.include_router(
    compliance_unified.router,
    prefix=f"{settings.api_v1_prefix}/compliance/unified",
    tags=["compliance", "unified"]
)

# Slack integration API
app.include_router(
    slack.router,
    prefix=f"{settings.api_v1_prefix}/slack",
    tags=["slack", "notifications"]
)

# Email notification API
app.include_router(
    email.router,
    prefix=f"{settings.api_v1_prefix}/notifications",
    tags=["email", "notifications"]
)

# Generic webhook notification API
app.include_router(
    webhooks.router,
    prefix=f"{settings.api_v1_prefix}/notifications",
    tags=["webhooks", "notifications"]
)

if settings.enable_agent_metrics:
    try:  # pragma: no cover - optional dependency guard
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
    except ImportError:  # pragma: no cover
        logger.warning(
            "Prometheus client not installed; metrics endpoint disabled",
        )
    else:

        @app.get(settings.agent_metrics_path, include_in_schema=False, tags=["observability"])
        async def agent_metrics() -> Response:
            registry = get_registry()
            if registry is None:
                raise HTTPException(status_code=503, detail="Metrics registry unavailable")
            payload = generate_latest(registry)
            return Response(payload, media_type=CONTENT_TYPE_LATEST)

# Forklift webhook receiver (intelligence integration)
app.include_router(
    forklift_webhooks.router,
    prefix=f"{settings.api_v1_prefix}",
    tags=["forklift", "integrations"]
)

app.include_router(
    packs.router,
    prefix=f"{settings.api_v1_prefix}/packs",
    tags=["packs"]
)

app.include_router(
    integrations.router,
    prefix=f"{settings.api_v1_prefix}",
    tags=["integrations"]
)

# Telemetry API (repository and runtime intelligence)
app.include_router(
    telemetry.router,
    prefix=f"{settings.api_v1_prefix}",
    tags=["telemetry", "intelligence"]
)

app.include_router(
    automation.router,
    prefix=f"{settings.api_v1_prefix}",
    tags=["automation", "telemetry"]
)


_rotation_task: asyncio.Task | None = None


async def _jwt_rotation_worker(interval: int) -> None:
    while True:
        try:
            async with async_session_factory() as session:
                key_store = JWTKeyStore(session, metrics=jwt_metrics)
                rotated = await key_store.rotate_keys_if_needed()
                cleaned = await key_store.cleanup_expired_keys()
                if rotated:
                    logger.info("Background JWT rotation executed")
                if cleaned:
                    logger.info("Background JWT key cleanup executed", cleaned=cleaned)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning("JWT rotation worker iteration failed", error=str(exc))

        await asyncio.sleep(interval)


@app.on_event("startup")
async def _start_background_tasks() -> None:
    global _rotation_task
    interval = max(settings.jwt_rotation_check_interval_seconds, 0)
    if interval <= 0:
        return
    if _rotation_task is None or _rotation_task.done():
        loop = asyncio.get_running_loop()
        _rotation_task = loop.create_task(_jwt_rotation_worker(interval))


@app.on_event("shutdown")
async def _stop_background_tasks() -> None:
    if _rotation_task is None:
        return
    _rotation_task.cancel()
    with suppress(asyncio.CancelledError):
        await _rotation_task


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Cerebro Security System of Record API",
        "version": "0.1.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/health/db")
async def health_db():
    """Database health check endpoint."""
    from cerebro.core.database import async_session_factory
    from sqlalchemy import text
    
    try:
        async with async_session_factory() as db:
            await db.execute(text("SELECT 1"))
            return {"status": "healthy", "database": "connected"}
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail=f"Database unhealthy: {str(e)}")


@app.get("/health/celery")
async def health_celery():
    """Celery health check endpoint with worker status and queue depths."""
    from datetime import datetime, timezone
    import asyncio
    from cerebro.tasks.celery_app import celery_app
    
    try:
        def get_celery_status():
            inspect = celery_app.control.inspect(timeout=5.0)  # type: ignore[arg-type]
            if inspect is None:
                raise RuntimeError("No Celery workers responded to inspect")

            try:
                active_tasks = inspect.active() or {}
            except Exception as exc:  # pragma: no cover - celery inspect can raise
                raise RuntimeError(f"Failed to fetch active tasks: {exc}")

            try:
                reserved_tasks = inspect.reserved() or {}
            except Exception as exc:  # pragma: no cover
                reserved_tasks = {}

            try:
                worker_stats = inspect.stats() or {}
            except Exception as exc:  # pragma: no cover
                worker_stats = {}

            total_active = sum(len(tasks) for tasks in active_tasks.values())
            total_reserved = sum(len(tasks) for tasks in reserved_tasks.values())

            worker_heartbeats = []
            for worker, stats in worker_stats.items():
                heartbeats = {
                    "worker": worker,
                    "status": "alive",
                    "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                    "active_tasks": len(active_tasks.get(worker, [])),
                    "reserved_tasks": len(reserved_tasks.get(worker, [])),
                    "total_tasks": stats.get('total', 0)
                }
                worker_heartbeats.append(heartbeats)

            status = "healthy" if worker_heartbeats else "degraded"
            return {
                "status": status,
                "workers": {
                    "total_workers": len(worker_heartbeats),
                    "active_workers": len(worker_heartbeats),
                    "worker_details": worker_heartbeats
                },
                "queues": {
                    "total_active_tasks": total_active,
                    "total_reserved_tasks": total_reserved,
                    "total_pending": total_active + total_reserved
                },
                "last_check": datetime.now(timezone.utc).isoformat()
            }

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, get_celery_status)

        if result["status"] == "degraded":
            raise HTTPException(
                status_code=503,
                detail="No Celery workers available"
            )

        return result

    except HTTPException:
        raise
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=503,
            detail="Celery inspect timed out"
        ) from exc
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Celery health check failed: {str(e)}"
        )


@app.get("/health/encryption")
async def health_encryption():
    """Encryption service health check endpoint with cache stats."""
    from cerebro.core.encryption import get_encryption_service

    try:
        service = get_encryption_service()

        # Test encryption service
        is_healthy = await service.test_encryption()

        if not is_healthy:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=503,
                detail="Encryption service test failed"
            )

        return {
            "status": "healthy",
            "kms_provider": service.kms.name,
            "cache_stats": service.get_cache_stats(),
        }

    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=503,
            detail=f"Encryption health check failed: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
