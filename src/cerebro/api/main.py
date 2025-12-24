"""Main FastAPI application."""

import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import UTC
from time import perf_counter

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from cerebro.agents.metrics import get_registry
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory
from cerebro.core.logging import configure_structlog
from cerebro.core.observability import configure_service_observability
from cerebro.core.security.key_store import JWTKeyStore
from cerebro.metrics import api_metrics
from cerebro.metrics.jwt_metrics import jwt_metrics

from .routers import (
    accounts,
    agents,
    analysis,
    analytics,
    attack_path,
    auth,
    automation,
    collectors,
    compliance,
    compliance_unified,
    customers,
    email,
    findings,
    forklift_webhooks,
    identity_governance,
    integrations,
    jwks,
    oauth_risk,
    organizations,
    packs,
    principals,
    query,
    resources,
    rules,
    security_center,
    serval,
    slack,
    telemetry,
    tests,
    vendors,
    webhooks,
    websockets,
)
from .routers.v2 import (
    agents as agents_v2,
)
from .routers.v2 import (
    findings as findings_v2,
)
from .routers.v2 import (
    organizations as organizations_v2,
)

# Configure logging
configure_structlog()
logger = structlog.get_logger(__name__)


# Create FastAPI app
@asynccontextmanager
async def _app_lifespan(_: FastAPI):
    global _rotation_task
    interval = max(settings.jwt_rotation_check_interval_seconds, 0)
    if interval > 0 and (_rotation_task is None or _rotation_task.done()):
        loop = asyncio.get_running_loop()
        _rotation_task = loop.create_task(_jwt_rotation_worker(interval))
    try:
        yield
    finally:
        if _rotation_task is not None:
            _rotation_task.cancel()
            with suppress(asyncio.CancelledError):
                await _rotation_task


app = FastAPI(
    title=settings.api_title,
    description=settings.api_description,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=_app_lifespan,
)


def custom_openapi() -> dict:
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    schema["servers"] = [
        {"url": "https://api.cerebro.yourdomain.com"},
        {"url": "https://staging-api.cerebro.yourdomain.com"},
        {"url": "http://localhost:8000"},
    ]

    components = schema.setdefault("components", {})
    schemas = components.setdefault("schemas", {})

    schemas.setdefault(
        "ErrorResponse",
        {
            "title": "ErrorResponse",
            "type": "object",
            "properties": {
                "detail": {"anyOf": [{"type": "string"}, {"type": "object"}]},
                "error": {"type": "string"},
                "code": {"type": "string"},
            },
        },
    )

    schemas.setdefault(
        "PaginationMeta",
        {
            "title": "PaginationMeta",
            "type": "object",
            "properties": {
                "page": {"type": "integer", "minimum": 1},
                "page_size": {"type": "integer", "minimum": 1},
                "total": {"type": "integer", "minimum": 0},
                "next_cursor": {"type": ["string", "null"]},
            },
        },
    )

    schemas.setdefault(
        "PaginatedResponse",
        {
            "title": "PaginatedResponse",
            "type": "object",
            "properties": {
                "items": {"type": "array", "items": {"type": "object"}},
                "pagination": {"$ref": "#/components/schemas/PaginationMeta"},
            },
        },
    )

    components.setdefault("securitySchemes", {}).setdefault(
        "HTTPBearer",
        {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
    )

    schema.setdefault("security", [{"HTTPBearer": []}])

    schema.setdefault(
        "x-websocket-endpoints",
        [
            {
                "url": "wss://api.cerebro.yourdomain.com/ws/events",
                "description": "Streaming events",
            },
            {
                "url": "ws://localhost:8000/ws/events",
                "description": "Local development events",
            },
        ],
    )

    def _inject_example(path: str, method: str, example: dict) -> None:
        paths = schema.get("paths", {})
        entry = paths.get(path, {})
        op = entry.get(method)
        if not op:
            return
        responses = op.setdefault("responses", {})
        ok = responses.setdefault("200", {})
        content = ok.setdefault("content", {}).setdefault("application/json", {})
        content.setdefault("example", example)

    _inject_example(
        "/api/v1/auth/token",
        "post",
        {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "bearer",
            "expires_in": 3600,
        },
    )

    _inject_example(
        "/api/v1/analytics/organizations/{org_id}/dashboard",
        "get",
        {
            "executive_summary": {
                "org_id": "11111111-1111-1111-1111-111111111111",
                "overall_risk_score": 67,
                "risk_level": "medium",
            },
            "security_metrics": {
                "findings": {
                    "total": 120,
                    "critical": 2,
                    "high": 8,
                    "open": 54,
                    "trend_7d": -3,
                    "critical_trend_7d": 0,
                },
                "sla_performance": {
                    "breaches": 1,
                    "mttr_hours": 12,
                    "new_24h": 3,
                    "resolved_24h": 6,
                },
            },
            "compliance_status": {},
            "compliance_trends": {"overall": [{"date": "2024-10-01", "score": 0.82}]},
            "investment_recommendations": [],
            "identity_analytics": {"summary": {"total_identities": 500}},
            "risk_heatmap": {"heatmap_data": []},
            "runtime_health": {},
            "integration_coverage": {},
            "freshness": {},
            "freshness_warnings": [],
            "metadata": {
                "generated_at": "2024-10-16T00:00:00Z",
                "component_timings": {"total": 0.17},
            },
        },
    )

    _inject_example(
        "/api/v1/findings",
        "get",
        {
            "items": [
                {
                    "finding_id": "f-123",
                    "title": "Public S3 bucket",
                    "severity": "high",
                    "status": "open",
                    "provider": "aws",
                    "resource_id": "arn:aws:s3:::example",
                }
            ],
            "pagination": {"page": 1, "page_size": 50, "total": 1, "next_cursor": None},
        },
    )

    _inject_example(
        "/api/v1/telemetry/frontend/observe",
        "post",
        {"status": "accepted"},
    )

    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = custom_openapi  # type: ignore

configure_service_observability(service_name="cerebro-api")

# Configure rate limiter
default_limits = [limit for limit in settings.get_default_rate_limits() if limit]
if default_limits:
    limiter = Limiter(key_func=get_remote_address, default_limits=default_limits)  # type: ignore[arg-type]
else:
    limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

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


@app.get(f"{settings.api_v1_prefix}/openapi.json", include_in_schema=False)
async def get_versioned_openapi() -> dict:
    return app.openapi()


@app.middleware("http")
async def record_request_metrics(request: Request, call_next):
    start = perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration_ms = (perf_counter() - start) * 1000.0
        route = request.scope.get("route")
        path_template = getattr(route, "path", request.url.path)
        try:
            api_metrics.record(
                duration_ms=duration_ms,
                status_code=status_code,
                method=request.method,
                path_template=path_template,
            )
        except Exception:  # pragma: no cover - metrics should not break requests
            logger.debug("api_metrics_record_failed", path=path_template)


# Include routers
app.include_router(
    auth.router, prefix=f"{settings.api_v1_prefix}/auth", tags=["authentication"]
)

app.include_router(
    organizations.router,
    prefix=f"{settings.api_v1_prefix}/organizations",
    tags=["organizations"],
)

app.include_router(
    accounts.router, prefix=f"{settings.api_v1_prefix}/accounts", tags=["accounts"]
)

app.include_router(
    resources.router, prefix=f"{settings.api_v1_prefix}/resources", tags=["resources"]
)

app.include_router(
    principals.router,
    prefix=f"{settings.api_v1_prefix}/principals",
    tags=["principals"],
)

app.include_router(
    rules.router, prefix=f"{settings.api_v1_prefix}/rules", tags=["rules"]
)

app.include_router(
    findings.router, prefix=f"{settings.api_v1_prefix}/findings", tags=["findings"]
)

app.include_router(
    collectors.router,
    prefix=f"{settings.api_v1_prefix}/collectors",
    tags=["collectors"],
)

app.include_router(
    analysis.router, prefix=f"{settings.api_v1_prefix}/analysis", tags=["analysis"]
)

app.include_router(
    agents.router, prefix=f"{settings.api_v1_prefix}/agents", tags=["agents"]
)

app.include_router(query.router, prefix=f"{settings.api_v1_prefix}", tags=["query"])

app.include_router(
    identity_governance.router,
    prefix=f"{settings.api_v1_prefix}/identity-governance",
    tags=["identity-governance"],
)

app.include_router(
    oauth_risk.router,
    prefix=f"{settings.api_v1_prefix}/oauth-risk",
    tags=["oauth-risk"],
)

app.include_router(
    attack_path.router,
    prefix=f"{settings.api_v1_prefix}/attack-path",
    tags=["attack-path"],
)

app.include_router(
    vendors.router, prefix=f"{settings.api_v1_prefix}/vendors", tags=["vendors"]
)

app.include_router(
    customers.router, prefix=f"{settings.api_v1_prefix}/customers", tags=["customers"]
)

app.include_router(
    security_center.router,
    prefix=f"{settings.api_v1_prefix}/security-center",
    tags=["security-center"],
)

app.include_router(
    tests.router, prefix=f"{settings.api_v1_prefix}/tests", tags=["tests"]
)

app.include_router(
    analytics.router, prefix=f"{settings.api_v1_prefix}/analytics", tags=["analytics"]
)

app.include_router(websockets.router, tags=["websockets"])

# JWKS and OpenID Connect endpoints (no prefix - served at root)
app.include_router(jwks.router, tags=["authentication"])

app.include_router(
    compliance.router,
    prefix=f"{settings.api_v1_prefix}/compliance",
    tags=["compliance"],
)

# Unified compliance API with new architecture
app.include_router(
    compliance_unified.router,
    prefix=f"{settings.api_v1_prefix}/compliance/unified",
    tags=["compliance", "unified"],
)

# Slack integration API
app.include_router(
    slack.router,
    prefix=f"{settings.api_v1_prefix}/slack",
    tags=["slack", "notifications"],
)

# Email notification API
app.include_router(
    email.router,
    prefix=f"{settings.api_v1_prefix}/notifications",
    tags=["email", "notifications"],
)

# Generic webhook notification API
app.include_router(
    webhooks.router,
    prefix=f"{settings.api_v1_prefix}/notifications",
    tags=["webhooks", "notifications"],
)

if settings.enable_agent_metrics:
    try:  # pragma: no cover - optional dependency guard
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
    except ImportError:  # pragma: no cover
        logger.warning(
            "Prometheus client not installed; metrics endpoint disabled",
        )
    else:

        @app.get(
            settings.agent_metrics_path, include_in_schema=False, tags=["observability"]
        )
        async def agent_metrics() -> Response:
            registry = get_registry()
            if registry is None:
                raise HTTPException(
                    status_code=503, detail="Metrics registry unavailable"
                )
            payload = generate_latest(registry)
            return Response(payload, media_type=CONTENT_TYPE_LATEST)


# Forklift webhook receiver (intelligence integration)
app.include_router(
    forklift_webhooks.router,
    prefix=f"{settings.api_v1_prefix}",
    tags=["forklift", "integrations"],
)

app.include_router(
    packs.router, prefix=f"{settings.api_v1_prefix}/packs", tags=["packs"]
)

app.include_router(
    integrations.router, prefix=f"{settings.api_v1_prefix}", tags=["integrations"]
)

app.include_router(
    serval.router, prefix=f"{settings.api_v1_prefix}", tags=["integrations"]
)

# Telemetry API (repository and runtime intelligence)
app.include_router(
    telemetry.router,
    prefix=f"{settings.api_v1_prefix}",
    tags=["telemetry", "intelligence"],
)

app.include_router(
    automation.router,
    prefix=f"{settings.api_v1_prefix}",
    tags=["automation", "telemetry"],
)

# V2 API routers using DynamoDB backend
# These are parallel to V1 endpoints and can be used for gradual migration
app.include_router(
    organizations_v2.router, prefix="/api/v2", tags=["v2", "organizations"]
)

app.include_router(findings_v2.router, prefix="/api/v2", tags=["v2", "findings"])

app.include_router(agents_v2.router, prefix="/api/v2", tags=["v2", "agents"])


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


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Cerebro Security System of Record API",
        "version": "0.1.0",
        "docs": "/docs",
    }


@app.get("/ready", include_in_schema=False)
async def readiness():
    """Readiness probe aggregating core dependencies."""
    from cerebro.core import probes

    checks: dict[str, dict[str, object]] = {}
    ready = True

    db_ok, db_error = await probes.check_database()
    checks["database"] = {"healthy": db_ok, "error": db_error}
    ready &= db_ok

    celery_ok, celery_error = await probes.check_celery_workers()
    checks["celery"] = {"healthy": celery_ok, "error": celery_error}
    ready &= celery_ok

    broker_ok, broker_error = await probes.check_broker_connection()
    checks["broker"] = {"healthy": broker_ok, "error": broker_error}
    ready &= broker_ok

    status = "ready" if ready else "degraded"
    return {"status": status, "checks": checks}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/health/db")
async def health_db():
    """Database health check endpoint."""
    from sqlalchemy import text

    from cerebro.core.database import async_session_factory

    try:
        async with async_session_factory() as db:
            await db.execute(text("SELECT 1"))
            return {"status": "healthy", "database": "connected"}
    except Exception as e:
        from fastapi import HTTPException

        raise HTTPException(status_code=503, detail=f"Database unhealthy: {e!s}")


@app.get("/health/celery")
async def health_celery():
    """Celery health check endpoint with worker status and queue depths."""
    import asyncio
    from datetime import datetime

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
            except Exception:  # pragma: no cover
                reserved_tasks = {}

            try:
                worker_stats = inspect.stats() or {}
            except Exception:  # pragma: no cover
                worker_stats = {}

            total_active = sum(len(tasks) for tasks in active_tasks.values())
            total_reserved = sum(len(tasks) for tasks in reserved_tasks.values())

            worker_heartbeats = []
            for worker, stats in worker_stats.items():
                heartbeats = {
                    "worker": worker,
                    "status": "alive",
                    "last_heartbeat": datetime.now(UTC).isoformat(),
                    "active_tasks": len(active_tasks.get(worker, [])),
                    "reserved_tasks": len(reserved_tasks.get(worker, [])),
                    "total_tasks": stats.get("total", 0),
                }
                worker_heartbeats.append(heartbeats)

            status = "healthy" if worker_heartbeats else "degraded"
            return {
                "status": status,
                "workers": {
                    "total_workers": len(worker_heartbeats),
                    "active_workers": len(worker_heartbeats),
                    "worker_details": worker_heartbeats,
                },
                "queues": {
                    "total_active_tasks": total_active,
                    "total_reserved_tasks": total_reserved,
                    "total_pending": total_active + total_reserved,
                },
                "last_check": datetime.now(UTC).isoformat(),
            }

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, get_celery_status)

        if result["status"] == "degraded":
            raise HTTPException(status_code=503, detail="No Celery workers available")

        return result

    except HTTPException:
        raise
    except TimeoutError as exc:
        raise HTTPException(status_code=503, detail="Celery inspect timed out") from exc
    except Exception as e:
        raise HTTPException(
            status_code=503, detail=f"Celery health check failed: {e!s}"
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
                status_code=503, detail="Encryption service test failed"
            )

        return {
            "status": "healthy",
            "kms_provider": service.kms.name,
            "cache_stats": service.get_cache_stats(),
        }

    except Exception as e:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=503, detail=f"Encryption health check failed: {e!s}"
        )


@app.get("/health/dynamodb")
async def health_dynamodb():
    """DynamoDB health check endpoint."""
    from cerebro.core.dynamodb_client import health_check

    try:
        result = await health_check()

        if not result["healthy"]:
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "unhealthy",
                    "tables": result["tables"],
                    "errors": result["errors"],
                },
            )

        return {
            "status": "healthy",
            "tables": result["tables"],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=503, detail=f"DynamoDB health check failed: {e!s}"
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
