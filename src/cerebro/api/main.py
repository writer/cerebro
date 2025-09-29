"""Main FastAPI application."""

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import logging

from cerebro.core.config import settings
from .routers import auth, organizations, accounts, resources, principals, rules, findings, collectors, analysis, query, identity_governance, oauth_risk, attack_path, vendors, tests, websockets, analytics, compliance
from .routers import jwks
from .auth import User, get_current_user

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title=settings.api_title,
    description=settings.api_description,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware (restricted for production)
allowed_origins = [
    "http://localhost:3000",  # React dev server
    "http://localhost:8080",  # Vue dev server  
    "https://cerebro.yourdomain.com",  # Production UI
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
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
    from cerebro.tasks.celery_app import celery_app
    from datetime import datetime, timezone
    import asyncio
    
    try:
        def get_celery_status():
            # Get worker stats
            inspect = celery_app.control.inspect()
            
            # Get active/reserved tasks and worker stats
            active_tasks = inspect.active() or {}
            reserved_tasks = inspect.reserved() or {}
            worker_stats = inspect.stats() or {}
            
            # Get queue lengths (approximation via active + reserved)
            total_active = sum(len(tasks) for tasks in active_tasks.values())
            total_reserved = sum(len(tasks) for tasks in reserved_tasks.values())
            
            # Check worker heartbeats
            worker_heartbeats = []
            for worker, stats in worker_stats.items():
                if 'rusage' in stats:
                    # Worker is alive and reporting stats
                    heartbeats = {
                        "worker": worker,
                        "status": "alive",
                        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                        "active_tasks": len(active_tasks.get(worker, [])),
                        "reserved_tasks": len(reserved_tasks.get(worker, [])),
                        "total_tasks": stats.get('total', 0)
                    }
                    worker_heartbeats.append(heartbeats)
            
            return {
                "status": "healthy" if worker_heartbeats else "degraded",
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
        
        # Run in executor to avoid blocking
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, get_celery_status)
        
        if result["status"] == "degraded":
            from fastapi import HTTPException
            raise HTTPException(
                status_code=503, 
                detail="No Celery workers available"
            )
            
        return result
        
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=503, 
            detail=f"Celery health check failed: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
