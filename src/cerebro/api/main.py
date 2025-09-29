"""Main FastAPI application."""

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import logging

from cerebro.core.config import settings
from .routers import auth, organizations, accounts, resources, principals, rules, findings, collectors, analysis, query, identity_governance, oauth_risk
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
