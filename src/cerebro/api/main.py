"""Main FastAPI application."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from cerebro.core.config import settings
from .routers import organizations, accounts, resources, principals, rules, findings, collectors

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

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
