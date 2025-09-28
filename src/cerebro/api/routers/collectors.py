"""Collection management endpoints."""

from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.database import get_db
from cerebro.core.models import Organization
from cerebro.api.schemas import CollectionRequest, CollectionResponse
from cerebro.api.dependencies import get_collector_manager
from cerebro.collectors.manager import CollectorManager

router = APIRouter()


@router.post("/organizations/{org_id}/collect", response_model=CollectionResponse)
async def collect_organization(
    org_id: UUID,
    request: CollectionRequest,
    collector_manager: CollectorManager = Depends(get_collector_manager),
    db: AsyncSession = Depends(get_db)
):
    """Collect configuration data for an organization."""
    # Verify organization exists
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        result = await collector_manager.collect_organization(
            str(org_id),
            providers=request.providers,
            resource_types=request.resource_types
        )
        return CollectionResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Collection failed: {str(e)}")


@router.post("/organizations/{org_id}/collect/background")
async def collect_organization_background(
    org_id: UUID,
    request: CollectionRequest,
    background_tasks: BackgroundTasks,
    collector_manager: CollectorManager = Depends(get_collector_manager),
    db: AsyncSession = Depends(get_db)
):
    """Start background collection for an organization."""
    # Verify organization exists
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    async def collect_task():
        try:
            result = await collector_manager.collect_organization(
                str(org_id),
                providers=request.providers,
                resource_types=request.resource_types
            )
            # Could store result or send notification here
        except Exception as e:
            # Log error
            pass
    
    background_tasks.add_task(collect_task)
    
    return {
        "message": "Collection started in background",
        "org_id": org_id,
        "providers": request.providers,
        "resource_types": request.resource_types
    }


@router.get("/providers")
async def list_supported_providers():
    """List supported providers."""
    return {
        "providers": [
            {
                "name": "github",
                "display_name": "GitHub",
                "description": "GitHub repositories, users, and permissions",
                "resource_types": ["github.repo", "github.team"],
                "status": "implemented"
            },
            {
                "name": "aws",
                "display_name": "Amazon Web Services",
                "description": "AWS resources, IAM, and configurations",
                "resource_types": ["aws.s3.bucket", "aws.ec2.instance", "aws.ec2.vpc"],
                "status": "implemented"
            },
            {
                "name": "gcp",
                "display_name": "Google Cloud Platform",
                "description": "GCP resources and IAM",
                "resource_types": ["gcp.storage.bucket", "gcp.compute.instance"],
                "status": "planned"
            },
            {
                "name": "google_workspace",
                "display_name": "Google Workspace",
                "description": "Google Workspace users and groups",
                "resource_types": ["google_workspace.user", "google_workspace.group"],
                "status": "planned"
            }
        ]
    }


@router.get("/status")
async def get_collection_status():
    """Get collection system status."""
    return {
        "status": "healthy",
        "collectors": {
            "github": {"status": "ready"},
            "aws": {"status": "ready"},
            "gcp": {"status": "not_implemented"},
            "google_workspace": {"status": "not_implemented"}
        }
    }
