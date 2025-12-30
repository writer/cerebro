"""Collection management endpoints."""

from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import User, get_current_user, require_collect
from cerebro.api.dependencies import get_collector_manager
from cerebro.api.org_access import require_org_access
from cerebro.api.schemas import CollectionRequest, CollectionResponse
from cerebro.collectors.manager import CollectorManager
from cerebro.core.database import get_db
from cerebro.core.models import Organization

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.post("/organizations/{org_id}/collect", response_model=CollectionResponse)
async def collect_organization(
    org_id: UUID,
    request: CollectionRequest,
    collector_manager: CollectorManager = Depends(get_collector_manager),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_collect)),
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
            resource_types=request.resource_types,
        )
        return CollectionResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    except Exception:

        structlog.get_logger(__name__).exception(
            "Collection failed",
            extra={"org_id": str(org_id)},
        )
        raise HTTPException(status_code=500, detail="Collection failed") from None



@router.post("/organizations/{org_id}/collect/background")
async def collect_organization_background(
    org_id: UUID,
    request: CollectionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_org_access(require_collect)),
):
    """Start background collection for an organization using Celery."""
    from cerebro.tasks.collection_tasks import collect_organization_task

    # Verify organization exists
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Schedule background task
    task = collect_organization_task.delay(
        str(org_id),
        provider_filter=request.providers,
        resource_types=request.resource_types,
    )

    return {
        "message": "Collection started in background",
        "task_id": task.id,
        "org_id": org_id,
        "providers": request.providers,
        "resource_types": request.resource_types,
    }


@router.get("/tasks/{task_id}")
async def get_task_status(task_id: str):
    """Get background task status."""
    from cerebro.tasks.celery_app import celery_app

    task = celery_app.AsyncResult(task_id)

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return {
        "task_id": task_id,
        "status": task.status,
        "result": task.result,
        "info": task.info,
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
                "status": "implemented",
            },
            {
                "name": "aws",
                "display_name": "Amazon Web Services",
                "description": "AWS resources, IAM, and configurations",
                "resource_types": ["aws.s3.bucket", "aws.ec2.instance", "aws.ec2.vpc"],
                "status": "implemented",
            },
            {
                "name": "gcp",
                "display_name": "Google Cloud Platform",
                "description": "GCP resources and IAM",
                "resource_types": ["gcp.storage.bucket", "gcp.compute.instance"],
                "status": "planned",
            },
            {
                "name": "google_workspace",
                "display_name": "Google Workspace",
                "description": "Google Workspace users and groups",
                "resource_types": ["google_workspace.user", "google_workspace.group"],
                "status": "planned",
            },
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
            "google_workspace": {"status": "not_implemented"},
        },
    }
