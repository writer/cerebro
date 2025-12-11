"""Webhook receiver for Forklift events.

Receives events from Forklift (drift detection, plan creation, PR status)
and creates/updates findings in Cerebro.
"""

import logging
import hmac
import hashlib
from datetime import datetime
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.database import get_db
from cerebro.core.models import Finding, Organization, Account, Resource, Rule
from cerebro.core.config import settings
from sqlalchemy import select

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks/forklift", tags=["Forklift Integration"])


def verify_forklift_signature(payload: bytes, signature: str, secret: str) -> bool:
    """
    Verify Forklift webhook signature using HMAC-SHA256.
    
    Args:
        payload: Raw request body bytes
        signature: Signature from X-Forklift-Signature header (format: sha256=<hex>)
        secret: Shared secret for signature verification
        
    Returns:
        True if signature is valid, False otherwise
    """
    if not signature or not signature.startswith('sha256='):
        logger.warning("Invalid signature format")
        return False
    
    try:
        expected_signature = signature[7:]  # Remove 'sha256=' prefix
        computed_hmac = hmac.new(
            secret.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(computed_hmac, expected_signature)
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False


# Pydantic models for Forklift events
class DriftDetectedEvent(BaseModel):
    """Forklift drift detected event."""
    type: Literal["drift_detected"]
    timestamp: datetime
    source: Literal["forklift"]
    repository: str
    organizationId: int
    bundleId: int
    bundleName: str
    drift: Dict[str, Any] = Field(..., description="Drift details")
    severity: Literal["critical", "high", "medium", "low"]
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PlanCreatedEvent(BaseModel):
    """Forklift plan created event."""
    type: Literal["plan_created"]
    timestamp: datetime
    source: Literal["forklift"]
    planId: int
    repository: str
    organizationId: int
    bundleId: int
    bundleName: str
    changes: Dict[str, Any]
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PlanAppliedEvent(BaseModel):
    """Forklift plan applied (PR created) event."""
    type: Literal["plan_applied"]
    timestamp: datetime
    source: Literal["forklift"]
    planId: int
    repository: str
    organizationId: int
    pullRequest: Dict[str, Any]
    appliedChanges: int
    status: str


class PRMergedEvent(BaseModel):
    """Forklift PR merged event."""
    type: Literal["pr_merged"]
    timestamp: datetime
    source: Literal["forklift"]
    planId: int
    repository: str
    organizationId: int
    pullRequest: Dict[str, Any]
    bundleName: str


@router.post("", status_code=200)
async def receive_forklift_event(
    request: Request,
    db: AsyncSession = Depends(get_db),
    authorization: Optional[str] = Header(None),
    x_forklift_event: Optional[str] = Header(None),
    x_forklift_signature: Optional[str] = Header(None, alias="X-Forklift-Signature"),
):
    """
    Receive events from Forklift.
    
    This endpoint processes various Forklift events and creates/updates
    findings in Cerebro's security dashboard.
    """
    
    # Verify webhook signature if secret is configured
    forklift_webhook_secret = getattr(settings, 'FORKLIFT_WEBHOOK_SECRET', None)
    
    if forklift_webhook_secret:
        if not x_forklift_signature:
            logger.warning("Missing X-Forklift-Signature header")
            raise HTTPException(status_code=401, detail="Missing webhook signature")
        
        # Get raw request body for signature verification
        body = await request.body()
        
        if not verify_forklift_signature(body, x_forklift_signature, forklift_webhook_secret):
            logger.warning("Invalid webhook signature")
            raise HTTPException(status_code=401, detail="Invalid webhook signature")
        
        logger.debug("Webhook signature verified successfully")
        
        # Parse event from already-read body
        import json
        event_data = json.loads(body.decode('utf-8'))
    else:
        logger.warning("FORKLIFT_WEBHOOK_SECRET not configured - skipping signature verification")
        # Parse event normally
        event_data = await request.json()
    event_type = event_data.get("type")
    
    logger.info(f"Received Forklift event: {event_type}", extra={
        "event_type": event_type,
        "repository": event_data.get("repository"),
    })
    
    try:
        if event_type == "drift_detected":
            result = await handle_drift_detected(event_data, db)
        elif event_type == "plan_created":
            result = await handle_plan_created(event_data, db)
        elif event_type == "plan_applied":
            result = await handle_plan_applied(event_data, db)
        elif event_type == "pr_merged":
            result = await handle_pr_merged(event_data, db)
        else:
            logger.warning(f"Unknown Forklift event type: {event_type}")
            return {"status": "ignored", "reason": "unknown_event_type"}
        
        await db.commit()
        return {"status": "processed", "result": result}
        
    except Exception as e:
        logger.exception(f"Failed to process Forklift event: {event_type}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Event processing failed: {str(e)}")


async def handle_drift_detected(event_data: Dict[str, Any], db: AsyncSession) -> Dict[str, Any]:
    """
    Handle drift_detected event by creating a finding.
    """
    event = DriftDetectedEvent(**event_data)
    
    # Get or create organization (using repo name as org identifier for now)
    org_name = event.repository.split('/')[0]
    org_stmt = select(Organization).where(Organization.name == org_name)
    org = await db.scalar(org_stmt)
    
    if not org:
        # Create organization if it doesn't exist
        org = Organization(name=org_name)
        db.add(org)
        await db.flush()
    
    # Get or create account for GitHub/Forklift
    account_stmt = select(Account).where(
        Account.org_id == org.org_id,
        Account.provider == "github"
    )
    account = await db.scalar(account_stmt)
    
    if not account:
        account = Account(
            org_id=org.org_id,
            provider="github",
            external_id=str(event.organizationId),
            display_name=org_name
        )
        db.add(account)
        await db.flush()
    
    # Get or create resource for repository
    resource_stmt = select(Resource).where(
        Resource.account_id == account.account_id,
        Resource.external_id == event.repository
    )
    resource = await db.scalar(resource_stmt)
    
    if not resource:
        resource = Resource(
            account_id=account.account_id,
            provider="github",
            resource_type="github.repository",
            external_id=event.repository,
            name=event.repository
        )
        db.add(resource)
        await db.flush()
    
    # Get or create Forklift rule
    rule_stmt = select(Rule).where(Rule.name == "Forklift Configuration Drift")
    rule = await db.scalar(rule_stmt)
    
    if not rule:
        rule = Rule(
            name="Forklift Configuration Drift",
            description="Repository configuration has drifted from enforced Forklift bundle",
            provider=["github"],
            resource_types=["github.repository"],
            expression_lang="cel",
            expression="true",  # Always true, we're creating finding directly
            severity=event.severity,
            cis=["5.1.1"],
            nist_800_53=["CM-2", "CM-3"]
        )
        db.add(rule)
        await db.flush()
    
    # Create fingerprint for deduplication
    fingerprint = f"forklift-drift-{event.repository}-{event.bundleId}"
    
    # Check if finding already exists
    finding_stmt = select(Finding).where(
        Finding.org_id == org.org_id,
        Finding.fingerprint == fingerprint
    )
    existing_finding = await db.scalar(finding_stmt)
    
    if existing_finding:
        # Update existing finding
        existing_finding.last_seen = event.timestamp
        existing_finding.severity = event.severity
        existing_finding.evidence = {
            "drift": event.drift,
            "bundle_name": event.bundleName,
            "bundle_id": event.bundleId,
            **event.metadata,
            "updated_at": event.timestamp.isoformat()
        }
        logger.info(f"Updated existing finding: {existing_finding.finding_id}")
        return {"finding_id": str(existing_finding.finding_id), "action": "updated"}
    
    # Create new finding
    finding = Finding(
        org_id=org.org_id,
        account_id=account.account_id,
        provider="github",
        rule_id=rule.rule_id,
        rule_version=rule.version,
        resource_id=resource.resource_id,
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        status="open",
        severity=event.severity,
        fingerprint=fingerprint,
        title=f"Configuration drift: {event.repository} ({event.bundleName})",
        summary=(
            f"Repository {event.repository} has drifted from Forklift bundle '{event.bundleName}'. "
            f"Missing: {len(event.drift.get('missing_files', []))}, "
            f"Modified: {len(event.drift.get('modified_files', []))}, "
            f"Deleted: {len(event.drift.get('deleted_files', []))}."
        ),
        evidence={
            "drift": event.drift,
            "bundle_name": event.bundleName,
            "bundle_id": event.bundleId,
            "forklift_organization_id": event.organizationId,
            **event.metadata,
            "detected_at": event.timestamp.isoformat()
        }
    )
    
    db.add(finding)
    await db.flush()
    
    logger.info(f"Created new finding: {finding.finding_id}")
    return {"finding_id": str(finding.finding_id), "action": "created"}


async def handle_plan_created(event_data: Dict[str, Any], db: AsyncSession) -> Dict[str, Any]:
    """Handle plan_created event by updating finding status."""
    event = PlanCreatedEvent(**event_data)
    
    # Find the drift finding for this repository/bundle
    fingerprint = f"forklift-drift-{event.repository}-{event.bundleId}"
    
    finding_stmt = select(Finding).where(Finding.fingerprint == fingerprint)
    finding = await db.scalar(finding_stmt)
    
    if finding:
        # Update finding evidence with plan info
        evidence = finding.evidence or {}
        evidence.update({
            "remediation_plan_created": event.timestamp.isoformat(),
            "plan_id": event.planId,
            "planned_changes": event.changes,
            "remediation_status": "plan_created"
        })
        finding.evidence = evidence
        logger.info(f"Updated finding with plan info: {finding.finding_id}")
        return {"finding_id": str(finding.finding_id), "action": "plan_recorded"}
    
    return {"action": "no_finding_found"}


async def handle_plan_applied(event_data: Dict[str, Any], db: AsyncSession) -> Dict[str, Any]:
    """Handle plan_applied event by updating finding status."""
    event = PlanAppliedEvent(**event_data)
    
    # Update finding with PR info
    fingerprint = f"forklift-drift-{event.repository}-{event.planId}"  # Try with planId
    finding_stmt = select(Finding).where(Finding.fingerprint.like(f"forklift-drift-{event.repository}%"))
    finding = await db.scalar(finding_stmt)
    
    if finding:
        evidence = finding.evidence or {}
        evidence.update({
            "remediation_pr_created": event.timestamp.isoformat(),
            "pr_number": event.pullRequest.get("number"),
            "pr_url": event.pullRequest.get("url"),
            "pr_branch": event.pullRequest.get("branch"),
            "applied_changes": event.appliedChanges,
            "remediation_status": "pr_pending_review"
        })
        finding.evidence = evidence
        finding.status = "open"  # Keep open until PR is merged
        logger.info(f"Updated finding with PR info: {finding.finding_id}")
        return {"finding_id": str(finding.finding_id), "action": "pr_recorded"}
    
    return {"action": "no_finding_found"}


async def handle_pr_merged(event_data: Dict[str, Any], db: AsyncSession) -> Dict[str, Any]:
    """Handle pr_merged event by marking finding as fixed."""
    event = PRMergedEvent(**event_data)
    
    # Mark finding as fixed
    fingerprint = f"forklift-drift-{event.repository}%"
    finding_stmt = select(Finding).where(Finding.fingerprint.like(fingerprint))
    finding = await db.scalar(finding_stmt)
    
    if finding:
        evidence = finding.evidence or {}
        evidence.update({
            "remediation_completed": event.timestamp.isoformat(),
            "pr_merged_by": event.pullRequest.get("merged_by"),
            "pr_merged_at": event.pullRequest.get("merged_at"),
            "remediation_status": "completed"
        })
        finding.evidence = evidence
        finding.status = "fixed"
        logger.info(f"Marked finding as fixed: {finding.finding_id}")
        return {"finding_id": str(finding.finding_id), "action": "marked_fixed"}
    
    return {"action": "no_finding_found"}
