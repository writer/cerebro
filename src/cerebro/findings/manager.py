"""Finding manager for creating and managing security findings."""

import hashlib
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_

from cerebro.core.models import Finding, Rule, Resource, Principal, Account, Organization
from cerebro.rules import RuleResult
from .evaluator import RuleEvaluator
from .producers import ProducerBasedFindingService, producer_registry

logger = logging.getLogger(__name__)


@dataclass
class FindingResult:
    """Result of finding generation."""
    findings_created: int = 0
    findings_updated: int = 0
    findings_closed: int = 0
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class FindingManager:
    """Manages the creation and lifecycle of security findings."""
    
    def __init__(self, db_session: AsyncSession, rule_evaluator: RuleEvaluator):
        """Initialize finding manager."""
        self.db = db_session
        self.evaluator = rule_evaluator
        self.producer_service = ProducerBasedFindingService(producer_registry)
    
    async def generate_findings(
        self,
        org: Organization,
        provider: Optional[str] = None,
        resource_types: Optional[List[str]] = None
    ) -> FindingResult:
        """Generate findings for an organization."""
        result = FindingResult()
        
        try:
            # Evaluate rules across the organization
            evaluation_results = await self.evaluator.evaluate_organization(
                org, provider, resource_types
            )
            
            if not evaluation_results:
                logger.info(f"No rule matches found for organization {org.name}")
                return result
            
            logger.info(f"Processing {len(evaluation_results)} resource evaluation results")
            
            # Process each resource's results
            for resource_external_id, rule_results in evaluation_results.items():
                await self._process_resource_results(
                    org, resource_external_id, rule_results, result
                )
            
            # Commit changes
            await self.db.commit()
            
            logger.info(f"Finding generation completed: {result.findings_created} created, "
                       f"{result.findings_updated} updated, {result.findings_closed} closed")
            
        except Exception as e:
            logger.error(f"Finding generation failed: {e}")
            result.errors.append(str(e))
            await self.db.rollback()
        
        return result
    
    async def _process_resource_results(
        self,
        org: Organization,
        resource_external_id: str,
        rule_results: List[RuleResult],
        result: FindingResult
    ) -> None:
        """Process rule results for a specific resource."""
        
        # Get the resource
        stmt = select(Resource).join(Resource.account).where(
            and_(
                Resource.external_id == resource_external_id,
                Resource.account.has(org_id=org.org_id)
            )
        )
        resource = await self.db.scalar(stmt)
        
        if not resource:
            logger.warning(f"Resource not found: {resource_external_id}")
            return
        
        # Process each rule result
        for rule_result in rule_results:
            if rule_result.error:
                result.errors.append(f"Rule {rule_result.rule_id} error: {rule_result.error}")
                continue
            
            if rule_result.matched:
                await self._create_or_update_finding(
                    org, resource, rule_result, result
                )
            else:
                # Close any existing findings for this rule/resource combination
                await self._close_finding(org, resource, rule_result.rule_id, result)
    
    async def _create_or_update_finding(
        self,
        org: Organization,
        resource: Resource,
        rule_result: RuleResult,
        result: FindingResult
    ) -> None:
        """Create or update a finding."""
        
        # Get the rule
        rule = await self.db.get(Rule, rule_result.rule_id)
        if not rule:
            logger.warning(f"Rule not found: {rule_result.rule_id}")
            return
        
        # Generate fingerprint
        fingerprint = self._generate_fingerprint(
            rule.rule_id, resource.resource_id, None
        )
        
        # Check if finding already exists
        stmt = select(Finding).where(
            and_(
                Finding.org_id == org.org_id,
                Finding.fingerprint == fingerprint
            )
        )
        existing_finding = await self.db.scalar(stmt)
        
        if existing_finding:
            # Update existing finding
            existing_finding.last_seen = datetime.utcnow()
            existing_finding.status = "open"  # Reopen if it was closed
            result.findings_updated += 1
            logger.debug(f"Updated finding {existing_finding.finding_id}")
        else:
            # Create new finding
            now = datetime.utcnow()
            finding = Finding(
                org_id=org.org_id,
                account_id=resource.account_id,
                provider=resource.provider,
                rule_id=rule.rule_id,
                rule_version=rule.version,
                resource_id=resource.resource_id,
                first_seen=now,
                last_seen=now,
                status="open",
                severity=rule.severity,
                fingerprint=fingerprint,
                title=self._generate_finding_title(rule, resource),
                summary=self._generate_finding_summary(rule, resource),
                evidence={
                    "rule_name": rule.name,
                    "rule_expression": rule.expression,
                    "resource_type": resource.resource_type,
                    "resource_name": resource.name,
                    "execution_time_ms": rule_result.execution_time_ms,
                }
            )
            
            self.db.add(finding)
            result.findings_created += 1
            logger.debug(f"Created finding for rule {rule.name} on resource {resource.external_id}")
    
    async def _close_finding(
        self,
        org: Organization,
        resource: Resource,
        rule_id: UUID,
        result: FindingResult
    ) -> None:
        """Close a finding that no longer matches."""
        
        fingerprint = self._generate_fingerprint(rule_id, resource.resource_id, None)
        
        stmt = select(Finding).where(
            and_(
                Finding.org_id == org.org_id,
                Finding.fingerprint == fingerprint,
                Finding.status == "open"
            )
        )
        existing_finding = await self.db.scalar(stmt)
        
        if existing_finding:
            existing_finding.status = "fixed"
            existing_finding.last_seen = datetime.utcnow()
            result.findings_closed += 1
            logger.debug(f"Closed finding {existing_finding.finding_id}")
    
    def _generate_fingerprint(
        self,
        rule_id: UUID,
        resource_id: Optional[UUID],
        principal_id: Optional[UUID]
    ) -> str:
        """Generate a unique fingerprint for a finding."""
        components = [str(rule_id)]
        
        if resource_id:
            components.append(str(resource_id))
        
        if principal_id:
            components.append(str(principal_id))
        
        fingerprint_str = "|".join(components)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
    
    def _generate_finding_title(self, rule: Rule, resource: Resource) -> str:
        """Generate a human-readable title for the finding."""
        return f"{rule.name}: {resource.name or resource.external_id}"
    
    def _generate_finding_summary(self, rule: Rule, resource: Resource) -> str:
        """Generate a summary for the finding."""
        return (f"Rule '{rule.name}' triggered on {resource.resource_type} "
                f"'{resource.name or resource.external_id}'. {rule.description or ''}")
    
    async def suppress_finding(
        self,
        finding_id: UUID,
        reason: str,
        user_id: Optional[UUID] = None,
        expires_at: Optional[datetime] = None
    ) -> bool:
        """Suppress a specific finding."""
        finding = await self.db.get(Finding, finding_id)
        if not finding:
            return False
        
        finding.status = "suppressed"
        finding.last_seen = datetime.utcnow()
        
        # Create suppression record in suppressions table
        from cerebro.core.models import Suppression
        suppression = Suppression(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            org_id=finding.org_id,
            pattern_type='finding_id',
            pattern_value=str(finding.finding_id),
            reason=reason,
            created_by=user_id,
            expires_at=expires_at
        )
        self.db.add(suppression)
        
        await self.db.commit()
        logger.info(f"Suppressed finding {finding_id}: {reason}")
        return True
    
    async def accept_risk(
        self,
        finding_id: UUID,
        reason: str
    ) -> bool:
        """Accept risk for a specific finding."""
        finding = await self.db.get(Finding, finding_id)
        if not finding:
            return False
        
        finding.status = "accepted_risk"
        finding.last_seen = datetime.utcnow()
        
        await self.db.commit()
        logger.info(f"Accepted risk for finding {finding_id}: {reason}")
        return True
    
    async def get_findings_by_status(
        self,
        org_id: UUID,
        status: str,
        limit: int = 100,
        offset: int = 0
    ) -> List[Finding]:
        """Get findings by status."""
        stmt = select(Finding).where(
            and_(
                Finding.org_id == org_id,
                Finding.status == status
            )
        ).order_by(Finding.last_seen.desc()).offset(offset).limit(limit)
        
        return list(await self.db.scalars(stmt))
    
    async def get_finding_stats(self, org_id: UUID) -> Dict[str, Any]:
        """Get finding statistics for an organization."""
        # This would typically use raw SQL for better performance
        stmt = select(Finding).where(Finding.org_id == org_id)
        all_findings = list(await self.db.scalars(stmt))
        
        stats = {
            "total": len(all_findings),
            "by_status": {},
            "by_severity": {},
            "by_provider": {},
        }
        
        for finding in all_findings:
            # By status
            stats["by_status"][finding.status] = stats["by_status"].get(finding.status, 0) + 1
            
            # By severity
            stats["by_severity"][finding.severity] = stats["by_severity"].get(finding.severity, 0) + 1
            
            # By provider
            stats["by_provider"][finding.provider] = stats["by_provider"].get(finding.provider, 0) + 1
        
        return stats
