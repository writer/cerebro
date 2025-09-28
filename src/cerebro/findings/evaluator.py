"""Rule evaluator for generating findings."""

from typing import Any, Dict, List, Optional
from datetime import datetime
from uuid import UUID
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc

from cerebro.core.models import (
    Rule, Resource, Principal, ConfigSnapshot, IamEdge, Organization
)
from cerebro.rules import RuleEngine, EvaluationContext, RuleResult

logger = logging.getLogger(__name__)


class RuleEvaluator:
    """Evaluates rules against resources to generate findings."""
    
    def __init__(self, db_session: AsyncSession, rule_engine: RuleEngine):
        """Initialize rule evaluator."""
        self.db = db_session
        self.rule_engine = rule_engine
    
    async def evaluate_resource(
        self,
        resource: Resource,
        rules: Optional[List[Rule]] = None
    ) -> List[RuleResult]:
        """Evaluate rules against a specific resource."""
        if rules is None:
            # Get applicable rules for this resource
            rules = await self._get_applicable_rules(resource)
        
        if not rules:
            logger.debug(f"No applicable rules found for resource {resource.external_id}")
            return []
        
        # Get latest configuration
        config_snapshot = await self._get_latest_config(resource)
        if not config_snapshot:
            logger.warning(f"No configuration found for resource {resource.external_id}")
            return []
        
        # Build evaluation context
        context = await self._build_evaluation_context(resource, config_snapshot)
        
        # Evaluate rules
        rule_data = [
            {
                "rule_id": rule.rule_id,
                "expression": rule.expression
            }
            for rule in rules if rule.expression_lang == "cel"
        ]
        
        results = self.rule_engine.evaluate_rules(rule_data, context)
        
        logger.debug(f"Evaluated {len(results)} rules for resource {resource.external_id}, "
                    f"{sum(1 for r in results if r.matched)} matches")
        
        return results
    
    async def evaluate_principal(
        self,
        principal: Principal,
        rules: Optional[List[Rule]] = None
    ) -> List[RuleResult]:
        """Evaluate rules against a principal."""
        if rules is None:
            # Get applicable rules for principals
            rules = await self._get_applicable_rules(principal=principal)
        
        if not rules:
            logger.debug(f"No applicable rules found for principal {principal.external_id}")
            return []
        
        # Build evaluation context for principal
        context = await self._build_principal_context(principal)
        
        # Evaluate rules
        rule_data = [
            {
                "rule_id": rule.rule_id,
                "expression": rule.expression
            }
            for rule in rules if rule.expression_lang == "cel"
        ]
        
        results = self.rule_engine.evaluate_rules(rule_data, context)
        
        logger.debug(f"Evaluated {len(results)} rules for principal {principal.external_id}, "
                    f"{sum(1 for r in results if r.matched)} matches")
        
        return results
    
    async def evaluate_organization(
        self,
        org: Organization,
        provider: Optional[str] = None,
        resource_types: Optional[List[str]] = None
    ) -> Dict[str, List[RuleResult]]:
        """Evaluate rules across an entire organization."""
        results = {}
        
        # Get all applicable rules
        stmt = select(Rule).where(
            and_(
                Rule.policy_id.in_(
                    select(Rule.policy_id).join(Rule.policy).where(
                        Rule.policy.has(org_id=org.org_id)
                    )
                ),
                Rule.is_active == True
            )
        )
        
        if provider:
            stmt = stmt.where(Rule.provider.contains([provider]))
        
        rules = list(await self.db.scalars(stmt))
        
        if not rules:
            logger.warning(f"No active rules found for organization {org.name}")
            return results
        
        # Get all resources in the organization
        resource_stmt = select(Resource).join(Resource.account).where(
            Resource.account.has(org_id=org.org_id)
        )
        
        if provider:
            resource_stmt = resource_stmt.where(Resource.provider == provider)
        
        if resource_types:
            resource_stmt = resource_stmt.where(Resource.resource_type.in_(resource_types))
        
        resources = list(await self.db.scalars(resource_stmt))
        
        logger.info(f"Evaluating {len(rules)} rules against {len(resources)} resources")
        
        # Evaluate each resource
        for resource in resources:
            try:
                resource_results = await self.evaluate_resource(resource, rules)
                if resource_results:
                    results[resource.external_id] = resource_results
            except Exception as e:
                logger.error(f"Failed to evaluate resource {resource.external_id}: {e}")
        
        return results
    
    async def _get_applicable_rules(
        self,
        resource: Optional[Resource] = None,
        principal: Optional[Principal] = None
    ) -> List[Rule]:
        """Get rules applicable to a resource or principal."""
        stmt = select(Rule).where(Rule.is_active == True)
        
        if resource:
            # Filter by provider and resource type
            stmt = stmt.where(
                and_(
                    Rule.provider.contains([resource.provider]),
                    Rule.resource_types.is_(None) | Rule.resource_types.contains([resource.resource_type])
                )
            )
        elif principal:
            # Filter by provider (principal rules)
            stmt = stmt.where(Rule.provider.contains([principal.provider]))
        
        return list(await self.db.scalars(stmt))
    
    async def _get_latest_config(self, resource: Resource) -> Optional[ConfigSnapshot]:
        """Get the latest configuration snapshot for a resource."""
        stmt = select(ConfigSnapshot).where(
            ConfigSnapshot.resource_id == resource.resource_id
        ).order_by(desc(ConfigSnapshot.captured_at)).limit(1)
        
        return await self.db.scalar(stmt)
    
    async def _build_evaluation_context(
        self,
        resource: Resource,
        config_snapshot: ConfigSnapshot,
        principal: Optional[Principal] = None,
        iam_edge: Optional[IamEdge] = None
    ) -> EvaluationContext:
        """Build evaluation context for rule execution."""
        
        # Resource context
        resource_context = {
            "resource_id": str(resource.resource_id),
            "account_id": str(resource.account_id),
            "provider": resource.provider,
            "resource_type": resource.resource_type,
            "external_id": resource.external_id,
            "name": resource.name,
            "parent_external_id": resource.parent_external_id,
        }
        
        # Configuration context
        config_context = config_snapshot.normalized_config
        
        # Principal context (if provided)
        principal_context = None
        if principal:
            principal_context = {
                "principal_id": str(principal.principal_id),
                "principal_type": principal.principal_type,
                "external_id": principal.external_id,
                "email": principal.email,
                "display_name": principal.display_name,
                "is_human": principal.is_human,
            }
        
        # IAM edge context (if provided)
        iam_edge_context = None
        if iam_edge:
            iam_edge_context = {
                "permission": iam_edge.permission,
                "via": iam_edge.via,
                "effective_at": iam_edge.effective_at.isoformat(),
                "expires_at": iam_edge.expires_at.isoformat() if iam_edge.expires_at else None,
                "is_admin": iam_edge.is_admin,
            }
        
        # TODO: Add org_config and user_config if needed
        
        return EvaluationContext(
            resource=resource_context,
            config=config_context,
            principal=principal_context,
            iam_edge=iam_edge_context,
            org_config=None,  # TODO: Implement org config
            user_config=None  # TODO: Implement user config
        )
    
    async def _build_principal_context(self, principal: Principal) -> EvaluationContext:
        """Build evaluation context for principal-based rules."""
        principal_context = {
            "principal_id": str(principal.principal_id),
            "principal_type": principal.principal_type,
            "external_id": principal.external_id,
            "email": principal.email,
            "display_name": principal.display_name,
            "is_human": principal.is_human,
        }
        
        return EvaluationContext(
            principal=principal_context,
            # TODO: Add user_config for MFA checks etc.
            user_config=None
        )
