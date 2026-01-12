"""Rule evaluator for generating findings."""

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import and_, desc, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import (
    ConfigSnapshot,
    IamEdge,
    Organization,
    Principal,
    Resource,
    Rule,
)
from cerebro.rules import EvaluationContext, RuleEngine, RuleResult

logger = structlog.get_logger(__name__)


class OrgConfigProvider:
    """Provides organization-level configuration for rule evaluation."""

    def __init__(self, db_session: AsyncSession) -> None:
        self.db = db_session
        self._cache: dict[UUID, dict[str, Any]] = {}

    async def get_org_config(self, org_id: UUID) -> dict[str, Any]:
        """Get organization configuration for rule evaluation."""
        if org_id in self._cache:
            return self._cache[org_id]

        try:
            stmt = select(Organization).where(Organization.org_id == org_id)
            org = await self.db.scalar(stmt)
            if not org:
                return {}

            config = {
                "org_id": str(org.org_id),
                "name": org.name,
                "settings": org.settings if hasattr(org, "settings") else {},
                "security_policies": await self._get_security_policies(org_id),
                "compliance_requirements": await self._get_compliance_requirements(
                    org_id
                ),
            }
            self._cache[org_id] = config
            return config
        except SQLAlchemyError as e:
            logger.warning(f"Failed to load org config for {org_id}: {e}")
            return {}

    async def _get_security_policies(self, org_id: UUID) -> dict[str, Any]:
        """Get organization security policies."""
        from cerebro.core.models import Policy

        try:
            stmt = select(Policy).where(
                and_(Policy.org_id == org_id, Policy.is_active.is_(True))
            )
            result = await self.db.scalars(stmt)
            policies = list(result)
            return {
                "mfa_required": any(
                    p.name.lower().find("mfa") >= 0 for p in policies
                ),
                "password_policy_enabled": any(
                    p.name.lower().find("password") >= 0 for p in policies
                ),
                "active_policy_count": len(policies),
            }
        except SQLAlchemyError:
            return {}

    async def _get_compliance_requirements(self, org_id: UUID) -> list[str]:
        """Get organization compliance framework requirements."""
        return []


class UserConfigProvider:
    """Provides user-level configuration for rule evaluation."""

    def __init__(self, db_session: AsyncSession) -> None:
        self.db = db_session
        self._cache: dict[str, dict[str, Any]] = {}

    async def get_user_config(self, principal: Principal) -> dict[str, Any]:
        """Get user configuration for rule evaluation."""
        cache_key = str(principal.principal_id)
        if cache_key in self._cache:
            return self._cache[cache_key]

        config = {
            "principal_id": str(principal.principal_id),
            "email": principal.email,
            "is_human": principal.is_human,
            "mfa_enabled": await self._check_mfa_status(principal),
            "last_login": await self._get_last_login(principal),
            "risk_factors": await self._get_risk_factors(principal),
        }
        self._cache[cache_key] = config
        return config

    async def _check_mfa_status(self, principal: Principal) -> bool:
        """Check if MFA is enabled for the principal."""
        metadata = principal.metadata or {}
        return bool(
            metadata.get("mfa_enabled")
            or metadata.get("is_enrolled_in_2sv")
            or metadata.get("two_factor_enabled")
        )

    async def _get_last_login(self, principal: Principal) -> str | None:
        """Get the last login timestamp for the principal."""
        metadata = principal.metadata or {}
        last_login = metadata.get("last_login_time") or metadata.get("last_login")
        return str(last_login) if last_login else None

    async def _get_risk_factors(self, principal: Principal) -> list[str]:
        """Get risk factors for the principal."""
        risk_factors = []
        metadata = principal.metadata or {}

        if not await self._check_mfa_status(principal):
            risk_factors.append("mfa_not_enabled")

        if metadata.get("suspended"):
            risk_factors.append("account_suspended")

        if metadata.get("is_admin") or metadata.get("is_delegated_admin"):
            risk_factors.append("elevated_privileges")

        return risk_factors


class RuleEvaluator:
    """Evaluates rules against resources to generate findings."""

    def __init__(self, db_session: AsyncSession, rule_engine: RuleEngine) -> None:
        """Initialize rule evaluator."""
        self.db = db_session
        self.rule_engine = rule_engine
        self._org_config_provider = OrgConfigProvider(db_session)
        self._user_config_provider = UserConfigProvider(db_session)

    async def evaluate_resource(
        self, resource: Resource, rules: list[Rule] | None = None
    ) -> list[RuleResult]:
        """Evaluate rules against a specific resource."""
        if rules is None:
            # Get applicable rules for this resource
            rules = await self._get_applicable_rules(resource)

        if not rules:
            logger.debug(
                f"No applicable rules found for resource {resource.external_id}"
            )
            return []

        # Get latest configuration
        config_snapshot = await self._get_latest_config(resource)
        if not config_snapshot:
            logger.warning(
                f"No configuration found for resource {resource.external_id}"
            )
            return []

        # Build evaluation context
        context = await self._build_evaluation_context(resource, config_snapshot)

        # Evaluate rules
        rule_data = [
            {"rule_id": rule.rule_id, "expression": rule.expression}
            for rule in rules
            if rule.expression_lang == "cel"
        ]

        results = self.rule_engine.evaluate_rules(rule_data, context)

        logger.debug(
            f"Evaluated {len(results)} rules for resource {resource.external_id}, "
            f"{sum(1 for r in results if r.matched)} matches"
        )

        return results

    async def evaluate_principal(
        self, principal: Principal, rules: list[Rule] | None = None
    ) -> list[RuleResult]:
        """Evaluate rules against a principal."""
        if rules is None:
            # Get applicable rules for principals
            rules = await self._get_applicable_rules(principal=principal)

        if not rules:
            logger.debug(
                f"No applicable rules found for principal {principal.external_id}"
            )
            return []

        # Build evaluation context for principal
        context = await self._build_principal_context(principal)

        # Evaluate rules
        rule_data = [
            {"rule_id": rule.rule_id, "expression": rule.expression}
            for rule in rules
            if rule.expression_lang == "cel"
        ]

        results = self.rule_engine.evaluate_rules(rule_data, context)

        logger.debug(
            f"Evaluated {len(results)} rules for principal {principal.external_id}, "
            f"{sum(1 for r in results if r.matched)} matches"
        )

        return results

    async def evaluate_organization(
        self,
        org: Organization,
        provider: str | None = None,
        resource_types: list[str] | None = None,
    ) -> dict[str, list[RuleResult]]:
        """Evaluate rules across an entire organization."""
        results: dict[str, list[RuleResult]] = {}

        # Get all applicable rules for the organization
        from cerebro.core.models import Policy

        # First get policy IDs for this organization
        policy_subquery = select(Policy.policy_id).where(Policy.org_id == org.org_id)

        # Then get rules for those policies
        stmt = select(Rule).where(
            and_(Rule.policy_id.in_(policy_subquery), Rule.is_active)
        )

        if provider:
            stmt = stmt.where(Rule.provider.contains([provider]))

        rules = list(await self.db.scalars(stmt))

        if not rules:
            logger.warning(f"No active rules found for organization {org.name}")
            return results

        # Get all resources in the organization
        resource_stmt = (
            select(Resource)
            .join(Resource.account)
            .where(Resource.account.has(org_id=org.org_id))
        )

        if provider:
            resource_stmt = resource_stmt.where(Resource.provider == provider)

        if resource_types:
            resource_stmt = resource_stmt.where(
                Resource.resource_type.in_(resource_types)
            )

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
        self, resource: Resource | None = None, principal: Principal | None = None
    ) -> list[Rule]:
        """Get rules applicable to a resource or principal."""
        stmt = select(Rule).where(Rule.is_active)

        if resource:
            # Filter by provider and resource type
            stmt = stmt.where(
                and_(
                    Rule.provider.contains([resource.provider]),
                    Rule.resource_types.is_(None)
                    | Rule.resource_types.contains([resource.resource_type]),
                )
            )
        elif principal:
            # Filter by provider (principal rules)
            stmt = stmt.where(Rule.provider.contains([principal.provider]))

        return list(await self.db.scalars(stmt))

    async def _get_latest_config(self, resource: Resource) -> ConfigSnapshot | None:
        """Get the latest configuration snapshot for a resource."""
        stmt = (
            select(ConfigSnapshot)
            .where(ConfigSnapshot.resource_id == resource.resource_id)
            .order_by(desc(ConfigSnapshot.captured_at))
            .limit(1)
        )

        return await self.db.scalar(stmt)

    async def _build_evaluation_context(
        self,
        resource: Resource,
        config_snapshot: ConfigSnapshot,
        principal: Principal | None = None,
        iam_edge: IamEdge | None = None,
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
                "expires_at": (
                    iam_edge.expires_at.isoformat() if iam_edge.expires_at else None
                ),
                "is_admin": iam_edge.is_admin,
            }

        # Get org_config from the resource's account
        org_config = None
        try:
            from cerebro.core.models import Account

            account_stmt = select(Account).where(
                Account.account_id == resource.account_id
            )
            account = await self.db.scalar(account_stmt)
            if account and account.org_id:
                org_config = await self._org_config_provider.get_org_config(
                    account.org_id
                )
        except SQLAlchemyError as e:
            logger.warning(f"Failed to load org config: {e}")

        # Get user_config if principal is provided
        user_config = None
        if principal:
            user_config = await self._user_config_provider.get_user_config(principal)

        return EvaluationContext(
            resource=resource_context,
            config=config_context,
            principal=principal_context,
            iam_edge=iam_edge_context,
            org_config=org_config,
            user_config=user_config,
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

        # Get user_config with MFA status and risk factors
        user_config = await self._user_config_provider.get_user_config(principal)

        return EvaluationContext(
            principal=principal_context,
            user_config=user_config,
        )
