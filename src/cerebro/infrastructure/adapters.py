"""Infrastructure adapters implementing domain ports."""

from typing import List, Dict, Any, Optional
from uuid import UUID
from datetime import datetime
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from cerebro.domain.entities import (
    ResourceEntity,
    PrincipalEntity,
    ConfigEntity,
    IamPermissionEntity,
    FindingEntity,
    RuleEntity,
    IdentityClusterEntity,
)
from cerebro.core.models import Finding
from cerebro.core.bulk_operations import BulkOperations
from cerebro.rules.engine import RuleEngine, EvaluationContext

logger = logging.getLogger(__name__)


class SQLAlchemyRepository:
    """SQLAlchemy implementation of RepositoryPort."""

    def __init__(self, db_session: AsyncSession):
        """Initialize repository."""
        self.db = db_session
        self.bulk_ops = BulkOperations(db_session)

    async def save_resources(
        self, account_id: UUID, resources: List[ResourceEntity]
    ) -> Dict[str, UUID]:
        """Save resources and return mapping of external_id -> resource_id."""
        if not resources:
            return {}

        # Convert domain entities to database format
        resource_data = []
        for resource in resources:
            resource_data.append(
                {
                    "resource_type": resource.resource_type,
                    "external_id": resource.external_id,
                    "name": resource.name,
                    "parent_external_id": resource.parent_external_id,
                }
            )

        # Use bulk operations
        await self.bulk_ops.bulk_upsert_resources(
            account_id,
            resources[0].provider,  # Assume all resources have same provider
            resource_data,
        )

        # Get the resource ID mapping
        external_ids = [r.external_id for r in resources]
        return await self.bulk_ops.get_existing_resources(
            account_id, resources[0].provider, external_ids
        )

    async def save_principals(
        self, account_id: UUID, principals: List[PrincipalEntity]
    ) -> Dict[str, UUID]:
        """Save principals and return mapping of external_id -> principal_id."""
        if not principals:
            return {}

        # Convert domain entities to database format
        principal_data = []
        for principal in principals:
            principal_data.append(
                {
                    "principal_type": principal.principal_type.value,
                    "external_id": principal.external_id,
                    "email": principal.email,
                    "display_name": principal.display_name,
                    "is_human": principal.is_human,
                }
            )

        # Use bulk operations
        await self.bulk_ops.bulk_upsert_principals(
            account_id,
            principals[0].provider,  # Assume all principals have same provider
            principal_data,
        )

        # Get the principal ID mapping
        external_ids = [p.external_id for p in principals]
        return await self.bulk_ops.get_existing_principals(
            account_id, principals[0].provider, external_ids
        )

    async def save_configurations(
        self, resource_id_map: Dict[str, UUID], configs: List[ConfigEntity]
    ) -> int:
        """Save configuration snapshots."""
        if not configs:
            return 0

        # Convert domain entities to database format
        snapshot_data = []
        for config in configs:
            resource_id = resource_id_map.get(config.resource_external_id)
            if resource_id:
                import hashlib
                import json

                config_json = json.dumps(config.normalized_config, sort_keys=True)
                config_sha = hashlib.sha256(config_json.encode()).digest()

                snapshot_data.append(
                    {
                        "resource_id": resource_id,
                        "captured_at": config.captured_at,
                        "config_sha": config_sha,
                        "normalized_config": config.normalized_config,
                        "collector_version": config.collector_version,
                    }
                )

        if snapshot_data:
            result = await self.bulk_ops.bulk_insert_config_snapshots(snapshot_data)
            return result["inserted"]

        return 0

    async def save_iam_permissions(
        self,
        account_id: UUID,
        resource_id_map: Dict[str, UUID],
        principal_id_map: Dict[str, UUID],
        permissions: List[IamPermissionEntity],
    ) -> int:
        """Save IAM permission edges."""
        if not permissions:
            return 0

        # Convert domain entities to database format
        iam_data = []
        for perm in permissions:
            principal_id = principal_id_map.get(perm.principal_external_id)
            if not principal_id:
                continue

            resource_id = None
            if perm.resource_external_id:
                resource_id = resource_id_map.get(perm.resource_external_id)

            # Use current time if not specified
            effective_at = perm.effective_at or datetime.utcnow()

            iam_data.append(
                {
                    "account_id": account_id,
                    "provider": permissions[0].principal_external_id.split(".")[
                        0
                    ],  # Extract from external_id
                    "principal_id": principal_id,
                    "resource_id": resource_id,
                    "permission": perm.permission,
                    "via": perm.via,
                    "effective_at": effective_at,
                    "expires_at": perm.expires_at,
                    "is_admin": perm.is_admin,
                }
            )

        if iam_data:
            result = await self.bulk_ops.bulk_insert_iam_edges(iam_data)
            return result["processed"]

        return 0

    async def get_findings_by_status(
        self, org_id: UUID, status: str, limit: int = 100, offset: int = 0
    ) -> List[FindingEntity]:
        """Get findings by status."""
        stmt = (
            select(Finding)
            .where(and_(Finding.org_id == org_id, Finding.status == status))
            .offset(offset)
            .limit(limit)
        )

        db_findings = await self.db.scalars(stmt)

        # Convert to domain entities
        findings = []
        for db_finding in db_findings:
            finding = FindingEntity(
                rule_id=db_finding.rule_id,
                resource_external_id=(
                    str(db_finding.resource_id) if db_finding.resource_id else None
                ),
                principal_external_id=(
                    str(db_finding.principal_id) if db_finding.principal_id else None
                ),
                title=db_finding.title,
                summary=db_finding.summary or "",
                severity=db_finding.severity,
                status=db_finding.status,
                evidence=db_finding.evidence or {},
                first_seen=db_finding.first_seen,
                last_seen=db_finding.last_seen,
                fingerprint=db_finding.fingerprint,
            )
            findings.append(finding)

        return findings

    async def save_finding(self, org_id: UUID, finding: FindingEntity) -> UUID:
        """Save a finding."""
        # Convert domain entity to database model
        db_finding = Finding(
            org_id=org_id,
            rule_id=finding.rule_id,
            title=finding.title,
            summary=finding.summary,
            severity=finding.severity.value,
            status=finding.status.value,
            evidence=finding.evidence,
            first_seen=finding.first_seen or datetime.utcnow(),
            last_seen=finding.last_seen or datetime.utcnow(),
            fingerprint=finding.fingerprint or "",
        )

        self.db.add(db_finding)
        await self.db.commit()
        await self.db.refresh(db_finding)

        return db_finding.finding_id

    async def update_finding(self, finding_id: UUID, finding: FindingEntity) -> None:
        """Update an existing finding."""
        db_finding = await self.db.get(Finding, finding_id)
        if not db_finding:
            raise ValueError(f"Finding {finding_id} not found")

        # Update fields
        db_finding.status = finding.status.value
        db_finding.last_seen = finding.last_seen or datetime.utcnow()
        db_finding.evidence = finding.evidence

        await self.db.commit()

    async def save_identity_clusters(
        self, org_id: UUID, clusters: List[IdentityClusterEntity]
    ) -> int:
        """Save identity clusters."""
        from cerebro.core.repositories_sqlalchemy import IdentityRepository

        identity_repo = IdentityRepository(self.db)
        saved_count = 0

        for cluster in clusters:
            # Check if cluster exists
            existing_cluster = await identity_repo.get_cluster(
                org_id, cluster.cluster_id
            )

            if not existing_cluster:
                # Create new cluster
                db_cluster = await identity_repo.create_cluster(
                    org_id=org_id,
                    cluster_name=cluster.cluster_id,
                    confidence_score=cluster.confidence_score,
                    stitching_evidence=cluster.stitching_evidence,
                )

                # Add cluster members
                for principal in cluster.principals:
                    await identity_repo.add_cluster_member(
                        cluster_id=db_cluster.id,
                        principal_external_id=principal.external_id,
                        provider=principal.provider,
                        confidence_score=cluster.confidence_score,
                    )

                saved_count += 1
            else:
                logger.debug(f"Cluster {cluster.cluster_id} already exists, skipping")

        await self.db.commit()
        return saved_count


class CELRuleEngineAdapter:
    """CEL rule engine implementation of RuleEnginePort."""

    def __init__(self, rule_engine: RuleEngine):
        """Initialize rule engine adapter."""
        self.rule_engine = rule_engine

    async def compile_rule(self, expression: str) -> Any:
        """Compile a rule expression."""
        return self.rule_engine.compile_rule(expression)

    async def evaluate_rule(
        self,
        rule: RuleEntity,
        resource: Optional[ResourceEntity] = None,
        config: Optional[ConfigEntity] = None,
        principal: Optional[PrincipalEntity] = None,
        iam_permission: Optional[IamPermissionEntity] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Evaluate a rule against given entities."""
        # Build evaluation context
        eval_context = EvaluationContext()

        if resource:
            eval_context.resource = {
                "external_id": resource.external_id,
                "resource_type": resource.resource_type,
                "provider": resource.provider,
                "name": resource.name,
            }

        if config:
            eval_context.config = config.normalized_config

        if principal:
            eval_context.principal = {
                "external_id": principal.external_id,
                "principal_type": principal.principal_type.value,
                "provider": principal.provider,
                "email": principal.email,
                "display_name": principal.display_name,
                "is_human": principal.is_human,
            }

        if iam_permission:
            eval_context.iam_edge = {
                "permission": iam_permission.permission,
                "via": iam_permission.via,
                "is_admin": iam_permission.is_admin,
                "effective_at": (
                    iam_permission.effective_at.isoformat()
                    if iam_permission.effective_at
                    else None
                ),
            }

        if context:
            # Merge additional context
            if context.get("org_config"):
                eval_context.org_config = context["org_config"]
            if context.get("user_config"):
                eval_context.user_config = context["user_config"]

        # Evaluate the rule
        result = self.rule_engine.evaluate_rule(
            rule.rule_id, rule.expression, eval_context
        )

        return result.matched

    async def evaluate_rules_batch(
        self,
        rules: List[RuleEntity],
        resources: List[ResourceEntity],
        configs: Dict[str, ConfigEntity],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[UUID, List[bool]]:
        """Batch evaluate multiple rules against multiple resources."""
        results = {}

        for rule in rules:
            rule_results = []

            for resource in resources:
                config = configs.get(resource.external_id)

                try:
                    result = await self.evaluate_rule(
                        rule, resource, config, context=context
                    )
                    rule_results.append(result)
                except Exception as e:
                    logger.error(f"Rule evaluation failed for {rule.rule_id}: {e}")
                    rule_results.append(False)

            results[rule.rule_id] = rule_results

        return results


class IdentityStitcherAdapter:
    """Identity stitcher adapter implementing IdentityStitcherPort."""

    def __init__(self, db_session: AsyncSession):
        """Initialize identity stitcher adapter."""
        self.db = db_session

    async def find_identity_clusters(
        self, org_id: UUID, principals: List[PrincipalEntity]
    ) -> List[IdentityClusterEntity]:
        """Find identity clusters for given principals."""
        from cerebro.core.identity import IdentityStitcher

        # Use the existing IdentityStitcher implementation
        stitcher = IdentityStitcher(self.db)

        # The existing method expects an org_id and gets principals from DB
        # but the port interface passes principals directly
        # For now, we'll use the existing implementation
        clusters = await stitcher.find_identity_clusters(org_id)

        # Convert to domain entities
        domain_clusters = []
        for cluster in clusters:
            # Convert Principal models to PrincipalEntity
            principal_entities = []
            for principal in cluster.principals:
                principal_entity = PrincipalEntity(
                    external_id=principal.external_id,
                    provider=principal.provider,
                    principal_type=principal.principal_type,
                    display_name=principal.name,
                    email=principal.email,
                    metadata=principal.metadata or {},
                )
                principal_entities.append(principal_entity)

            cluster_entity = IdentityClusterEntity(
                cluster_id=cluster.cluster_id,
                principals=principal_entities,
                confidence_score=cluster.confidence_score,
                stitching_evidence=cluster.stitching_evidence,
            )
            domain_clusters.append(cluster_entity)

        return domain_clusters

    async def get_unified_identity(
        self, principal: PrincipalEntity
    ) -> Optional[IdentityClusterEntity]:
        """Get unified identity for a principal."""
        # This would require additional implementation in the core IdentityStitcher
        # For now, return None as this is not implemented
        logger.warning("get_unified_identity not implemented")
        return None
