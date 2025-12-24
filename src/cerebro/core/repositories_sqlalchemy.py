"""Repository facade pattern for data access abstraction."""

from typing import List, Optional
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .models import Finding, Resource
from .identity_models import (
    IdentityCluster,
    IdentityClusterMember,
    IdentityStitchingLog,
)


class IdentityRepository:
    """Repository for identity and cluster management operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_cluster(
        self, org_id: UUID, cluster_name: str
    ) -> Optional[IdentityCluster]:
        """Get identity cluster by organization and name."""
        stmt = select(IdentityCluster).where(
            and_(
                IdentityCluster.org_id == org_id,
                IdentityCluster.cluster_name == cluster_name,
            )
        )
        return await self.db.scalar(stmt)

    async def create_cluster(
        self, org_id: UUID, cluster_name: str, **kwargs
    ) -> IdentityCluster:
        """Create new identity cluster."""
        cluster = IdentityCluster(org_id=org_id, cluster_name=cluster_name, **kwargs)
        self.db.add(cluster)
        await self.db.flush()
        return cluster

    async def get_cluster_members(
        self, cluster_id: UUID
    ) -> List[IdentityClusterMember]:
        """Get all members of an identity cluster."""
        stmt = (
            select(IdentityClusterMember)
            .where(IdentityClusterMember.cluster_id == cluster_id)
            .options(selectinload(IdentityClusterMember.principal))  # type: ignore[attr-defined]
        )
        result = await self.db.scalars(stmt)
        return list(result)

    async def add_cluster_member(
        self, cluster_id: UUID, principal_id: UUID, confidence_score: float
    ) -> IdentityClusterMember:
        """Add principal to identity cluster."""
        member = IdentityClusterMember(
            cluster_id=cluster_id,
            principal_id=principal_id,
            confidence_score=confidence_score,
        )
        self.db.add(member)
        await self.db.flush()
        return member

    async def log_stitching_operation(
        self, org_id: UUID, operation_type: str, details: dict, **kwargs
    ) -> IdentityStitchingLog:
        """Log identity stitching operation for audit trail."""
        log_entry = IdentityStitchingLog(
            org_id=org_id,
            operation_type=operation_type,
            operation_details=details,
            **kwargs,
        )
        self.db.add(log_entry)
        await self.db.flush()
        return log_entry


class ResourceRepository:
    """Repository for resource management operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_external_id(
        self, account_id: UUID, external_id: str
    ) -> Optional[Resource]:
        """Get resource by external ID within an account."""
        stmt = select(Resource).where(
            and_(Resource.account_id == account_id, Resource.external_id == external_id)
        )
        return await self.db.scalar(stmt)

    async def get_by_type(self, account_id: UUID, resource_type: str) -> List[Resource]:
        """Get all resources of a specific type."""
        stmt = select(Resource).where(
            and_(
                Resource.account_id == account_id,
                Resource.resource_type == resource_type,
            )
        )
        result = await self.db.scalars(stmt)
        return list(result)


class FindingRepository:
    """Repository for finding management operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_active_by_severity(
        self, org_id: UUID, severity: str
    ) -> List[Finding]:
        """Get active findings by severity level."""
        stmt = (
            select(Finding)
            .where(
                and_(
                    Finding.org_id == org_id,
                    Finding.severity == severity,
                    Finding.status == "active",
                )
            )
            .order_by(Finding.created_at.desc())  # type: ignore[attr-defined]
        )
        result = await self.db.scalars(stmt)
        return list(result)

    async def get_mttr_metrics(self, org_id: UUID, days: int = 30) -> dict:
        """Calculate MTTR metrics for resolved findings."""
        from datetime import datetime, timedelta

        cutoff_date = datetime.utcnow() - timedelta(days=days)

        stmt = select(Finding).where(
            and_(
                Finding.org_id == org_id,
                Finding.status.in_(["resolved", "fixed"]),
                Finding.resolved_at >= cutoff_date,  # type: ignore[attr-defined]
            )
        )

        resolved_findings = await self.db.scalars(stmt)
        findings_list = list(resolved_findings)

        if not findings_list:
            return {"mttr": 0, "total_resolved": 0}

        total_resolution_time = sum(
            [
                (f.resolved_at - f.created_at).total_seconds() / 3600  # type: ignore[attr-defined, operator]
                for f in findings_list
                if getattr(f, 'resolved_at', None) and getattr(f, 'created_at', None)
            ]
        )

        mttr = total_resolution_time / len(findings_list)

        return {
            "mttr": round(mttr, 1),
            "total_resolved": len(findings_list),
            "sla_breaches": self._calculate_sla_breaches(findings_list),
        }

    def _calculate_sla_breaches(self, findings: List[Finding]) -> dict:
        """Calculate SLA breaches by severity."""
        sla_targets = {"critical": 4, "high": 24, "medium": 72, "low": 168}
        breaches = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for finding in findings:
            resolved_at = getattr(finding, 'resolved_at', None)
            created_at = getattr(finding, 'created_at', None)
            if resolved_at and created_at:
                resolution_hours = (
                    resolved_at - created_at
                ).total_seconds() / 3600
                target = sla_targets.get(finding.severity, 168)
                if resolution_hours > target:
                    breaches[finding.severity] += 1

        return breaches


# Factory functions for dependency injection
async def get_identity_repository(db: AsyncSession) -> IdentityRepository:
    """Factory function for identity repository."""
    return IdentityRepository(db)


async def get_resource_repository(db: AsyncSession) -> ResourceRepository:
    """Factory function for resource repository."""
    return ResourceRepository(db)


async def get_finding_repository(db: AsyncSession) -> FindingRepository:
    """Factory function for finding repository."""
    return FindingRepository(db)
