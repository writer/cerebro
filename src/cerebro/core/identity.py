"""Identity stitching across providers."""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Account, Principal
from .repositories_sqlalchemy import IdentityRepository

logger = structlog.get_logger(__name__)


@dataclass
class IdentityCluster:
    """A cluster of related identities across providers."""

    cluster_id: str
    principals: list[Principal]
    confidence_score: float
    stitching_evidence: dict[str, str]


class IdentityStitcher:
    """Stitches identities across different providers."""

    def __init__(self, db_session: AsyncSession):
        """Initialize identity stitcher."""
        self.db = db_session
        self.identity_repo = IdentityRepository(db_session)

    @staticmethod
    def _stable_cluster_name(prefix: str, value: str) -> str:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
        return f"{prefix}-{digest}"

    async def find_identity_clusters(
        self, org_id: UUID, *, persist: bool = True
    ) -> list[IdentityCluster]:
        """Find identity clusters for an organization."""
        # Get all principals for the organization
        stmt = (
            select(Principal)
            .join(Principal.account)
            .where(Principal.account.has(org_id=org_id))
        )
        principals = list(await self.db.scalars(stmt))

        if not principals:
            return []

        logger.info(f"Analyzing {len(principals)} principals for identity stitching")

        # Group by email first (strongest signal)
        email_groups = self._group_by_email(principals)

        # Group by display name patterns
        name_groups = self._group_by_name(principals)

        # Merge groups and calculate confidence
        clusters = []
        processed_ids: set[UUID] = set()

        for email, email_principals in email_groups.items():
            if not email or len(email_principals) < 2:
                continue

            principal_ids = {p.principal_id for p in email_principals}
            if principal_ids.intersection(processed_ids):
                continue

            cluster = IdentityCluster(
                cluster_id=self._stable_cluster_name("email", email),
                principals=email_principals,
                confidence_score=0.9,  # High confidence for email matches
                stitching_evidence={"method": "email_match", "email": email},
            )
            clusters.append(cluster)
            processed_ids.update(principal_ids)

        # Add name-based clusters for remaining principals
        for name, name_principals in name_groups.items():
            if not name or len(name_principals) < 2:
                continue

            principal_ids = {p.principal_id for p in name_principals}
            if principal_ids.intersection(processed_ids):
                continue

            cluster = IdentityCluster(
                cluster_id=self._stable_cluster_name("name", name),
                principals=name_principals,
                confidence_score=0.6,  # Lower confidence for name matches
                stitching_evidence={"method": "name_match", "name": name},
            )
            clusters.append(cluster)
            processed_ids.update(principal_ids)

        logger.info(f"Found {len(clusters)} identity clusters")

        if persist:
            await self._save_identity_clusters(org_id, clusters)

        return clusters

    def _group_by_email(
        self, principals: list[Principal]
    ) -> dict[str, list[Principal]]:
        """Group principals by email address."""
        groups: dict[str, list[Principal]] = {}
        for principal in principals:
            if principal.email and principal.is_human:
                email = principal.email.lower().strip()
                if email not in groups:
                    groups[email] = []
                groups[email].append(principal)
        return groups

    def _group_by_name(self, principals: list[Principal]) -> dict[str, list[Principal]]:
        """Group principals by display name."""
        groups: dict[str, list[Principal]] = {}
        for principal in principals:
            if principal.display_name and principal.is_human:
                # Normalize name (remove common variations)
                name = self._normalize_name(principal.display_name)
                if name not in groups:
                    groups[name] = []
                groups[name].append(principal)
        return groups

    def _normalize_name(self, display_name: str) -> str:
        """Normalize display name for matching."""
        name = display_name.lower().strip()

        # Remove common suffixes
        suffixes = [" (contractor)", " - contractor", " (external)"]
        for suffix in suffixes:
            if name.endswith(suffix):
                name = name[: -len(suffix)]

        return name

    async def get_unified_identity(self, principal_id: UUID) -> dict | None:
        """Get unified identity information for a principal."""
        principal = await self.db.get(Principal, principal_id)
        if not principal:
            return None

        from .identity_models import IdentityCluster as DBIdentityCluster
        from .identity_models import IdentityClusterMember

        org_id = await self.db.scalar(
            select(Account.org_id).where(Account.account_id == principal.account_id)
        )
        if not org_id:
            return None

        db_cluster = await self.db.scalar(
            select(DBIdentityCluster)
            .join(
                IdentityClusterMember,
                IdentityClusterMember.cluster_id == DBIdentityCluster.cluster_id,
            )
            .where(
                and_(
                    DBIdentityCluster.org_id == org_id,
                    DBIdentityCluster.is_active.is_(True),
                    IdentityClusterMember.principal_id == principal_id,
                )
            )
            .order_by(
                DBIdentityCluster.confidence_score.desc(),
                DBIdentityCluster.updated_at.desc(),
            )
            .limit(1)
        )

        if not db_cluster:
            return None

        related_principals = list(
            await self.db.scalars(
                select(Principal)
                .join(
                    IdentityClusterMember,
                    IdentityClusterMember.principal_id == Principal.principal_id,
                )
                .where(IdentityClusterMember.cluster_id == db_cluster.cluster_id)
            )
        )

        return {
            "cluster_id": db_cluster.cluster_name,
            "confidence_score": db_cluster.confidence_score,
            "stitching_evidence": db_cluster.stitching_evidence,
            "related_principals": [
                {
                    "principal_id": p.principal_id,
                    "provider": p.provider,
                    "external_id": p.external_id,
                    "email": p.email,
                    "display_name": p.display_name,
                }
                for p in related_principals
            ],
        }

    async def _save_identity_clusters(
        self, org_id: UUID, clusters: list[IdentityCluster]
    ) -> None:
        """Save identity clusters to database."""
        from .identity_models import IdentityCluster as DBIdentityCluster
        from .identity_models import IdentityClusterMember, IdentityStitchingLog

        saved_clusters = 0

        for cluster in clusters:
            try:
                # Check if cluster already exists
                stmt = select(DBIdentityCluster).where(
                    and_(
                        DBIdentityCluster.org_id == org_id,
                        DBIdentityCluster.cluster_name == cluster.cluster_id,
                    )
                )
                existing_cluster = await self.db.scalar(stmt)

                if existing_cluster:
                    # Update existing cluster
                    existing_cluster.confidence_score = cluster.confidence_score
                    existing_cluster.stitching_evidence = cluster.stitching_evidence
                    existing_cluster.updated_at = datetime.now(UTC)
                    db_cluster = existing_cluster
                else:
                    # Create new cluster
                    db_cluster = DBIdentityCluster(
                        org_id=org_id,
                        cluster_name=cluster.cluster_id,
                        confidence_score=cluster.confidence_score,
                        stitching_method=cluster.stitching_evidence.get(
                            "method", "unknown"
                        ),
                        stitching_evidence=cluster.stitching_evidence,
                    )
                    self.db.add(db_cluster)
                    await self.db.flush()  # Get cluster ID

                # Save cluster members
                for principal in cluster.principals:
                    # Check if member already exists
                    member_stmt = select(IdentityClusterMember).where(
                        and_(
                            IdentityClusterMember.cluster_id == db_cluster.cluster_id,
                            IdentityClusterMember.principal_id
                            == principal.principal_id,
                        )
                    )
                    existing_member = await self.db.scalar(member_stmt)

                    if not existing_member:
                        member = IdentityClusterMember(
                            cluster_id=db_cluster.cluster_id,
                            principal_id=principal.principal_id,
                            confidence_score=cluster.confidence_score,
                            evidence=cluster.stitching_evidence,
                            added_by="system",
                        )
                        self.db.add(member)

                saved_clusters += 1

            except (OSError, RuntimeError, ValueError) as e:
                logger.error(
                    f"Failed to save identity cluster {cluster.cluster_id}: {e}"
                )

        # Log the stitching operation
        stitching_log = IdentityStitchingLog(
            org_id=org_id,
            operation="bulk_cluster_creation",
            principals_affected=[
                p.external_id for cluster in clusters for p in cluster.principals
            ],
            confidence_threshold=0.6,  # Minimum threshold used
            algorithm_version="1.0.0",
            operation_metadata={
                "clusters_processed": len(clusters),
                "clusters_saved": saved_clusters,
                "method": "email_and_name_matching",
            },
        )
        self.db.add(stitching_log)

        await self.db.commit()
        logger.info(f"Saved {saved_clusters} identity clusters to database")
