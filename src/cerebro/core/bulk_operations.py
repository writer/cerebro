"""Bulk database operations for high-performance data ingestion."""

import hashlib
from datetime import datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import and_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .models import ConfigSnapshot, IamEdge, Principal, Resource

logger = structlog.get_logger(__name__)


class BulkOperations:
    """High-performance bulk operations for data ingestion."""

    def __init__(self, db_session: AsyncSession):
        """Initialize bulk operations with database session."""
        self.db = db_session

    async def bulk_insert_config_snapshots(
        self, account_id: UUID, snapshots: list[dict[str, Any]]
    ) -> int:
        """
        Bulk insert configuration snapshots with conflict resolution.

        Args:
            account_id: Account ID for logging/metrics
            snapshots: List of snapshot dictionaries with keys:
                - resource_id: UUID
                - captured_at: datetime
                - config_sha: bytes (SHA256 hash)
                - normalized_config: dict
                - collector_version: str

        Returns:
            Number of new snapshots inserted (excluding duplicates)
        """
        if not snapshots:
            return 0

        start_time = datetime.utcnow()

        # Process in batches to avoid overwhelming the database
        batch_size = min(settings.collection_batch_size, len(snapshots))
        total_inserted = 0

        for i in range(0, len(snapshots), batch_size):
            batch = snapshots[i : i + batch_size]

            # First, check which snapshots already exist to avoid conflicts
            existing_keys: set[tuple[Any, Any]] = set()
            if len(batch) > 0:
                # Build list of (resource_id, config_sha) tuples to check
                check_tuples = [(s["resource_id"], s["config_sha"]) for s in batch]

                # Query existing snapshots in chunks to avoid parameter limits
                chunk_size = 1000
                for chunk_start in range(0, len(check_tuples), chunk_size):
                    chunk = check_tuples[chunk_start : chunk_start + chunk_size]

                    stmt = select(
                        ConfigSnapshot.resource_id, ConfigSnapshot.config_sha
                    ).where(
                        and_(
                            ConfigSnapshot.resource_id.in_([t[0] for t in chunk]),
                            ConfigSnapshot.config_sha.in_([t[1] for t in chunk]),
                        )
                    )

                    result = await self.db.execute(stmt)
                    existing_keys.update(
                        (row.resource_id, row.config_sha) for row in result.fetchall()
                    )

            # Filter out existing snapshots
            new_snapshots = []
            for snapshot in batch:
                key = (snapshot["resource_id"], snapshot["config_sha"])
                if key not in existing_keys:
                    new_snapshots.append(snapshot)

            if new_snapshots:
                # Use PostgreSQL's INSERT ... ON CONFLICT DO NOTHING for safety
                insert_stmt = insert(ConfigSnapshot).values(new_snapshots)
                insert_stmt = insert_stmt.on_conflict_do_nothing(
                    index_elements=["resource_id", "config_sha"]
                )

                result = await self.db.execute(insert_stmt)
                batch_inserted = result.rowcount
                total_inserted += batch_inserted

                logger.debug(
                    f"Batch inserted {batch_inserted}/{len(batch)} config snapshots"
                )

        # Commit all batches
        await self.db.commit()

        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        logger.info(
            f"Bulk inserted {total_inserted}/{len(snapshots)} config snapshots "
            f"for account {account_id} in {duration_ms:.1f}ms"
        )

        return total_inserted

    async def bulk_insert_iam_edges(self, edges: list[dict[str, Any]]) -> int:
        """
        Bulk insert IAM edges with conflict resolution.

        Args:
            edges: List of IAM edge dictionaries with keys:
                - account_id: UUID
                - provider: str
                - principal_id: UUID
                - resource_id: UUID (optional)
                - permission: str
                - via: str (optional)
                - effective_at: datetime
                - expires_at: datetime (optional)
                - is_admin: bool

        Returns:
            Number of new edges inserted (excluding duplicates)
        """
        if not edges:
            return 0

        start_time = datetime.utcnow()

        # Process in batches
        batch_size = min(settings.iam_edge_batch_size, len(edges))
        total_inserted = 0

        for i in range(0, len(edges), batch_size):
            batch = edges[i : i + batch_size]

            # Use PostgreSQL's upsert capability
            stmt = insert(IamEdge).values(batch)
            # Use the unique constraint from the model for conflict detection
            stmt = stmt.on_conflict_do_nothing(
                index_elements=[
                    "account_id",
                    "provider",
                    "principal_id",
                    "resource_id",
                    "permission",
                    "effective_at",
                    "via",
                ]
            )

            try:
                result = await self.db.execute(stmt)
                batch_inserted = result.rowcount
                total_inserted += batch_inserted

                logger.debug(f"Batch inserted {batch_inserted}/{len(batch)} IAM edges")

            except IntegrityError as e:
                # Log but continue - this shouldn't happen with ON CONFLICT but be defensive
                logger.warning(f"Integrity error in IAM edge batch insert: {e}")
                # Roll back this batch and continue
                await self.db.rollback()
                continue

        # Commit all successful batches
        await self.db.commit()

        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        logger.info(
            f"Bulk inserted {total_inserted}/{len(edges)} IAM edges "
            f"in {duration_ms:.1f}ms"
        )

        return total_inserted

    async def preload_principal_map(
        self, account_id: UUID, provider: str
    ) -> dict[str, UUID]:
        """
        Preload mapping of principal external_id -> principal_id for an account.

        This avoids N+1 queries when processing IAM edges.

        Returns:
            Dictionary mapping external_id to principal_id
        """
        stmt = select(Principal.external_id, Principal.principal_id).where(
            and_(Principal.account_id == account_id, Principal.provider == provider)
        )

        result = await self.db.execute(stmt)
        return {row[0]: row[1] for row in result.fetchall()}

    async def preload_resource_map(
        self, account_id: UUID, provider: str
    ) -> dict[str, UUID]:
        """
        Preload mapping of resource external_id -> resource_id for an account.

        This avoids N+1 queries when processing IAM edges.

        Returns:
            Dictionary mapping external_id to resource_id
        """
        stmt = select(Resource.external_id, Resource.resource_id).where(
            and_(Resource.account_id == account_id, Resource.provider == provider)
        )

        result = await self.db.execute(stmt)
        return {row[0]: row[1] for row in result.fetchall()}

    async def bulk_upsert_resources(
        self, account_id: UUID, provider: str, resources: list[dict[str, Any]]
    ) -> int:
        """
        Bulk upsert resources with conflict resolution.

        Args:
            account_id: Account ID these resources belong to
            provider: Provider name
            resources: List of resource dictionaries with keys:
                - resource_type: str
                - external_id: str
                - name: str (optional)
                - parent_external_id: str (optional)

        Returns:
            Number of resources inserted/updated
        """
        if not resources:
            return 0

        # Add account_id and provider to each resource
        for resource in resources:
            resource["account_id"] = account_id
            resource["provider"] = provider
            if "name" not in resource:
                resource["name"] = None
            if "parent_external_id" not in resource:
                resource["parent_external_id"] = None

        # Use PostgreSQL UPSERT
        stmt = insert(Resource).values(resources)
        stmt = stmt.on_conflict_do_update(
            index_elements=["account_id", "provider", "resource_type", "external_id"],
            set_={
                "name": stmt.excluded.name,
                "parent_external_id": stmt.excluded.parent_external_id,
            },
        )

        result = await self.db.execute(stmt)
        await self.db.commit()

        logger.info(
            f"Bulk upserted {result.rowcount} resources for account {account_id}"
        )
        return result.rowcount

    async def bulk_upsert_principals(
        self, account_id: UUID, provider: str, principals: list[dict[str, Any]]
    ) -> int:
        """
        Bulk upsert principals with conflict resolution.

        Args:
            account_id: Account ID these principals belong to
            provider: Provider name
            principals: List of principal dictionaries with keys:
                - principal_type: str
                - external_id: str
                - email: str (optional)
                - display_name: str (optional)
                - is_human: bool (optional)

        Returns:
            Number of principals inserted/updated
        """
        if not principals:
            return 0

        # Add account_id and provider to each principal
        for principal in principals:
            principal["account_id"] = account_id
            principal["provider"] = provider
            if "email" not in principal:
                principal["email"] = None
            if "display_name" not in principal:
                principal["display_name"] = None
            if "is_human" not in principal:
                principal["is_human"] = None

        # Use PostgreSQL UPSERT
        stmt = insert(Principal).values(principals)
        stmt = stmt.on_conflict_do_update(
            index_elements=["account_id", "provider", "external_id"],
            set_={
                "principal_type": stmt.excluded.principal_type,
                "email": stmt.excluded.email,
                "display_name": stmt.excluded.display_name,
                "is_human": stmt.excluded.is_human,
            },
        )

        result = await self.db.execute(stmt)
        await self.db.commit()

        logger.info(
            f"Bulk upserted {result.rowcount} principals for account {account_id}"
        )
        return result.rowcount


def compute_config_hash(normalized_config: dict[str, Any]) -> bytes:
    """
    Compute SHA256 hash of normalized configuration.

    This ensures consistent hashing across the system.
    """
    import json

    # Ensure consistent serialization
    config_json = json.dumps(normalized_config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(config_json.encode("utf-8")).digest()
