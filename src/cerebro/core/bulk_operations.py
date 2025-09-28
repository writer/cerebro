"""Bulk database operations for performance optimization."""

from typing import List, Dict, Any, Optional
from uuid import UUID
from datetime import datetime
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .models import Resource, Principal, ConfigSnapshot, IamEdge, Finding

logger = logging.getLogger(__name__)


class BulkOperations:
    """Bulk database operations manager."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize bulk operations manager."""
        self.db = db_session
    
    async def bulk_upsert_resources(
        self,
        account_id: UUID,
        provider: str,
        resources: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Bulk insert/update resources."""
        if not resources:
            return {"inserted": 0, "updated": 0}
        
        # Prepare data for bulk insert
        resource_data = []
        for resource in resources:
            resource_data.append({
                "account_id": account_id,
                "provider": provider,
                "resource_type": resource["resource_type"],
                "external_id": resource["external_id"],
                "name": resource.get("name"),
                "parent_external_id": resource.get("parent_external_id"),
                "created_at": datetime.utcnow(),
            })
        
        # Use PostgreSQL UPSERT (ON CONFLICT DO UPDATE)
        stmt = pg_insert(Resource).values(resource_data)
        stmt = stmt.on_conflict_do_update(
            index_elements=["account_id", "provider", "resource_type", "external_id"],
            set_={
                "name": stmt.excluded.name,
                "parent_external_id": stmt.excluded.parent_external_id,
            }
        )
        
        result = await self.db.execute(stmt)
        await self.db.commit()
        
        logger.info(f"Bulk upserted {len(resources)} resources for provider {provider}")
        return {"processed": len(resources), "provider": provider}
    
    async def bulk_upsert_principals(
        self,
        account_id: UUID,
        provider: str,
        principals: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Bulk insert/update principals."""
        if not principals:
            return {"processed": 0}
        
        # Prepare data for bulk insert
        principal_data = []
        for principal in principals:
            principal_data.append({
                "account_id": account_id,
                "provider": provider,
                "principal_type": principal["principal_type"],
                "external_id": principal["external_id"],
                "email": principal.get("email"),
                "display_name": principal.get("display_name"),
                "is_human": principal.get("is_human"),
            })
        
        # Use PostgreSQL UPSERT
        stmt = pg_insert(Principal).values(principal_data)
        stmt = stmt.on_conflict_do_update(
            index_elements=["account_id", "provider", "external_id"],
            set_={
                "email": stmt.excluded.email,
                "display_name": stmt.excluded.display_name,
                "is_human": stmt.excluded.is_human,
            }
        )
        
        result = await self.db.execute(stmt)
        await self.db.commit()
        
        logger.info(f"Bulk upserted {len(principals)} principals for provider {provider}")
        return {"processed": len(principals), "provider": provider}
    
    async def bulk_insert_config_snapshots(
        self,
        snapshots: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Bulk insert config snapshots (append-only)."""
        if not snapshots:
            return {"inserted": 0}
        
        try:
            # Direct bulk insert - no conflicts expected due to UNIQUE constraint
            result = await self.db.execute(
                insert(ConfigSnapshot).values(snapshots)
            )
            await self.db.commit()
            
            logger.info(f"Bulk inserted {len(snapshots)} config snapshots")
            return {"inserted": len(snapshots)}
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Bulk config snapshot insert failed: {e}")
            return {"inserted": 0, "error": str(e)}
    
    async def bulk_insert_iam_edges(
        self,
        iam_edges: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Bulk insert IAM edges (append-only)."""
        if not iam_edges:
            return {"inserted": 0}
        
        try:
            # Use ON CONFLICT DO NOTHING for IAM edges due to complex unique constraint
            stmt = pg_insert(IamEdge).values(iam_edges)
            stmt = stmt.on_conflict_do_nothing()
            
            result = await self.db.execute(stmt)
            await self.db.commit()
            
            logger.info(f"Bulk processed {len(iam_edges)} IAM edges")
            return {"processed": len(iam_edges)}
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Bulk IAM edges insert failed: {e}")
            return {"processed": 0, "error": str(e)}
    
    async def bulk_update_findings(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Bulk update finding last_seen timestamps."""
        if not findings:
            return {"updated": 0}
        
        # Extract finding IDs and new timestamps
        finding_updates = [(f["finding_id"], f["last_seen"]) for f in findings]
        
        # Use raw SQL for efficient bulk update
        sql = text("""
            UPDATE findings 
            SET last_seen = data.last_seen
            FROM (VALUES (:finding_id, :last_seen)) AS data(finding_id, last_seen)
            WHERE findings.finding_id = data.finding_id::uuid
        """)
        
        try:
            result = await self.db.execute(sql, [
                {"finding_id": str(f_id), "last_seen": timestamp}
                for f_id, timestamp in finding_updates
            ])
            await self.db.commit()
            
            logger.info(f"Bulk updated {len(findings)} findings")
            return {"updated": len(findings)}
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Bulk findings update failed: {e}")
            return {"updated": 0, "error": str(e)}
    
    async def get_existing_resources(
        self, 
        account_id: UUID, 
        provider: str,
        external_ids: List[str]
    ) -> Dict[str, UUID]:
        """Get existing resource IDs for external IDs."""
        if not external_ids:
            return {}
        
        stmt = select(Resource.external_id, Resource.resource_id).where(
            Resource.account_id == account_id,
            Resource.provider == provider,
            Resource.external_id.in_(external_ids)
        )
        
        result = await self.db.execute(stmt)
        return {external_id: resource_id for external_id, resource_id in result.fetchall()}
    
    async def get_existing_principals(
        self,
        account_id: UUID,
        provider: str,
        external_ids: List[str]
    ) -> Dict[str, UUID]:
        """Get existing principal IDs for external IDs."""
        if not external_ids:
            return {}
        
        stmt = select(Principal.external_id, Principal.principal_id).where(
            Principal.account_id == account_id,
            Principal.provider == provider,
            Principal.external_id.in_(external_ids)
        )
        
        result = await self.db.execute(stmt)
        return {external_id: principal_id for external_id, principal_id in result.fetchall()}
    
    async def vacuum_analyze_table(self, table_name: str) -> None:
        """Run VACUUM ANALYZE on a table for performance."""
        try:
            # Note: VACUUM cannot run inside a transaction
            await self.db.connection()
            await self.db.execute(text(f"VACUUM ANALYZE {table_name}"))
            logger.info(f"VACUUM ANALYZE completed for {table_name}")
        except Exception as e:
            logger.warning(f"VACUUM ANALYZE failed for {table_name}: {e}")
