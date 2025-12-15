"""Provenance tracking for audit and forensics."""

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import and_, desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditEvent, ConfigSnapshot, IamEdge

logger = logging.getLogger(__name__)


@dataclass
class ProvenanceRecord:
    """A provenance record with full audit trail."""
    entity_id: UUID
    entity_type: str  # 'config_snapshot', 'iam_edge', 'audit_event'
    captured_at: datetime
    source_system: str
    source_api: str
    source_response_hash: str
    collector_version: str
    raw_data: Optional[Dict[str, Any]]
    transformations: List[str]


class ProvenanceTracker:
    """Tracks provenance for all ingested data."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize provenance tracker."""
        self.db = db_session
    
    async def get_config_provenance(
        self,
        resource_id: UUID,
        at_time: Optional[datetime] = None
    ) -> List[ProvenanceRecord]:
        """Get configuration provenance for a resource."""
        stmt = select(ConfigSnapshot).where(
            ConfigSnapshot.resource_id == resource_id
        )
        
        if at_time:
            stmt = stmt.where(ConfigSnapshot.captured_at <= at_time)
        
        stmt = stmt.order_by(desc(ConfigSnapshot.captured_at))
        snapshots = list(await self.db.scalars(stmt))
        
        records = []
        for snapshot in snapshots:
            record = ProvenanceRecord(
                entity_id=snapshot.snapshot_id,
                entity_type="config_snapshot",
                captured_at=snapshot.captured_at,
                source_system="provider_api",
                source_api=f"{snapshot.resource.provider}_api",
                source_response_hash=snapshot.config_sha.hex(),
                collector_version=snapshot.collector_version,
                raw_data=snapshot.normalized_config,
                transformations=["normalize", "hash"]
            )
            records.append(record)
        
        return records
    
    async def get_permission_history(
        self,
        principal_id: UUID,
        resource_id: Optional[UUID] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[ProvenanceRecord]:
        """Get permission history with full provenance."""
        stmt = select(IamEdge).where(IamEdge.principal_id == principal_id)
        
        if resource_id:
            stmt = stmt.where(IamEdge.resource_id == resource_id)
        if start_time:
            stmt = stmt.where(IamEdge.effective_at >= start_time)
        if end_time:
            stmt = stmt.where(IamEdge.effective_at <= end_time)
        
        stmt = stmt.order_by(desc(IamEdge.effective_at))
        edges = list(await self.db.scalars(stmt))
        
        records = []
        for edge in edges:
            record = ProvenanceRecord(
                entity_id=edge.edge_id,
                entity_type="iam_edge",
                captured_at=edge.effective_at,
                source_system="provider_api",
                source_api=f"{edge.provider}_iam_api",
                source_response_hash="",  # Would need to track this
                collector_version="1.0.0",  # Would need to track this
                raw_data={
                    "permission": edge.permission,
                    "via": edge.via,
                    "is_admin": edge.is_admin,
                    "expires_at": edge.expires_at.isoformat() if edge.expires_at else None
                },
                transformations=["normalize_permission", "extract_via"]
            )
            records.append(record)
        
        return records
    
    async def get_audit_trail(
        self,
        account_id: UUID,
        resource_external_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[ProvenanceRecord]:
        """Get audit trail for forensic investigation."""
        stmt = select(AuditEvent).where(AuditEvent.account_id == account_id)
        
        if resource_external_id:
            stmt = stmt.where(AuditEvent.resource_external_id == resource_external_id)
        if start_time:
            stmt = stmt.where(AuditEvent.occurred_at >= start_time)
        if end_time:
            stmt = stmt.where(AuditEvent.occurred_at <= end_time)
        
        stmt = stmt.order_by(desc(AuditEvent.occurred_at))
        events = list(await self.db.scalars(stmt))
        
        records = []
        for event in events:
            record = ProvenanceRecord(
                entity_id=event.event_id,
                entity_type="audit_event",
                captured_at=event.occurred_at,
                source_system="provider_audit_log",
                source_api=f"{event.provider}_audit_api",
                source_response_hash=hashlib.sha256(
                    json.dumps(event.raw, sort_keys=True).encode()
                ).hexdigest()[:16],
                collector_version="1.0.0",
                raw_data=event.raw,
                transformations=["parse_timestamp", "extract_actor", "normalize_action"]
            )
            records.append(record)
        
        return records
    
    async def verify_data_integrity(self, snapshot_id: UUID) -> Dict[str, Any]:
        """Verify data integrity of a configuration snapshot."""
        snapshot = await self.db.get(ConfigSnapshot, snapshot_id)
        if not snapshot:
            return {"valid": False, "error": "Snapshot not found"}
        
        # Recalculate hash
        config_json = json.dumps(snapshot.normalized_config, sort_keys=True)
        calculated_hash = hashlib.sha256(config_json.encode()).digest()
        
        if calculated_hash != snapshot.config_sha:
            return {
                "valid": False,
                "error": "Hash mismatch",
                "stored_hash": snapshot.config_sha.hex(),
                "calculated_hash": calculated_hash.hex()
            }
        
        return {
            "valid": True,
            "snapshot_id": snapshot_id,
            "captured_at": snapshot.captured_at.isoformat(),
            "collector_version": snapshot.collector_version,
            "hash_verified": True
        }
    
    async def get_temporal_diff(
        self,
        resource_id: UUID,
        time1: datetime,
        time2: datetime
    ) -> Dict[str, Any]:
        """Get configuration differences between two points in time."""
        # Get snapshots at or before each time
        stmt1 = select(ConfigSnapshot).where(
            and_(
                ConfigSnapshot.resource_id == resource_id,
                ConfigSnapshot.captured_at <= time1
            )
        ).order_by(desc(ConfigSnapshot.captured_at)).limit(1)
        
        stmt2 = select(ConfigSnapshot).where(
            and_(
                ConfigSnapshot.resource_id == resource_id,
                ConfigSnapshot.captured_at <= time2
            )
        ).order_by(desc(ConfigSnapshot.captured_at)).limit(1)
        
        snapshot1 = await self.db.scalar(stmt1)
        snapshot2 = await self.db.scalar(stmt2)
        
        if not snapshot1 or not snapshot2:
            return {
                "error": "Insufficient data for temporal comparison",
                "snapshot1_found": snapshot1 is not None,
                "snapshot2_found": snapshot2 is not None
            }
        
        # Calculate differences
        config1 = snapshot1.normalized_config
        config2 = snapshot2.normalized_config
        
        added = {}
        removed = {}
        changed = {}
        
        # Find keys that exist in config2 but not config1
        for key in config2:
            if key not in config1:
                added[key] = config2[key]
            elif config1[key] != config2[key]:
                changed[key] = {"from": config1[key], "to": config2[key]}
        
        # Find keys that exist in config1 but not config2
        for key in config1:
            if key not in config2:
                removed[key] = config1[key]
        
        return {
            "resource_id": str(resource_id),
            "time1": time1.isoformat(),
            "time2": time2.isoformat(),
            "snapshot1_id": str(snapshot1.snapshot_id),
            "snapshot2_id": str(snapshot2.snapshot_id),
            "changes": {
                "added": added,
                "removed": removed,
                "changed": changed
            },
            "provenance": {
                "snapshot1_hash": snapshot1.config_sha.hex(),
                "snapshot2_hash": snapshot2.config_sha.hex(),
                "collector_versions": {
                    "snapshot1": snapshot1.collector_version,
                    "snapshot2": snapshot2.collector_version
                }
            }
        }


class TemporalQueryEngine:
    """Temporal queries for time-travel investigations."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize temporal query engine."""
        self.db = db_session
    
    async def who_had_access_at(
        self,
        resource_id: UUID,
        at_time: datetime,
        permission_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Who had access to a resource at a specific time?"""
        stmt = select(IamEdge).join(IamEdge.principal).where(
            and_(
                IamEdge.resource_id == resource_id,
                IamEdge.effective_at <= at_time,
                or_(
                    IamEdge.expires_at.is_(None),
                    IamEdge.expires_at > at_time
                )
            )
        )
        
        if permission_type:
            stmt = stmt.where(IamEdge.permission.contains(permission_type))
        
        edges = list(await self.db.scalars(stmt))
        
        results = []
        for edge in edges:
            results.append({
                "principal_id": str(edge.principal_id),
                "principal_type": edge.principal.principal_type,
                "external_id": edge.principal.external_id,
                "display_name": edge.principal.display_name,
                "permission": edge.permission,
                "via": edge.via,
                "effective_at": edge.effective_at.isoformat(),
                "expires_at": edge.expires_at.isoformat() if edge.expires_at else None,
                "is_admin": edge.is_admin
            })
        
        return results
    
    async def when_did_config_change(
        self,
        resource_id: UUID,
        config_path: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """When did a specific configuration value change?"""
        # This would require a more sophisticated JSONB query
        # For now, we'll get all snapshots and analyze in Python
        
        stmt = select(ConfigSnapshot).where(
            ConfigSnapshot.resource_id == resource_id
        )
        
        if start_time:
            stmt = stmt.where(ConfigSnapshot.captured_at >= start_time)
        if end_time:
            stmt = stmt.where(ConfigSnapshot.captured_at <= end_time)
        
        stmt = stmt.order_by(ConfigSnapshot.captured_at)
        snapshots = list(await self.db.scalars(stmt))
        
        changes = []
        previous_value = None
        
        for snapshot in snapshots:
            # Navigate to the config path (simplified - would need robust path parsing)
            current_value = self._get_config_value(snapshot.normalized_config, config_path)
            
            if current_value != previous_value and previous_value is not None:
                changes.append({
                    "timestamp": snapshot.captured_at.isoformat(),
                    "config_path": config_path,
                    "old_value": previous_value,
                    "new_value": current_value,
                    "snapshot_id": str(snapshot.snapshot_id),
                    "hash": snapshot.config_sha.hex()
                })
            
            previous_value = current_value
        
        return changes
    
    def _get_config_value(self, config: Dict[str, Any], path: str) -> Any:
        """Get value from config using dot notation path."""
        keys = path.split(".")
        current = config
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
