"""
Test entity management for security testing workflows.

Implements test entity lifecycle management, tracking, and validation
following security testing best practices.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from cerebro.core.database_types import JSONType
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, DateTime, Boolean, Text
from sqlalchemy.sql import func

from cerebro.core.database import Base

logger = logging.getLogger(__name__)


class TestEntityType(Enum):
    """Types of test entities."""
    USER_ACCOUNT = "user_account"
    SERVICE_ACCOUNT = "service_account"
    TEST_RESOURCE = "test_resource"
    TEST_DATA = "test_data"
    MOCK_INTEGRATION = "mock_integration"
    SANDBOX_ENVIRONMENT = "sandbox_environment"


class TestEntityStatus(Enum):
    """Status of test entities."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPIRED = "expired"
    CLEANUP_PENDING = "cleanup_pending"
    ERROR = "error"


@dataclass
class TestEntityMetadata:
    """Metadata for test entities."""
    created_by: str
    purpose: str
    test_suite: str
    environment: str
    expiration_date: datetime
    cleanup_required: bool
    dependencies: List[str]
    tags: List[str]


class TestEntity(Base):
    """Database model for test entities."""
    __tablename__ = "test_entities"
    
    entity_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    
    # Entity identification
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    
    # Entity details
    entity_config: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default=TestEntityStatus.ACTIVE.value)
    
    # Test context
    test_suite_id: Mapped[Optional[str]] = mapped_column(String(100))
    test_purpose: Mapped[str] = mapped_column(Text, nullable=False)
    environment: Mapped[str] = mapped_column(String(50), nullable=False)
    
    # Lifecycle management
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    cleanup_required: Mapped[bool] = mapped_column(Boolean, default=True)
    cleanup_completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    
    # Dependencies and relationships
    depends_on: Mapped[Optional[List[str]]] = mapped_column(JSONType)  # List of entity IDs
    supports: Mapped[Optional[List[str]]] = mapped_column(JSONType)    # List of entity IDs
    
    # Tags and metadata
    tags: Mapped[Optional[List[str]]] = mapped_column(JSONType)
    entity_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType)
    
    # Tracking
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    last_accessed: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class TestEntityManager:
    """Manager for test entity lifecycle and operations."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize test entity manager."""
        self.db = db_session
    
    async def create_test_entity(
        self,
        org_id: UUID,
        entity_type: TestEntityType,
        external_id: str,
        display_name: str,
        entity_config: Dict[str, Any],
        test_purpose: str,
        environment: str,
        created_by: str,
        expires_in_hours: Optional[int] = 24,
        depends_on: Optional[List[str]] = None,
        tags: Optional[List[str]] = None
    ) -> TestEntity:
        """Create a new test entity."""
        
        # Calculate expiration
        expires_at = None
        if expires_in_hours:
            expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
        
        entity = TestEntity(
            org_id=org_id,
            entity_type=entity_type.value,
            external_id=external_id,
            display_name=display_name,
            entity_config=entity_config,
            test_purpose=test_purpose,
            environment=environment,
            created_by=created_by,
            expires_at=expires_at,
            depends_on=depends_on or [],
            tags=tags or [],
            entity_metadata={"created_for_testing": True}
        )
        
        self.db.add(entity)
        await self.db.commit()
        await self.db.refresh(entity)
        
        logger.info(f"Created test entity {entity.entity_id} of type {entity_type.value}")
        return entity
    
    async def get_test_entity(self, entity_id: UUID) -> Optional[TestEntity]:
        """Get test entity by ID."""
        return await self.db.get(TestEntity, entity_id)
    
    async def list_test_entities(
        self,
        org_id: UUID,
        entity_type: Optional[TestEntityType] = None,
        environment: Optional[str] = None,
        status: Optional[TestEntityStatus] = None,
        test_suite_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[TestEntity]:
        """List test entities with filtering."""
        stmt = select(TestEntity).where(TestEntity.org_id == org_id)
        
        if entity_type:
            stmt = stmt.where(TestEntity.entity_type == entity_type.value)
        if environment:
            stmt = stmt.where(TestEntity.environment == environment)
        if status:
            stmt = stmt.where(TestEntity.status == status.value)
        if test_suite_id:
            stmt = stmt.where(TestEntity.test_suite_id == test_suite_id)
        
        stmt = stmt.order_by(desc(TestEntity.created_at)).offset(offset).limit(limit)
        
        return list(await self.db.scalars(stmt))
    
    async def update_entity_status(
        self,
        entity_id: UUID,
        status: TestEntityStatus,
        notes: Optional[str] = None
    ) -> bool:
        """Update test entity status."""
        entity = await self.get_test_entity(entity_id)
        if not entity:
            return False
        
        entity.status = status.value
        entity.last_accessed = datetime.utcnow()
        
        if notes and entity.entity_metadata:
            entity.entity_metadata["status_notes"] = notes
        
        await self.db.commit()
        
        logger.info(f"Updated test entity {entity_id} status to {status.value}")
        return True
    
    async def cleanup_expired_entities(self, org_id: UUID) -> int:
        """Clean up expired test entities."""
        now = datetime.utcnow()
        
        stmt = select(TestEntity).where(
            and_(
                TestEntity.org_id == org_id,
                TestEntity.expires_at < now,
                TestEntity.status == TestEntityStatus.ACTIVE.value,
                TestEntity.cleanup_required == True
            )
        )
        
        expired_entities = list(await self.db.scalars(stmt))
        
        cleanup_count = 0
        for entity in expired_entities:
            try:
                # Mark as cleanup pending
                entity.status = TestEntityStatus.CLEANUP_PENDING.value
                
                # Perform actual cleanup based on entity type
                await self._cleanup_entity_resources(entity)
                
                # Mark cleanup as completed
                entity.cleanup_completed_at = now
                entity.status = TestEntityStatus.EXPIRED.value
                
                cleanup_count += 1
                logger.info(f"Cleaned up expired test entity {entity.entity_id}")
                
            except Exception as e:
                entity.status = TestEntityStatus.ERROR.value
                logger.error(f"Failed to cleanup test entity {entity.entity_id}: {e}")
        
        await self.db.commit()
        
        logger.info(f"Cleaned up {cleanup_count} expired test entities")
        return cleanup_count
    
    async def _cleanup_entity_resources(self, entity: TestEntity) -> None:
        """Clean up resources associated with a test entity."""
        entity_type = TestEntityType(entity.entity_type)
        
        if entity_type == TestEntityType.USER_ACCOUNT:
            await self._cleanup_user_account(entity)
        elif entity_type == TestEntityType.SERVICE_ACCOUNT:
            await self._cleanup_service_account(entity)
        elif entity_type == TestEntityType.TEST_RESOURCE:
            await self._cleanup_test_resource(entity)
        elif entity_type == TestEntityType.TEST_DATA:
            await self._cleanup_test_data(entity)
        
        logger.debug(f"Cleaned up resources for {entity_type.value} entity {entity.entity_id}")
    
    async def _cleanup_user_account(self, entity: TestEntity) -> None:
        """Clean up test user account."""
        # Implementation would depend on the provider
        # For now, just log the cleanup action
        logger.info(f"Cleaning up test user account: {entity.external_id}")
    
    async def _cleanup_service_account(self, entity: TestEntity) -> None:
        """Clean up test service account."""
        logger.info(f"Cleaning up test service account: {entity.external_id}")
    
    async def _cleanup_test_resource(self, entity: TestEntity) -> None:
        """Clean up test resource."""
        logger.info(f"Cleaning up test resource: {entity.external_id}")
    
    async def _cleanup_test_data(self, entity: TestEntity) -> None:
        """Clean up test data."""
        logger.info(f"Cleaning up test data: {entity.external_id}")
    
    async def get_entity_dependencies(self, entity_id: UUID) -> List[TestEntity]:
        """Get entities that this entity depends on."""
        entity = await self.get_test_entity(entity_id)
        if not entity or not entity.depends_on:
            return []
        
        stmt = select(TestEntity).where(
            TestEntity.entity_id.in_(entity.depends_on)
        )
        
        return list(await self.db.scalars(stmt))
    
    async def get_entity_dependents(self, entity_id: UUID) -> List[TestEntity]:
        """Get entities that depend on this entity."""
        stmt = select(TestEntity).where(
            TestEntity.depends_on.contains([str(entity_id)])
        )
        
        return list(await self.db.scalars(stmt))
    
    async def validate_entity_dependencies(self, entity_id: UUID) -> Dict[str, Any]:
        """Validate that all dependencies are available and active."""
        entity = await self.get_test_entity(entity_id)
        if not entity:
            return {"valid": False, "error": "Entity not found"}
        
        dependencies = await self.get_entity_dependencies(entity_id)
        
        validation_results = {
            "valid": True,
            "total_dependencies": len(dependencies),
            "active_dependencies": 0,
            "failed_dependencies": [],
            "warnings": []
        }
        
        for dep in dependencies:
            if dep.status == TestEntityStatus.ACTIVE.value:
                validation_results["active_dependencies"] += 1
            else:
                validation_results["valid"] = False
                validation_results["failed_dependencies"].append({
                    "entity_id": str(dep.entity_id),
                    "external_id": dep.external_id,
                    "status": dep.status,
                    "entity_type": dep.entity_type
                })
        
        # Check for expired dependencies
        now = datetime.utcnow()
        for dep in dependencies:
            if dep.expires_at and dep.expires_at < now:
                validation_results["warnings"].append(
                    f"Dependency {dep.external_id} is expired"
                )
        
        return validation_results
    
    async def get_test_entity_summary(self, org_id: UUID) -> Dict[str, Any]:
        """Get summary of test entities for an organization.
        
        Uses SQL aggregation for efficient counting on large datasets.
        """
        now = datetime.utcnow()
        soon_threshold = now + timedelta(hours=4)
        
        # Total count
        total_stmt = select(func.count()).select_from(TestEntity).where(
            TestEntity.org_id == org_id
        )
        total = await self.db.scalar(total_stmt) or 0
        
        # Count by type
        type_stmt = select(
            TestEntity.entity_type,
            func.count().label('count')
        ).where(TestEntity.org_id == org_id).group_by(TestEntity.entity_type)
        type_results = await self.db.execute(type_stmt)
        by_type = {row.entity_type: row.count for row in type_results}
        
        # Count by status
        status_stmt = select(
            TestEntity.status,
            func.count().label('count')
        ).where(TestEntity.org_id == org_id).group_by(TestEntity.status)
        status_results = await self.db.execute(status_stmt)
        by_status = {row.status: row.count for row in status_results}
        
        # Count by environment
        env_stmt = select(
            TestEntity.environment,
            func.count().label('count')
        ).where(TestEntity.org_id == org_id).group_by(TestEntity.environment)
        env_results = await self.db.execute(env_stmt)
        by_environment = {row.environment: row.count for row in env_results}
        
        # Count expiring soon
        expiring_stmt = select(func.count()).select_from(TestEntity).where(
            and_(
                TestEntity.org_id == org_id,
                TestEntity.expires_at <= soon_threshold,
                TestEntity.expires_at > now
            )
        )
        expiring_soon = await self.db.scalar(expiring_stmt) or 0
        
        # Cleanup pending is already in by_status
        cleanup_pending = by_status.get(TestEntityStatus.CLEANUP_PENDING.value, 0)
        
        return {
            "total_entities": total,
            "by_type": by_type,
            "by_status": by_status,
            "by_environment": by_environment,
            "expiring_soon": expiring_soon,
            "cleanup_pending": cleanup_pending
        }
