"""Identity stitching database models."""

from typing import Dict, Any, List
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import String, Text, Boolean, DateTime, Float, ForeignKey
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from .database import Base


class IdentityCluster(Base):
    """Identity clusters linking principals across providers."""
    __tablename__ = "identity_clusters"
    
    cluster_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE"))
    cluster_name: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    stitching_method: Mapped[str] = mapped_column(String(50), nullable=False)  # email, name, manual
    stitching_evidence: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    
    # Relationships
    cluster_members: Mapped[List["IdentityClusterMember"]] = relationship(back_populates="cluster", cascade="all, delete-orphan")


class IdentityClusterMember(Base):
    """Members of identity clusters.""" 
    __tablename__ = "identity_cluster_members"
    
    member_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    cluster_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("identity_clusters.cluster_id", ondelete="CASCADE"))
    principal_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("principals.principal_id", ondelete="CASCADE"))
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    added_by: Mapped[str] = mapped_column(String(50), default="system")  # system, user, etc.
    
    # Relationships
    cluster: Mapped["IdentityCluster"] = relationship(back_populates="cluster_members")


class IdentityStitchingLog(Base):
    """Log of identity stitching operations."""
    __tablename__ = "identity_stitching_logs"
    
    log_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE"))
    operation: Mapped[str] = mapped_column(String(50), nullable=False)  # create_cluster, merge_clusters, split_cluster
    cluster_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("identity_clusters.cluster_id", ondelete="SET NULL"))
    principals_affected: Mapped[List[str]] = mapped_column(JSONB, nullable=False)
    confidence_threshold: Mapped[float] = mapped_column(Float, nullable=False)
    algorithm_version: Mapped[str] = mapped_column(String(20), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    operation_metadata: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=True)
