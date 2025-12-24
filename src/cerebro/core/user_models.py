"""User management models for authentication and authorization."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from .database import Base


class User(Base):
    """User model for authentication."""

    __tablename__ = "users"

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Relationships
    user_scopes: Mapped[list["UserScope"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="UserScope.user_id",
    )
    audit_logs: Mapped[list["UserAuditLog"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Scope(Base):
    """Available scopes/permissions."""

    __tablename__ = "scopes"

    scope_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )

    # Relationships
    user_scopes: Mapped[list["UserScope"]] = relationship(
        back_populates="scope", cascade="all, delete-orphan"
    )


class UserScope(Base):
    """User-scope many-to-many relationship."""

    __tablename__ = "user_scopes"

    user_scope_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE")
    )
    scope_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scopes.scope_id", ondelete="CASCADE")
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    granted_by: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.user_id")
    )

    # Relationships
    user: Mapped["User"] = relationship(
        back_populates="user_scopes", foreign_keys=[user_id]
    )
    scope: Mapped["Scope"] = relationship(back_populates="user_scopes")


class UserAuditLog(Base):
    """Audit log for user actions."""

    __tablename__ = "user_audit_logs"

    log_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE")
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))  # IPv6 compatible
    user_agent: Mapped[str | None] = mapped_column(String(500))
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error_message: Mapped[str | None] = mapped_column(String(1000))

    # Relationships
    user: Mapped["User"] = relationship(back_populates="audit_logs")
