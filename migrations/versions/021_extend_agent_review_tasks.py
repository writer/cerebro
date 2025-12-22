"""Extend agent review tasks with escalation and notifications

Revision ID: 021_extend_agent_review_tasks
Revises: 020_add_agent_review_tasks
Create Date: 2025-10-16 18:10:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "021_extend_agent_review_tasks"
down_revision = "020_add_agent_review_tasks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    if not is_sqlite:
        op.execute("ALTER TYPE reviewtaskstatus ADD VALUE IF NOT EXISTS 'escalated'")

    uuid_type = sa.String(36) if is_sqlite else postgresql.UUID(as_uuid=True)
    json_type = sa.JSON() if is_sqlite else postgresql.JSONB()

    op.add_column(
        "agent_review_tasks",
        sa.Column("priority", sa.String(length=50), nullable=True),
    )
    op.add_column(
        "agent_review_tasks",
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "agent_review_tasks",
        sa.Column("escalated_to", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "agent_review_tasks",
        sa.Column("notification_channel", sa.String(length=100), nullable=True),
    )
    op.add_column(
        "agent_review_tasks",
        sa.Column("ticket_reference", sa.String(length=255), nullable=True),
    )

    op.create_table(
        "agent_review_notifications",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("org_id", uuid_type, nullable=False),
        sa.Column("task_id", uuid_type, nullable=False),
        sa.Column("channel", sa.String(length=100), nullable=False),
        sa.Column(
            "status", sa.String(length=50), nullable=False, server_default="pending"
        ),
        sa.Column(
            "payload",
            json_type,
            nullable=False,
            server_default=sa.text("'{}'" if is_sqlite else "'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.org_id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["agent_review_tasks.id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_agent_review_notifications_task_id",
        "agent_review_notifications",
        ["task_id"],
    )
    op.create_index(
        "ix_agent_review_notifications_status",
        "agent_review_notifications",
        ["status"],
    )

    op.create_table(
        "agent_review_tickets",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("org_id", uuid_type, nullable=False),
        sa.Column("task_id", uuid_type, nullable=False),
        sa.Column("system", sa.String(length=100), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column(
            "status", sa.String(length=50), nullable=False, server_default="open"
        ),
        sa.Column(
            "metadata",
            json_type,
            nullable=False,
            server_default=sa.text("'{}'" if is_sqlite else "'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.org_id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["task_id"], ["agent_review_tasks.id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_agent_review_tickets_task_id",
        "agent_review_tickets",
        ["task_id"],
    )
    op.create_index(
        "ix_agent_review_tickets_system",
        "agent_review_tickets",
        ["system"],
    )


def downgrade() -> None:
    op.drop_index("ix_agent_review_tickets_system", table_name="agent_review_tickets")
    op.drop_index("ix_agent_review_tickets_task_id", table_name="agent_review_tickets")
    op.drop_table("agent_review_tickets")
    op.drop_index(
        "ix_agent_review_notifications_status", table_name="agent_review_notifications"
    )
    op.drop_index(
        "ix_agent_review_notifications_task_id", table_name="agent_review_notifications"
    )
    op.drop_table("agent_review_notifications")
    op.drop_column("agent_review_tasks", "ticket_reference")
    op.drop_column("agent_review_tasks", "notification_channel")
    op.drop_column("agent_review_tasks", "escalated_to")
    op.drop_column("agent_review_tasks", "due_at")
    op.drop_column("agent_review_tasks", "priority")
