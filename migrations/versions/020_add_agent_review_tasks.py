"""
Add agent review tasks table

Revision ID: 020_add_agent_review_tasks
Revises: 019_enhance_agent_memory_metadata
Create Date: 2024-10-30 00:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "020_add_agent_review_tasks"
down_revision = "019_enhance_agent_memory_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    uuid_type = sa.String(36) if is_sqlite else postgresql.UUID(as_uuid=True)
    json_type = sa.JSON() if is_sqlite else postgresql.JSONB()
    json_default = sa.text("'{}'") if is_sqlite else sa.text("'{}'::jsonb")

    review_status = sa.Enum(
        "pending",
        "approved",
        "rejected",
        "promoted",
        name="reviewtaskstatus",
    )
    review_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "agent_review_tasks",
        sa.Column(
            "id",
            uuid_type,
            nullable=False,
            primary_key=True,
        ),
        sa.Column("org_id", uuid_type, nullable=False),
        sa.Column("session_id", uuid_type, nullable=False),
        sa.Column("message_id", uuid_type, nullable=True),
        sa.Column("tool_invocation_id", uuid_type, nullable=True),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("summary", sa.String(length=1000), nullable=True),
        sa.Column("payload", json_type, nullable=False, server_default=json_default),
        sa.Column(
            "status",
            review_status,
            nullable=False,
            server_default="pending",
        ),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("promotion_target", sa.String(length=255), nullable=True),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.Column("resolved_by", sa.String(length=255), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.org_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["session_id"], ["agent_sessions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["message_id"], ["agent_messages.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tool_invocation_id"], ["tool_invocations.id"], ondelete="SET NULL"),
    )

    op.create_index(
        "ix_agent_review_tasks_org_id",
        "agent_review_tasks",
        ["org_id"],
    )
    op.create_index(
        "ix_agent_review_tasks_session_id",
        "agent_review_tasks",
        ["session_id"],
    )
    op.create_index(
        "ix_agent_review_tasks_message_id",
        "agent_review_tasks",
        ["message_id"],
    )
    op.create_index(
        "ix_agent_review_tasks_tool_invocation_id",
        "agent_review_tasks",
        ["tool_invocation_id"],
    )
    op.create_index(
        "ix_agent_review_tasks_status",
        "agent_review_tasks",
        ["status"],
    )
    op.create_index(
        "ix_agent_review_tasks_created_at",
        "agent_review_tasks",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_agent_review_tasks_created_at", table_name="agent_review_tasks")
    op.drop_index("ix_agent_review_tasks_status", table_name="agent_review_tasks")
    op.drop_index("ix_agent_review_tasks_tool_invocation_id", table_name="agent_review_tasks")
    op.drop_index("ix_agent_review_tasks_message_id", table_name="agent_review_tasks")
    op.drop_index("ix_agent_review_tasks_session_id", table_name="agent_review_tasks")
    op.drop_index("ix_agent_review_tasks_org_id", table_name="agent_review_tasks")
    op.drop_table("agent_review_tasks")
    review_status = sa.Enum(name="reviewtaskstatus")
    review_status.drop(op.get_bind(), checkfirst=True)
