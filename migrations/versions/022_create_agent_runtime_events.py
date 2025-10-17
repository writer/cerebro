"""Create agent runtime analytics tables

Revision ID: 022_create_agent_runtime_events
Revises: 021_extend_agent_review_tasks
Create Date: 2025-10-16 18:10:30.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "022_create_agent_runtime_events"
down_revision = "021_extend_agent_review_tasks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"
    uuid_type = sa.String(36) if is_sqlite else postgresql.UUID(as_uuid=True)
    json_type = sa.JSON() if is_sqlite else postgresql.JSONB()

    op.create_table(
        "agent_runtime_events",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("org_id", uuid_type, nullable=False),
        sa.Column("session_id", uuid_type, nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("payload", json_type, nullable=False, server_default=sa.text("'{}'" if is_sqlite else "'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.org_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["session_id"], ["agent_sessions.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_agent_runtime_events_session_id",
        "agent_runtime_events",
        ["session_id"],
    )
    op.create_index(
        "ix_agent_runtime_events_event_type",
        "agent_runtime_events",
        ["event_type"],
    )


def downgrade() -> None:
    op.drop_index("ix_agent_runtime_events_event_type", table_name="agent_runtime_events")
    op.drop_index("ix_agent_runtime_events_session_id", table_name="agent_runtime_events")
    op.drop_table("agent_runtime_events")
