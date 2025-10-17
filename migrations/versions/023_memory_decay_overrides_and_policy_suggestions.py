"""Add memory decay overrides and policy suggestions

Revision ID: 023_memory_decay_overrides_and_policy_suggestions
Revises: 022_create_agent_runtime_events
Create Date: 2025-10-16 18:11:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "023_memory_decay_overrides_and_policy_suggestions"
down_revision = "022_create_agent_runtime_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"
    uuid_type = sa.String(36) if is_sqlite else postgresql.UUID(as_uuid=True)
    json_type = sa.JSON() if is_sqlite else postgresql.JSONB()

    op.create_table(
        "agent_memory_decay_overrides",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("org_id", uuid_type, nullable=False),
        sa.Column("scope_type", sa.String(length=50), nullable=False),
        sa.Column("scope_value", sa.String(length=255), nullable=True),
        sa.Column("half_life_hours", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.org_id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_agent_memory_decay_overrides_org_scope",
        "agent_memory_decay_overrides",
        ["org_id", "scope_type", "scope_value"],
        unique=True,
    )

    op.create_table(
        "agent_policy_suggestions",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("org_id", uuid_type, nullable=False),
        sa.Column("tool_name", sa.String(length=100), nullable=False),
        sa.Column("cel_expression", sa.Text(), nullable=False),
        sa.Column("support_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reject_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("metadata", json_type, nullable=False, server_default=sa.text("'{}'" if is_sqlite else "'{}'::jsonb")),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.org_id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_agent_policy_suggestions_org_tool",
        "agent_policy_suggestions",
        ["org_id", "tool_name"],
    )


def downgrade() -> None:
    op.drop_index("ix_agent_policy_suggestions_org_tool", table_name="agent_policy_suggestions")
    op.drop_table("agent_policy_suggestions")
    op.drop_index("ix_agent_memory_decay_overrides_org_scope", table_name="agent_memory_decay_overrides")
    op.drop_table("agent_memory_decay_overrides")
