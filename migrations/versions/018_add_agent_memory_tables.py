"""Add conversation items and memory tables for agents

Revision ID: 018
Revises: 017
Create Date: 2024-10-15 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    message_role_enum = sa.Enum(
        "user",
        "assistant",
        "tool",
        "system",
        name="messagerole",
        create_type=False,
    )

    op.create_table(
        "agent_conversation_items",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("item", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["agent_sessions.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "ix_agent_conversation_items_session_id",
        "agent_conversation_items",
        ["session_id"],
    )
    op.create_index(
        "ix_agent_conversation_items_created_at",
        "agent_conversation_items",
        ["created_at"],
    )

    op.create_table(
        "agent_memory_entries",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("agent_type", sa.String(length=100), nullable=True),
        sa.Column("role", message_role_enum, nullable=True),
        sa.Column(
            "scopes",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "scope_priority", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("summary", sa.String(length=500), nullable=True),
        sa.Column("embedding", postgresql.JSONB(), nullable=True),
        sa.Column("embedding_norm", sa.Float(), nullable=True),
        sa.Column(
            "extra_metadata",
            postgresql.JSONB(),
            nullable=True,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "decay_score", sa.Float(), nullable=False, server_default=sa.text("1.0")
        ),
        sa.Column(
            "last_accessed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["session_id"], ["agent_sessions.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "ix_agent_memory_entries_org_id",
        "agent_memory_entries",
        ["org_id"],
    )
    op.create_index(
        "ix_agent_memory_entries_session_id",
        "agent_memory_entries",
        ["session_id"],
    )
    op.create_index(
        "ix_agent_memory_entries_created_at",
        "agent_memory_entries",
        ["created_at"],
    )
    op.create_index(
        "ix_agent_memory_entries_scope_priority",
        "agent_memory_entries",
        ["scope_priority"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_agent_memory_entries_scope_priority",
        table_name="agent_memory_entries",
    )
    op.drop_index(
        "ix_agent_memory_entries_created_at",
        table_name="agent_memory_entries",
    )
    op.drop_index(
        "ix_agent_memory_entries_session_id",
        table_name="agent_memory_entries",
    )
    op.drop_index(
        "ix_agent_memory_entries_org_id",
        table_name="agent_memory_entries",
    )
    op.drop_table("agent_memory_entries")

    op.drop_index(
        "ix_agent_conversation_items_created_at",
        table_name="agent_conversation_items",
    )
    op.drop_index(
        "ix_agent_conversation_items_session_id",
        table_name="agent_conversation_items",
    )
    op.drop_table("agent_conversation_items")
