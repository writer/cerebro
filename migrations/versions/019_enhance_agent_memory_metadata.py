"""Enhance agent memory metadata with content hashes and token counts

Revision ID: 019
Revises: 018
Create Date: 2024-10-16 17:05:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_memory_entries",
        sa.Column("content_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "agent_memory_entries",
        sa.Column("token_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.alter_column(
        "agent_memory_entries",
        "token_count",
        server_default=None,
    )
    op.create_index(
        "ix_agent_memory_entries_content_hash",
        "agent_memory_entries",
        ["content_hash"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_agent_memory_entries_content_hash",
        table_name="agent_memory_entries",
    )
    op.drop_column("agent_memory_entries", "token_count")
    op.drop_column("agent_memory_entries", "content_hash")
