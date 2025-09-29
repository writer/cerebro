"""Add agent session context for cross-session memory

Revision ID: 012_add_agent_session_context
Revises: 011_add_agent_tables
Create Date: 2025-09-29

Enables agents to remember context across sessions for continuity and learning.
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic
revision: str = '012_add_agent_session_context'
down_revision: Union[str, None] = '011'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add agent_session_context table for cross-session memory."""

    # Create agent_session_context table
    op.create_table(
        'agent_session_context',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('context_key', sa.String(255), nullable=False, comment='Key identifying the context (e.g. prod_account_id, ceo_name)'),
        sa.Column('context_value', postgresql.JSONB, nullable=False, comment='Value stored as JSONB for flexibility'),
        sa.Column('context_type', sa.String(50), nullable=False, comment='Type: user_preference, learned_fact, correction, environment'),
        sa.Column('learned_from', sa.String(50), nullable=False, comment='Source: user_conversation, tool_execution, external_source'),
        sa.Column('confidence', sa.Float, nullable=True, comment='Confidence score 0-1 for learned facts'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True, comment='Optional expiration for temporary context'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('created_by', sa.String(255), nullable=False),
        sa.Column('metadata', postgresql.JSONB, nullable=True, comment='Additional metadata about the context'),

        # Foreign keys
        sa.ForeignKeyConstraint(['session_id'], ['agent_sessions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['org_id'], ['orgs.org_id'], ondelete='CASCADE'),

        # Indexes for fast retrieval
        sa.Index('idx_agent_session_context_session_id', 'session_id'),
        sa.Index('idx_agent_session_context_org_id', 'org_id'),
        sa.Index('idx_agent_session_context_key', 'context_key'),
        sa.Index('idx_agent_session_context_org_key', 'org_id', 'context_key'),  # Composite for org-level context lookup
        sa.Index('idx_agent_session_context_created_at', 'created_at'),
    )

    # Add comment to table
    op.execute("""
        COMMENT ON TABLE agent_session_context IS
        'Stores learned context and preferences from agent sessions for cross-session continuity.
        Enables agents to remember user preferences, environment facts, and corrections.'
    """)


def downgrade() -> None:
    """Remove agent_session_context table."""
    op.drop_table('agent_session_context')