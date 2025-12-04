"""add review task enhancements

Revision ID: 024_add_review_enhancements
Revises: 023_memory_decay_overrides_and_policy_suggestions
Create Date: 2024-10-16

Adds assignment, comments, and audit history to review tasks.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "024_add_review_enhancements"
down_revision = "023_memory_decay_overrides_and_policy_suggestions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add assignment columns to agent_review_tasks
    op.add_column('agent_review_tasks', sa.Column('assigned_to', sa.String(length=255), nullable=True))
    op.add_column('agent_review_tasks', sa.Column('assigned_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('agent_review_tasks', sa.Column('assigned_by', sa.String(length=255), nullable=True))
    op.create_index('ix_agent_review_tasks_assigned_to', 'agent_review_tasks', ['assigned_to'])

    # Create agent_review_comments table
    op.create_table(
        'agent_review_comments',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('task_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('author', sa.String(length=255), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.ForeignKeyConstraint(['task_id'], ['agent_review_tasks.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_agent_review_comments_task_id', 'agent_review_comments', ['task_id'])
    op.create_index('ix_agent_review_comments_created_at', 'agent_review_comments', ['created_at'])

    # Create agent_review_history table
    op.create_table(
        'agent_review_history',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('task_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('changed_by', sa.String(length=255), nullable=False),
        sa.Column('change_type', sa.String(length=100), nullable=False),
        sa.Column('field_name', sa.String(length=100), nullable=True),
        sa.Column('old_value', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('new_value', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.ForeignKeyConstraint(['task_id'], ['agent_review_tasks.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_agent_review_history_task_id', 'agent_review_history', ['task_id'])
    op.create_index('ix_agent_review_history_change_type', 'agent_review_history', ['change_type'])
    op.create_index('ix_agent_review_history_created_at', 'agent_review_history', ['created_at'])


def downgrade() -> None:
    # Drop tables
    op.drop_table('agent_review_history')
    op.drop_table('agent_review_comments')
    
    # Drop assignment columns
    op.drop_index('ix_agent_review_tasks_assigned_to', table_name='agent_review_tasks')
    op.drop_column('agent_review_tasks', 'assigned_by')
    op.drop_column('agent_review_tasks', 'assigned_at')
    op.drop_column('agent_review_tasks', 'assigned_to')
