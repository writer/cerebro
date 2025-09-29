"""Add response_time_ms column to webhook_notifications

Revision ID: 016
Revises: 015
Create Date: 2025-09-29

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '016'
down_revision = '015'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add response_time_ms column to webhook_notifications
    op.add_column('webhook_notifications', sa.Column('response_time_ms', sa.Integer(), nullable=True))

    # Create index for performance queries
    op.create_index('ix_webhook_notifications_response_time', 'webhook_notifications', ['response_time_ms'])


def downgrade() -> None:
    # Drop index
    op.drop_index('ix_webhook_notifications_response_time', 'webhook_notifications')

    # Drop column
    op.drop_column('webhook_notifications', 'response_time_ms')