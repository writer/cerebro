"""Add performance indexes for digest and stats queries

Revision ID: 017
Revises: 016
Create Date: 2025-09-29

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '017'
down_revision = '016'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Index for time window queries in digest processing
    op.create_index('ix_findings_created_at', 'findings', ['created_at'])

    # Composite index for org-specific digest queries (most selective first)
    op.create_index('ix_findings_org_created', 'findings', ['org_id', 'created_at'])

    # Index for notification stats queries
    op.create_index('ix_email_notifications_status', 'email_notifications', ['status'])
    op.create_index('ix_webhook_notifications_status', 'webhook_notifications', ['status'])


def downgrade() -> None:
    # Drop indexes in reverse order
    op.drop_index('ix_webhook_notifications_status', 'webhook_notifications')
    op.drop_index('ix_email_notifications_status', 'email_notifications')
    op.drop_index('ix_findings_org_created', 'findings')
    op.drop_index('ix_findings_created_at', 'findings')