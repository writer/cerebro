"""Add email and generic webhook notification tables

Revision ID: 014_add_email_webhook_notifications
Revises: 013_add_slack_integration
Create Date: 2025-09-29

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '014_add_email_webhook_notifications'
down_revision = '013_add_slack_integration'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create email_configs table
    op.create_table(
        'email_configs',
        sa.Column('config_id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('orgs.org_id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False, comment='Human-readable name'),
        sa.Column('smtp_host', sa.String(255), nullable=False),
        sa.Column('smtp_port', sa.Integer(), nullable=False, default=587),
        sa.Column('smtp_username', sa.String(255), nullable=True),
        sa.Column('smtp_password', sa.Text(), nullable=True, comment='Encrypted password'),
        sa.Column('from_email', sa.String(255), nullable=False),
        sa.Column('from_name', sa.String(255), nullable=True),
        sa.Column('to_emails', postgresql.ARRAY(sa.String), nullable=False, comment='List of recipient emails'),
        sa.Column('cc_emails', postgresql.ARRAY(sa.String), nullable=True),
        sa.Column('use_tls', sa.Boolean(), default=True, nullable=False),
        sa.Column('enabled', sa.Boolean(), default=True, nullable=False),
        sa.Column('severity_filter', postgresql.ARRAY(sa.String), nullable=True),
        sa.Column('event_types', postgresql.ARRAY(sa.String), nullable=False),
        sa.Column('digest_mode', sa.Boolean(), default=False, nullable=False, comment='Send digest instead of immediate'),
        sa.Column('digest_frequency', sa.String(50), nullable=True, comment='daily, weekly'),
        sa.Column('email_metadata', postgresql.JSONB(), nullable=True, comment='Additional config'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
        sa.Column('created_by', sa.String(255), nullable=True),
    )

    # Create indexes for email_configs
    op.create_index('ix_email_configs_org_id', 'email_configs', ['org_id'])
    op.create_index('ix_email_configs_enabled', 'email_configs', ['enabled'])

    # Create email_notifications table
    op.create_table(
        'email_notifications',
        sa.Column('notification_id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('config_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('email_configs.config_id', ondelete='CASCADE'), nullable=False),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('orgs.org_id', ondelete='CASCADE'), nullable=False),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('severity', sa.String(50), nullable=True),
        sa.Column('subject', sa.String(500), nullable=False),
        sa.Column('body_html', sa.Text(), nullable=False),
        sa.Column('body_text', sa.Text(), nullable=True),
        sa.Column('to_emails', postgresql.ARRAY(sa.String), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, comment='sent, failed, retrying'),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), default=0, nullable=False),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # Create indexes for email_notifications
    op.create_index('ix_email_notifications_config_id', 'email_notifications', ['config_id'])
    op.create_index('ix_email_notifications_org_id', 'email_notifications', ['org_id'])
    op.create_index('ix_email_notifications_status', 'email_notifications', ['status'])
    op.create_index('ix_email_notifications_created_at', 'email_notifications', ['created_at'])

    # Create webhook_configs table (generic webhooks)
    op.create_table(
        'webhook_configs',
        sa.Column('config_id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('orgs.org_id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('http_method', sa.String(10), nullable=False, default='POST', comment='POST, PUT, PATCH'),
        sa.Column('headers', postgresql.JSONB(), nullable=True, comment='Custom headers'),
        sa.Column('payload_template', postgresql.JSONB(), nullable=False, comment='Jinja2 template'),
        sa.Column('authentication', postgresql.JSONB(), nullable=True, comment='Auth config'),
        sa.Column('use_hmac_signature', sa.Boolean(), default=False, nullable=False),
        sa.Column('hmac_secret', sa.Text(), nullable=True, comment='HMAC secret key'),
        sa.Column('enabled', sa.Boolean(), default=True, nullable=False),
        sa.Column('severity_filter', postgresql.ARRAY(sa.String), nullable=True),
        sa.Column('event_types', postgresql.ARRAY(sa.String), nullable=False),
        sa.Column('timeout_seconds', sa.Integer(), default=10, nullable=False),
        sa.Column('webhook_metadata', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
        sa.Column('created_by', sa.String(255), nullable=True),
    )

    # Create indexes for webhook_configs
    op.create_index('ix_webhook_configs_org_id', 'webhook_configs', ['org_id'])
    op.create_index('ix_webhook_configs_enabled', 'webhook_configs', ['enabled'])

    # Create webhook_notifications table
    op.create_table(
        'webhook_notifications',
        sa.Column('notification_id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('config_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('webhook_configs.config_id', ondelete='CASCADE'), nullable=False),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('orgs.org_id', ondelete='CASCADE'), nullable=False),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('severity', sa.String(50), nullable=True),
        sa.Column('payload', postgresql.JSONB(), nullable=False),
        sa.Column('response_status', sa.Integer(), nullable=True),
        sa.Column('response_body', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False, comment='sent, failed, retrying'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), default=0, nullable=False),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # Create indexes for webhook_notifications
    op.create_index('ix_webhook_notifications_config_id', 'webhook_notifications', ['config_id'])
    op.create_index('ix_webhook_notifications_org_id', 'webhook_notifications', ['org_id'])
    op.create_index('ix_webhook_notifications_status', 'webhook_notifications', ['status'])
    op.create_index('ix_webhook_notifications_created_at', 'webhook_notifications', ['created_at'])


def downgrade() -> None:
    op.drop_table('webhook_notifications')
    op.drop_table('webhook_configs')
    op.drop_table('email_notifications')
    op.drop_table('email_configs')