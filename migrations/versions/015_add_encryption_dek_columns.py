"""Add DEK columns for encrypted fields in notification configs

Revision ID: 015_add_encryption_dek_columns
Revises: 014_add_email_webhook_notifications
Create Date: 2025-09-29

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '015_add_encryption_dek_columns'
down_revision = '014_add_email_webhook_notifications'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add DEK columns for EmailConfig encrypted fields
    op.add_column('email_configs', sa.Column('smtp_password_dek', sa.LargeBinary(), nullable=True))
    op.create_index('ix_email_configs_smtp_password_dek', 'email_configs', ['smtp_password_dek'])

    # Add DEK columns for WebhookConfig encrypted fields
    op.add_column('webhook_configs', sa.Column('hmac_secret_dek', sa.LargeBinary(), nullable=True))
    op.add_column('webhook_configs', sa.Column('authentication_dek', sa.LargeBinary(), nullable=True))
    op.create_index('ix_webhook_configs_hmac_secret_dek', 'webhook_configs', ['hmac_secret_dek'])

    # Add DEK column for SlackWebhook encrypted field
    op.add_column('slack_webhooks', sa.Column('webhook_url_dek', sa.LargeBinary(), nullable=True))
    op.create_index('ix_slack_webhooks_webhook_url_dek', 'slack_webhooks', ['webhook_url_dek'])

    # Update column types to LargeBinary for encrypted data
    # Note: This migration assumes no existing data or data will be migrated separately
    op.alter_column('email_configs', 'smtp_password',
                   existing_type=sa.Text(),
                   type_=sa.LargeBinary(),
                   existing_nullable=True)

    op.alter_column('webhook_configs', 'hmac_secret',
                   existing_type=sa.Text(),
                   type_=sa.LargeBinary(),
                   existing_nullable=True)

    # authentication stays as JSONB (encrypted as JSON string then stored)
    # webhook_url stays as Text (encrypted as bytes then stored)


def downgrade() -> None:
    # Drop indexes
    op.drop_index('ix_slack_webhooks_webhook_url_dek', 'slack_webhooks')
    op.drop_index('ix_webhook_configs_hmac_secret_dek', 'webhook_configs')
    op.drop_index('ix_email_configs_smtp_password_dek', 'email_configs')

    # Drop DEK columns
    op.drop_column('slack_webhooks', 'webhook_url_dek')
    op.drop_column('webhook_configs', 'authentication_dek')
    op.drop_column('webhook_configs', 'hmac_secret_dek')
    op.drop_column('email_configs', 'smtp_password_dek')

    # Revert column types
    op.alter_column('email_configs', 'smtp_password',
                   existing_type=sa.LargeBinary(),
                   type_=sa.Text(),
                   existing_nullable=True)

    op.alter_column('webhook_configs', 'hmac_secret',
                   existing_type=sa.LargeBinary(),
                   type_=sa.Text(),
                   existing_nullable=True)