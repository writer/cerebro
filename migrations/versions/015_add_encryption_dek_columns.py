"""Add DEK columns for encrypted fields in notification configs

Revision ID: 015_add_encryption_dek_columns
Revises: 014_add_email_webhook_notifications
Create Date: 2025-09-29

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add DEK columns for EmailConfig encrypted fields
    op.add_column(
        "email_configs", sa.Column("smtp_password_dek", sa.LargeBinary(), nullable=True)
    )
    op.create_index(
        "ix_email_configs_smtp_password_dek", "email_configs", ["smtp_password_dek"]
    )

    # Add DEK columns for WebhookConfig encrypted fields
    op.add_column(
        "webhook_configs", sa.Column("hmac_secret_dek", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "webhook_configs",
        sa.Column("authentication_dek", sa.LargeBinary(), nullable=True),
    )
    op.create_index(
        "ix_webhook_configs_hmac_secret_dek", "webhook_configs", ["hmac_secret_dek"]
    )

    # Add DEK column for SlackWebhook encrypted field
    op.add_column(
        "slack_webhooks", sa.Column("webhook_url_dek", sa.LargeBinary(), nullable=True)
    )
    op.create_index(
        "ix_slack_webhooks_webhook_url_dek", "slack_webhooks", ["webhook_url_dek"]
    )

    # Update column types to LargeBinary for encrypted data
    # Note: This migration assumes no existing data or data will be migrated separately
    # Use raw SQL with USING clause for type conversion
    op.execute(
        "ALTER TABLE email_configs ALTER COLUMN smtp_password TYPE BYTEA USING smtp_password::bytea"
    )
    op.execute(
        "ALTER TABLE webhook_configs ALTER COLUMN hmac_secret TYPE BYTEA USING hmac_secret::bytea"
    )
    op.execute(
        "ALTER TABLE slack_webhooks ALTER COLUMN webhook_url TYPE BYTEA USING webhook_url::bytea"
    )

    # authentication stays as JSONB (encrypted as JSON string then stored)


def downgrade() -> None:
    # Drop indexes
    op.drop_index("ix_slack_webhooks_webhook_url_dek", "slack_webhooks")
    op.drop_index("ix_webhook_configs_hmac_secret_dek", "webhook_configs")
    op.drop_index("ix_email_configs_smtp_password_dek", "email_configs")

    # Drop DEK columns
    op.drop_column("slack_webhooks", "webhook_url_dek")
    op.drop_column("webhook_configs", "authentication_dek")
    op.drop_column("webhook_configs", "hmac_secret_dek")
    op.drop_column("email_configs", "smtp_password_dek")

    # Revert column types
    op.execute(
        "ALTER TABLE slack_webhooks ALTER COLUMN webhook_url TYPE TEXT USING webhook_url::text"
    )
    op.execute(
        "ALTER TABLE email_configs ALTER COLUMN smtp_password TYPE TEXT USING smtp_password::text"
    )
    op.execute(
        "ALTER TABLE webhook_configs ALTER COLUMN hmac_secret TYPE TEXT USING hmac_secret::text"
    )
