"""Add Slack integration tables

Revision ID: 013_add_slack_integration
Revises: 012_add_agent_session_context
Create Date: 2025-09-29

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = "013_add_slack_integration"
down_revision = "012_add_agent_session_context"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create slack_webhooks table
    op.create_table(
        "slack_webhooks",
        sa.Column("webhook_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("orgs.org_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "name",
            sa.String(255),
            nullable=False,
            comment="Human-readable name for this webhook",
        ),
        sa.Column(
            "webhook_url",
            sa.Text(),
            nullable=False,
            comment="Slack incoming webhook URL",
        ),
        sa.Column(
            "channel",
            sa.String(255),
            nullable=True,
            comment="Slack channel name (e.g., #security-alerts)",
        ),
        sa.Column("enabled", sa.Boolean(), default=True, nullable=False),
        sa.Column(
            "severity_filter",
            postgresql.ARRAY(sa.String),
            nullable=True,
            comment="Filter by severity: critical, high, medium, low",
        ),
        sa.Column(
            "finding_type_filter",
            postgresql.ARRAY(sa.String),
            nullable=True,
            comment="Filter by finding types",
        ),
        sa.Column(
            "event_types",
            postgresql.ARRAY(sa.String),
            nullable=False,
            comment="Event types: finding_created, finding_updated, compliance_failed, monitoring_alert",
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(),
            nullable=True,
            comment="Additional webhook configuration",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            onupdate=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(255), nullable=True),
    )

    # Create indexes
    op.create_index("ix_slack_webhooks_org_id", "slack_webhooks", ["org_id"])
    op.create_index("ix_slack_webhooks_enabled", "slack_webhooks", ["enabled"])

    # Create slack_notifications table (audit log of sent notifications)
    op.create_table(
        "slack_notifications",
        sa.Column("notification_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "webhook_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("slack_webhooks.webhook_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("orgs.org_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("severity", sa.String(50), nullable=True),
        sa.Column(
            "payload",
            postgresql.JSONB(),
            nullable=False,
            comment="Full Slack message payload",
        ),
        sa.Column(
            "status", sa.String(50), nullable=False, comment="sent, failed, retrying"
        ),
        sa.Column(
            "status_code",
            sa.Integer(),
            nullable=True,
            comment="HTTP response status code",
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("retry_count", sa.Integer(), default=0, nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )

    # Create indexes for notifications
    op.create_index(
        "ix_slack_notifications_webhook_id", "slack_notifications", ["webhook_id"]
    )
    op.create_index("ix_slack_notifications_org_id", "slack_notifications", ["org_id"])
    op.create_index(
        "ix_slack_notifications_finding_id", "slack_notifications", ["finding_id"]
    )
    op.create_index("ix_slack_notifications_status", "slack_notifications", ["status"])
    op.create_index(
        "ix_slack_notifications_created_at", "slack_notifications", ["created_at"]
    )

    # Add slack_config to organization settings (optional JSONB field)
    op.add_column(
        "orgs",
        sa.Column(
            "slack_config",
            postgresql.JSONB(),
            nullable=True,
            comment="Slack workspace and default settings",
        ),
    )


def downgrade() -> None:
    op.drop_column("orgs", "slack_config")
    op.drop_table("slack_notifications")
    op.drop_table("slack_webhooks")
