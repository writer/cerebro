"""Add host telemetry events table

Revision ID: 028_add_host_telemetry_events
Revises: 027_expand_account_providers
Create Date: 2025-10-28 00:30:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "028_add_host_telemetry_events"
down_revision = "027_expand_account_providers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "host_telemetry_events",
        sa.Column("event_id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("orgs.org_id", ondelete="CASCADE"), nullable=False),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("accounts.account_id", ondelete="SET NULL"), nullable=True),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("resources.resource_id", ondelete="SET NULL"), nullable=True),
        sa.Column("host_id", sa.String(length=255), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("process_id", sa.Integer(), nullable=True),
        sa.Column("parent_pid", sa.Integer(), nullable=True),
        sa.Column("user", sa.String(length=255), nullable=True),
        sa.Column("command_line", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("agent_version", sa.String(length=64), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_index(
        "ix_host_telemetry_events_org_id",
        "host_telemetry_events",
        ["org_id"],
    )
    op.create_index(
        "ix_host_telemetry_events_resource_id",
        "host_telemetry_events",
        ["resource_id"],
    )
    op.create_index(
        "ix_host_telemetry_events_observed",
        "host_telemetry_events",
        ["observed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_host_telemetry_events_observed", table_name="host_telemetry_events")
    op.drop_index("ix_host_telemetry_events_resource_id", table_name="host_telemetry_events")
    op.drop_index("ix_host_telemetry_events_org_id", table_name="host_telemetry_events")
    op.drop_table("host_telemetry_events")
