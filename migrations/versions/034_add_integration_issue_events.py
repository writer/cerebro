"""Add integration sync issue events history table."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "034_add_integration_issue_events"
down_revision = "033_add_integration_sync_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "integration_sync_issue_events",
        sa.Column(
            "issue_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("integration", sa.String(length=128), nullable=False),
        sa.Column(
            "scope", sa.String(length=128), nullable=False, server_default="default"
        ),
        sa.Column("issue_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("age_seconds", sa.Float(), nullable=True),
        sa.Column(
            "issue_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.PrimaryKeyConstraint("issue_id"),
    )
    op.create_index(
        "ix_integration_issue_events_integration",
        "integration_sync_issue_events",
        ["integration"],
    )
    op.create_index(
        "ix_integration_issue_events_scope",
        "integration_sync_issue_events",
        ["scope"],
    )
    op.create_index(
        "ix_integration_issue_events_observed",
        "integration_sync_issue_events",
        ["observed_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_integration_issue_events_observed",
        table_name="integration_sync_issue_events",
    )
    op.drop_index(
        "ix_integration_issue_events_scope", table_name="integration_sync_issue_events"
    )
    op.drop_index(
        "ix_integration_issue_events_integration",
        table_name="integration_sync_issue_events",
    )
    op.drop_table("integration_sync_issue_events")
