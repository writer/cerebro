"""Add integration sync state table."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "033_add_integration_sync_state"
down_revision = "032_add_pack_triggers_and_targets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "integration_sync_state",
        sa.Column(
            "state_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("integration", sa.String(length=128), nullable=False),
        sa.Column(
            "scope", sa.String(length=128), nullable=False, server_default="default"
        ),
        sa.Column("last_cursor", sa.String(length=512), nullable=True),
        sa.Column("last_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "state_metadata",
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
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.PrimaryKeyConstraint("state_id"),
        sa.UniqueConstraint("integration", "scope"),
    )
    op.create_index(
        "ix_integration_sync_state_integration",
        "integration_sync_state",
        ["integration"],
    )
    op.create_index(
        "ix_integration_sync_state_scope",
        "integration_sync_state",
        ["scope"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_integration_sync_state_scope", table_name="integration_sync_state"
    )
    op.drop_index(
        "ix_integration_sync_state_integration", table_name="integration_sync_state"
    )
    op.drop_table("integration_sync_state")
