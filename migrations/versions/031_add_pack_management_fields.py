"""Add management fields to artifact packs

Revision ID: 031_add_pack_management_fields
Revises: 030_expand_artifact_pack_tasks
Create Date: 2025-10-29 14:40:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "031_add_pack_management_fields"
down_revision = "030_expand_artifact_pack_tasks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "artifact_packs",
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "artifact_packs",
        sa.Column("approval_state", sa.String(length=32), nullable=False, server_default="draft"),
    )
    op.add_column(
        "artifact_packs",
        sa.Column("approval_notes", sa.Text(), nullable=True),
    )
    op.add_column(
        "artifact_packs",
        sa.Column("schedule_interval_seconds", sa.Integer(), nullable=True),
    )
    op.add_column(
        "artifact_packs",
        sa.Column("last_deployed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("artifact_packs", "last_deployed_at")
    op.drop_column("artifact_packs", "schedule_interval_seconds")
    op.drop_column("artifact_packs", "approval_notes")
    op.drop_column("artifact_packs", "approval_state")
    op.drop_column("artifact_packs", "enabled")
