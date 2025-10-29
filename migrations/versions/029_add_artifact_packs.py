"""Add artifact packs tables

Revision ID: 029_add_artifact_packs
Revises: 028_add_host_telemetry_events
Create Date: 2025-10-29 12:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "029_add_artifact_packs"
down_revision = "028_add_host_telemetry_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "artifact_packs",
        sa.Column("pack_id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("orgs.org_id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("selectors", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_index("ix_artifact_packs_org_id", "artifact_packs", ["org_id"])

    op.create_table(
        "artifact_pack_tasks",
        sa.Column("task_id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("pack_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("artifact_packs.pack_id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("collector", sa.String(length=128), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=True),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_index("ix_artifact_pack_tasks_pack_id", "artifact_pack_tasks", ["pack_id"])


def downgrade() -> None:
    op.drop_index("ix_artifact_pack_tasks_pack_id", table_name="artifact_pack_tasks")
    op.drop_table("artifact_pack_tasks")
    op.drop_index("ix_artifact_packs_org_id", table_name="artifact_packs")
    op.drop_table("artifact_packs")
