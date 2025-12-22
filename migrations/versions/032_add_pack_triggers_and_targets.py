"""Add artifact pack triggers and targets

Revision ID: 032_add_pack_triggers_and_targets
Revises: 031_add_pack_management_fields
Create Date: 2025-10-29 15:30:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "032_add_pack_triggers_and_targets"
down_revision = "031_add_pack_management_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "artifact_pack_triggers",
        sa.Column(
            "trigger_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "pack_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("artifact_packs.pack_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("trigger_type", sa.String(length=64), nullable=False),
        sa.Column("match_value", sa.String(length=255), nullable=False),
        sa.Column("minimum_severity", sa.String(length=16), nullable=True),
        sa.Column("expires_after_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("timezone('utc', now())"),
        ),
    )

    op.create_index(
        "ix_artifact_pack_triggers_pack_id",
        "artifact_pack_triggers",
        ["pack_id"],
    )

    op.create_table(
        "artifact_pack_targets",
        sa.Column(
            "target_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "pack_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("artifact_packs.pack_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("host_id", sa.String(length=255), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("timezone('utc', now())"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fulfilled_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_index(
        "ix_artifact_pack_targets_pack_id",
        "artifact_pack_targets",
        ["pack_id"],
    )
    op.create_index(
        "ix_artifact_pack_targets_host_id",
        "artifact_pack_targets",
        ["host_id"],
    )
    op.create_index(
        "ix_artifact_pack_targets_pack_host",
        "artifact_pack_targets",
        ["pack_id", "host_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_artifact_pack_targets_pack_host", table_name="artifact_pack_targets"
    )
    op.drop_index(
        "ix_artifact_pack_targets_host_id", table_name="artifact_pack_targets"
    )
    op.drop_index(
        "ix_artifact_pack_targets_pack_id", table_name="artifact_pack_targets"
    )
    op.drop_index(
        "ix_artifact_pack_triggers_pack_id", table_name="artifact_pack_triggers"
    )
    op.drop_table("artifact_pack_targets")
    op.drop_table("artifact_pack_triggers")
