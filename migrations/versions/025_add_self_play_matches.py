"""add self play matches table

Revision ID: 025_add_self_play_matches
Revises: 024_add_review_enhancements
Create Date: 2024-10-21

Introduce persistence for self-play orchestration results.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "025_add_self_play_matches"
down_revision = "024_add_review_enhancements"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "self_play_matches",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("scenario_id", sa.String(length=255), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("turns", sa.Integer(), nullable=False),
        sa.Column("tool_calls", sa.Integer(), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("fail_reason", sa.String(length=255), nullable=True),
        sa.Column(
            "transcript",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_self_play_matches_scenario_id", "self_play_matches", ["scenario_id"]
    )
    op.create_index("ix_self_play_matches_org_id", "self_play_matches", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_self_play_matches_org_id", table_name="self_play_matches")
    op.drop_index("ix_self_play_matches_scenario_id", table_name="self_play_matches")
    op.drop_table("self_play_matches")
