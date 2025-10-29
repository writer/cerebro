"""Expand artifact pack tasks metadata

Revision ID: 030_expand_artifact_pack_tasks
Revises: 029_add_artifact_packs
Create Date: 2025-10-29 13:30:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "030_expand_artifact_pack_tasks"
down_revision = "029_add_artifact_packs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "artifact_pack_tasks",
        sa.Column("discovery", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'[]'::jsonb")),
    )
    op.add_column(
        "artifact_pack_tasks",
        sa.Column("parameters", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'[]'::jsonb")),
    )
    op.add_column(
        "artifact_pack_tasks",
        sa.Column("parameter_values", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column(
        "artifact_pack_tasks",
        sa.Column("resources", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column(
        "artifact_pack_tasks",
        sa.Column("tools", postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default=sa.text("'[]'::jsonb")),
    )

    op.execute("UPDATE artifact_pack_tasks SET discovery = '[]'::jsonb WHERE discovery IS NULL")
    op.execute("UPDATE artifact_pack_tasks SET parameters = '[]'::jsonb WHERE parameters IS NULL")
    op.execute("UPDATE artifact_pack_tasks SET parameter_values = '{}'::jsonb WHERE parameter_values IS NULL")
    op.execute("UPDATE artifact_pack_tasks SET resources = '{}'::jsonb WHERE resources IS NULL")
    op.execute("UPDATE artifact_pack_tasks SET tools = '[]'::jsonb WHERE tools IS NULL")


def downgrade() -> None:
    op.drop_column("artifact_pack_tasks", "tools")
    op.drop_column("artifact_pack_tasks", "resources")
    op.drop_column("artifact_pack_tasks", "parameter_values")
    op.drop_column("artifact_pack_tasks", "parameters")
    op.drop_column("artifact_pack_tasks", "discovery")
