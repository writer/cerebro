"""Add frontend observation telemetry table

Revision ID: 026_add_frontend_observation_events
Revises: 025_add_self_play_matches
Create Date: 2024-10-22 12:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "026_add_frontend_observation_events"
down_revision = "025_add_self_play_matches"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    uuid_type = sa.String(36) if is_sqlite else postgresql.UUID(as_uuid=True)
    json_type = sa.JSON() if is_sqlite else postgresql.JSONB()
    metadata_default = sa.text("'{}'") if is_sqlite else sa.text("'{}'::jsonb")
    context_default = sa.text("'{}'") if is_sqlite else sa.text("'{}'::jsonb")

    event_id_column = sa.Column(
        "event_id",
        uuid_type,
        primary_key=True,
        nullable=False,
        server_default=None if is_sqlite else sa.text("gen_random_uuid()"),
    )

    op.create_table(
        "frontend_observation_events",
        event_id_column,
        sa.Column("org_id", uuid_type, nullable=False),
        sa.Column("user_id", uuid_type, nullable=True),
        sa.Column("agent_session_id", uuid_type, nullable=True),
        sa.Column("event_type", sa.String(length=150), nullable=False),
        sa.Column("component", sa.String(length=200), nullable=True),
        sa.Column("context_data", json_type, nullable=False, server_default=context_default),
        sa.Column("metadata", json_type, nullable=False, server_default=metadata_default),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.user_id"], ondelete="SET NULL"),
    )

    op.create_index(
        "ix_frontend_observation_events_org_id",
        "frontend_observation_events",
        ["org_id"],
    )
    op.create_index(
        "ix_frontend_observation_events_user_id",
        "frontend_observation_events",
        ["user_id"],
    )
    op.create_index(
        "ix_frontend_observation_events_agent_session_id",
        "frontend_observation_events",
        ["agent_session_id"],
    )
    op.create_index(
        "ix_frontend_observation_events_event_type",
        "frontend_observation_events",
        ["event_type"],
    )
    op.create_index(
        "ix_frontend_observation_events_occurred_at",
        "frontend_observation_events",
        ["occurred_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_frontend_observation_events_occurred_at",
        table_name="frontend_observation_events",
    )
    op.drop_index(
        "ix_frontend_observation_events_event_type",
        table_name="frontend_observation_events",
    )
    op.drop_index(
        "ix_frontend_observation_events_agent_session_id",
        table_name="frontend_observation_events",
    )
    op.drop_index(
        "ix_frontend_observation_events_user_id",
        table_name="frontend_observation_events",
    )
    op.drop_index(
        "ix_frontend_observation_events_org_id",
        table_name="frontend_observation_events",
    )
    op.drop_table("frontend_observation_events")
