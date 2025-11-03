"""Add Serval integration configuration table."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "035_add_serval_integration"
down_revision = "034_add_integration_issue_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "serval_integrations",
        sa.Column(
            "integration_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column(
            "api_base_url",
            sa.String(length=255),
            nullable=False,
            server_default="https://public.api.serval.com",
        ),
        sa.Column("team_id", sa.String(length=255), nullable=False),
        sa.Column("default_status_id", sa.String(length=255), nullable=True),
        sa.Column("default_priority_id", sa.String(length=255), nullable=True),
        sa.Column("default_created_by_user_id", sa.String(length=255), nullable=False),
        sa.Column("default_requester_user_id", sa.String(length=255), nullable=True),
        sa.Column("default_assigned_user_id", sa.String(length=255), nullable=True),
        sa.Column(
            "settings",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("encrypted_client_id", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_client_id_dek", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_client_secret", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_client_secret_dek", sa.LargeBinary(), nullable=False),
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
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
    )


def downgrade() -> None:
    op.drop_table("serval_integrations")
