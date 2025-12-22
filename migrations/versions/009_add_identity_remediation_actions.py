"""Add identity remediation actions table

Revision ID: 009a_identity_remediation_actions
Revises: 009
Create Date: 2025-10-27 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "009a_identity_remediation_actions"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "identity_remediation_actions",
        sa.Column(
            "action_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("principal_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("summary", sa.String(length=255), nullable=False),
        sa.Column("recommended_action", sa.Text(), nullable=False),
        sa.Column(
            "priority", sa.String(length=16), nullable=False, server_default="medium"
        ),
        sa.Column(
            "status", sa.String(length=16), nullable=False, server_default="pending"
        ),
        sa.Column(
            "evidence",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "notes",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["principal_id"], ["principals.principal_id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["accepted_by"], ["users.user_id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["completed_by"], ["users.user_id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["created_by"], ["users.user_id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["updated_by"], ["users.user_id"], ondelete="SET NULL"),
        sa.CheckConstraint(
            "priority IN ('low','medium','high')", name="ck_remediation_priority"
        ),
        sa.CheckConstraint(
            "status IN ('pending','accepted','completed')", name="ck_remediation_status"
        ),
        sa.UniqueConstraint(
            "org_id",
            "principal_id",
            "recommended_action",
            name="uq_remediation_rec",
        ),
    )

    op.create_index(
        "ix_remediation_actions_org",
        "identity_remediation_actions",
        ["org_id"],
    )
    op.create_index(
        "ix_remediation_actions_principal",
        "identity_remediation_actions",
        ["principal_id"],
    )
    op.create_index(
        "ix_remediation_actions_status",
        "identity_remediation_actions",
        ["status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_remediation_actions_status", table_name="identity_remediation_actions"
    )
    op.drop_index(
        "ix_remediation_actions_principal", table_name="identity_remediation_actions"
    )
    op.drop_index(
        "ix_remediation_actions_org", table_name="identity_remediation_actions"
    )
    op.drop_table("identity_remediation_actions")
