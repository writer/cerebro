"""Add user lockout fields for rate limiting and security

Revision ID: 006
Revises: 005
Create Date: 2024-01-06 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add lockout fields to users table
    op.add_column(
        "users",
        sa.Column(
            "failed_login_attempts", sa.Integer(), nullable=False, server_default="0"
        ),
    )
    op.add_column(
        "users", sa.Column("last_failed_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "users", sa.Column("lockout_until", sa.DateTime(timezone=True), nullable=True)
    )

    # Add index for lockout tracking
    # Note: Partial index with NOW() not possible due to immutability requirements
    # Creating regular index instead - can be optimized later with a static date if needed
    op.create_index("ix_users_lockout_until", "users", ["lockout_until"])

    # Add index for failed attempt tracking
    op.create_index("ix_users_last_failed_at", "users", ["last_failed_at"])


def downgrade() -> None:
    # Drop indexes
    op.drop_index("ix_users_lockout_until")
    op.drop_index("ix_users_last_failed_at")

    # Drop columns
    op.drop_column("users", "lockout_until")
    op.drop_column("users", "last_failed_at")
    op.drop_column("users", "failed_login_attempts")
