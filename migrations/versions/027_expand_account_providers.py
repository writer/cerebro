"""Allow runtime and endpoint account providers

Revision ID: 027_expand_account_providers
Revises: 026_add_frontend_observation_events
Create Date: 2025-10-28 00:00:00.000000

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "027_expand_account_providers"
down_revision = "026_add_frontend_observation_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("accounts_provider_check", "accounts", type_="check")
    op.create_check_constraint(
        "accounts_provider_check",
        "accounts",
        "provider IN ('github','google_workspace','aws','gcp','runtime','endpoint')",
    )


def downgrade() -> None:
    op.drop_constraint("accounts_provider_check", "accounts", type_="check")
    op.create_check_constraint(
        "accounts_provider_check",
        "accounts",
        "provider IN ('github','google_workspace','aws','gcp')",
    )
