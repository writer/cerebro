"""Add envelope encryption support

Revision ID: 004
Revises: 003
Create Date: 2024-01-04 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # This migration is now obsolete as the provider_credentials table
    # is created in migration 005 with encrypted_dek column included
    # Keeping this as no-op for migration history consistency
    pass


def downgrade() -> None:
    # No-op as the table creation/deletion is handled in migration 005
    pass
