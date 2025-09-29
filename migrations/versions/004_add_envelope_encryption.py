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
    # Check if provider_credentials table exists first
    # (This will be created in migration 005 if it doesn't exist)
    from sqlalchemy import inspect
    conn = op.get_bind()
    inspector = inspect(conn)
    
    if 'provider_credentials' in inspector.get_table_names():
        # Add encrypted_dek column to provider_credentials
        op.add_column('provider_credentials', 
                      sa.Column('encrypted_dek', sa.LargeBinary(), nullable=True))
    else:
        # Table doesn't exist yet, skip for now - will be handled in migration 005
        pass
    
    # Note: In a real migration, you'd need to:
    # 1. Back-fill existing rows by generating DEKs from old SECRET_KEY
    # 2. Encrypt those DEKs with the chosen KMS
    # 3. Update encrypted_dek column for all existing rows
    # 4. Make encrypted_dek NOT NULL after back-fill


def downgrade() -> None:
    op.drop_column('provider_credentials', 'encrypted_dek')
