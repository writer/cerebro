"""Add provider credentials table

Revision ID: 005
Revises: 004
Create Date: 2024-01-05 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create provider_credentials table
    op.create_table('provider_credentials',
        sa.Column('credential_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('account_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider', sa.String(50), nullable=False),
        sa.Column('encrypted_credentials', sa.LargeBinary(), nullable=False),
        sa.Column('encrypted_dek', sa.LargeBinary(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, default=sa.text('now()')),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.account_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('credential_id'),
        sa.UniqueConstraint('account_id', 'provider', name='uq_provider_credentials_account_provider')
    )
    
    # Add indexes for performance
    op.create_index('ix_provider_credentials_account_id', 'provider_credentials', ['account_id'])
    op.create_index('ix_provider_credentials_provider', 'provider_credentials', ['provider'])
    op.create_index('ix_provider_credentials_is_active', 'provider_credentials', ['is_active'])
    op.create_index('ix_provider_credentials_expires_at', 'provider_credentials', ['expires_at'])


def downgrade() -> None:
    op.drop_table('provider_credentials')
