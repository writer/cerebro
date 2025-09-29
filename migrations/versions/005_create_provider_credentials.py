"""Create provider_credentials table

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
        sa.Column('credential_id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('account_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider_type', sa.String(50), nullable=False),
        sa.Column('credential_name', sa.String(255), nullable=False),
        sa.Column('encrypted_credentials', sa.LargeBinary(), nullable=False),
        sa.Column('encrypted_dek', sa.LargeBinary(), nullable=True),  # Added by migration 004
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True),
        
        # Foreign keys
        sa.ForeignKeyConstraint(['account_id'], ['accounts.account_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.user_id'], ondelete='SET NULL'),
        
        # Unique constraint 
        sa.UniqueConstraint('account_id', 'provider_type', 'credential_name'),
        
        # Indexes
        sa.Index('ix_provider_credentials_account_provider', 'account_id', 'provider_type'),
        sa.Index('ix_provider_credentials_active', 'is_active'),
    )


def downgrade() -> None:
    op.drop_table('provider_credentials')
