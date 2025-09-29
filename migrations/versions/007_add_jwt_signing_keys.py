"""Add JWT signing keys table for RS256 key rotation

Revision ID: 007
Revises: 006  
Create Date: 2024-01-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create JWT signing keys table
    op.create_table('jwt_signing_keys',
        sa.Column('key_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('kid', sa.String(50), nullable=False),
        sa.Column('encrypted_private_key', sa.LargeBinary(), nullable=False),
        sa.Column('encrypted_dek', sa.LargeBinary(), nullable=False),
        sa.Column('public_key_pem', sa.Text(), nullable=False),
        sa.Column('algorithm', sa.String(10), nullable=False, default='RS256'),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, default=sa.text('now()')),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('key_id'),
        sa.UniqueConstraint('kid', name='uq_jwt_signing_keys_kid')
    )
    
    # Add indexes for performance
    op.create_index('ix_jwt_signing_keys_is_active', 'jwt_signing_keys', ['is_active'])
    op.create_index('ix_jwt_signing_keys_expires_at', 'jwt_signing_keys', ['expires_at'])
    op.create_index('ix_jwt_signing_keys_created_at', 'jwt_signing_keys', ['created_at'])
    
    # Partial index for active keys lookup
    op.execute("""
        CREATE INDEX CONCURRENTLY ix_jwt_signing_keys_active_lookup
        ON jwt_signing_keys (created_at DESC, expires_at) 
        WHERE is_active = true
    """)


def downgrade() -> None:
    op.drop_table('jwt_signing_keys')
