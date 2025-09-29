"""Add refresh tokens table for JWT token rotation

Revision ID: 009
Revises: 008
Create Date: 2024-01-09 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create refresh tokens table
    op.create_table('refresh_tokens',
        sa.Column('token_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_revoked', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, default=sa.text('now()')),
        sa.Column('last_used', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('token_id'),
        sa.UniqueConstraint('token_hash', name='uq_refresh_tokens_token_hash')
    )
    
    # Add indexes for performance
    op.create_index('ix_refresh_tokens_user_id', 'refresh_tokens', ['user_id'])
    op.create_index('ix_refresh_tokens_expires_at', 'refresh_tokens', ['expires_at'])
    op.create_index('ix_refresh_tokens_is_revoked', 'refresh_tokens', ['is_revoked'])
    
    # Partial index for active tokens
    op.execute("""
        CREATE INDEX CONCURRENTLY ix_refresh_tokens_active
        ON refresh_tokens (user_id, expires_at)
        WHERE is_revoked = false
    """)


def downgrade() -> None:
    op.drop_table('refresh_tokens')
