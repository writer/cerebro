"""Add user management tables

Revision ID: 002
Revises: 001
Create Date: 2024-01-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Users table
    op.create_table('users',
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_admin', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('user_id'),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email')
    )
    
    # Scopes table
    op.create_table('scopes',
        sa.Column('scope_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.PrimaryKeyConstraint('scope_id'),
        sa.UniqueConstraint('name')
    )
    
    # User scopes many-to-many
    op.create_table('user_scopes',
        sa.Column('user_scope_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scope_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('granted_at', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.Column('granted_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(['granted_by'], ['users.user_id']),
        sa.ForeignKeyConstraint(['scope_id'], ['scopes.scope_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('user_scope_id')
    )
    
    # User audit logs
    op.create_table('user_audit_logs',
        sa.Column('log_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource_type', sa.String(length=50), nullable=True),
        sa.Column('resource_id', sa.String(length=255), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.Column('success', sa.Boolean(), nullable=True, default=True),
        sa.Column('error_message', sa.String(length=1000), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('log_id')
    )
    
    # Create indexes
    op.create_index('ix_user_audit_logs_timestamp', 'user_audit_logs', ['timestamp'])
    op.create_index('ix_user_audit_logs_action', 'user_audit_logs', ['action'])
    op.create_index('ix_user_audit_logs_user_id', 'user_audit_logs', ['user_id'])


def downgrade() -> None:
    op.drop_index('ix_user_audit_logs_user_id', table_name='user_audit_logs')
    op.drop_index('ix_user_audit_logs_action', table_name='user_audit_logs')
    op.drop_index('ix_user_audit_logs_timestamp', table_name='user_audit_logs')
    op.drop_table('user_audit_logs')
    op.drop_table('user_scopes')
    op.drop_table('scopes')
    op.drop_table('users')
