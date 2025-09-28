"""Add identity cluster tables

Revision ID: 003
Revises: 002
Create Date: 2024-01-03 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Identity clusters table
    op.create_table('identity_clusters',
        sa.Column('cluster_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('cluster_name', sa.String(length=255), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('stitching_method', sa.String(length=50), nullable=False),
        sa.Column('stitching_evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.ForeignKeyConstraint(['org_id'], ['orgs.org_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('cluster_id')
    )
    
    # Identity cluster members table
    op.create_table('identity_cluster_members',
        sa.Column('member_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('cluster_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('principal_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('added_at', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.Column('added_by', sa.String(length=50), nullable=True, default='system'),
        sa.ForeignKeyConstraint(['cluster_id'], ['identity_clusters.cluster_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['principal_id'], ['principals.principal_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('member_id')
    )
    
    # Identity stitching logs table
    op.create_table('identity_stitching_logs',
        sa.Column('log_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('operation', sa.String(length=50), nullable=False),
        sa.Column('cluster_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('principals_affected', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('confidence_threshold', sa.Float(), nullable=False),
        sa.Column('algorithm_version', sa.String(length=20), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(['cluster_id'], ['identity_clusters.cluster_id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['org_id'], ['orgs.org_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('log_id')
    )
    
    # Create indexes
    op.create_index('ix_identity_clusters_org_confidence', 'identity_clusters', ['org_id', 'confidence_score'])
    op.create_index('ix_identity_cluster_members_cluster', 'identity_cluster_members', ['cluster_id'])
    op.create_index('ix_identity_cluster_members_principal', 'identity_cluster_members', ['principal_id'])
    op.create_index('ix_identity_stitching_logs_timestamp', 'identity_stitching_logs', ['timestamp'])


def downgrade() -> None:
    op.drop_index('ix_identity_stitching_logs_timestamp', table_name='identity_stitching_logs')
    op.drop_index('ix_identity_cluster_members_principal', table_name='identity_cluster_members')
    op.drop_index('ix_identity_cluster_members_cluster', table_name='identity_cluster_members')
    op.drop_index('ix_identity_clusters_org_confidence', table_name='identity_clusters')
    op.drop_table('identity_stitching_logs')
    op.drop_table('identity_cluster_members')
    op.drop_table('identity_clusters')
