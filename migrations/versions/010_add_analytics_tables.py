"""Add analytics and time series tables

Revision ID: 010
Revises: 009
Create Date: 2024-01-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '010'
down_revision = '009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Security Metric Snapshots table for time series data
    op.create_table('security_metric_snapshots',
        sa.Column('snapshot_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('metric_type', sa.String(100), nullable=False),
        sa.Column('metric_category', sa.String(50), nullable=False),
        sa.Column('captured_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('aggregation_period', sa.String(20), nullable=False),
        sa.Column('value', sa.Float(), nullable=False),
        sa.Column('previous_value', sa.Float(), nullable=True),
        sa.Column('breakdown_data', postgresql.JSONB(), nullable=True),
        sa.Column('metadata', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, default=sa.text('now()')),
        sa.ForeignKeyConstraint(['org_id'], ['orgs.org_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('snapshot_id')
    )
    
    # Add indexes for time series queries
    op.create_index('ix_security_metric_snapshots_org_id', 'security_metric_snapshots', ['org_id'])
    op.create_index('ix_security_metric_snapshots_metric_type', 'security_metric_snapshots', ['metric_type'])
    op.create_index('ix_security_metric_snapshots_captured_at', 'security_metric_snapshots', ['captured_at'])
    op.create_index('ix_security_metric_snapshots_aggregation_period', 'security_metric_snapshots', ['aggregation_period'])
    
    # Composite index for time series queries
    op.create_index('ix_security_metric_snapshots_org_metric_time', 'security_metric_snapshots', 
                   ['org_id', 'metric_type', 'captured_at'])
    
    # Partial index for recent data
    op.execute("""
        CREATE INDEX CONCURRENTLY ix_security_metric_snapshots_recent
        ON security_metric_snapshots (org_id, metric_type, captured_at DESC)
        WHERE captured_at >= NOW() - INTERVAL '90 days'
    """)


def downgrade() -> None:
    op.drop_table('security_metric_snapshots')
