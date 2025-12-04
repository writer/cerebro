"""Initial database schema

Revision ID: 001
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql" if bind else False

    # Enable extensions when supported (skip for SQLite compatibility in CI)
    if is_postgres:
        op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        op.execute("CREATE EXTENSION IF NOT EXISTS btree_gin")
    
    # Organizations
    op.create_table('orgs',
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.PrimaryKeyConstraint('org_id')
    )
    
    # Accounts
    op.create_table('accounts',
        sa.Column('account_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider', sa.String(), nullable=False),
        sa.Column('external_id', sa.String(), nullable=False),
        sa.Column('display_name', sa.String(), nullable=True),
        sa.CheckConstraint("provider IN ('github','google_workspace','aws','gcp')", name='accounts_provider_check'),
        sa.ForeignKeyConstraint(['org_id'], ['orgs.org_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('account_id'),
        sa.UniqueConstraint('org_id', 'provider', 'external_id')
    )
    
    # Principals
    op.create_table('principals',
        sa.Column('principal_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('account_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider', sa.String(), nullable=False),
        sa.Column('principal_type', sa.String(), nullable=False),
        sa.Column('external_id', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=True),
        sa.Column('display_name', sa.String(), nullable=True),
        sa.Column('is_human', sa.Boolean(), nullable=True),
        sa.CheckConstraint("principal_type IN ('user','group','service_account','app','role')", name='principals_type_check'),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.account_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('principal_id'),
        sa.UniqueConstraint('account_id', 'provider', 'external_id')
    )
    
    # Resources
    op.create_table('resources',
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('account_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider', sa.String(), nullable=False),
        sa.Column('resource_type', sa.String(), nullable=False),
        sa.Column('external_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=True),
        sa.Column('parent_external_id', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.account_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('resource_id'),
        sa.UniqueConstraint('account_id', 'provider', 'resource_type', 'external_id')
    )
    
    # Config Snapshots
    op.create_table('config_snapshots',
        sa.Column('snapshot_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('captured_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('config_sha', sa.LargeBinary(), nullable=False),
        sa.Column('normalized_config', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('collector_version', sa.String(), nullable=False),
        sa.ForeignKeyConstraint(['resource_id'], ['resources.resource_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('snapshot_id'),
        sa.UniqueConstraint('resource_id', 'config_sha')
    )
    op.create_index('ix_config_snapshots_resource_captured', 'config_snapshots', ['resource_id', 'captured_at'])
    op.create_index('ix_config_snapshots_normalized_config', 'config_snapshots', ['normalized_config'], postgresql_using='gin')
    
    # Policies
    op.create_table('policies',
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('framework', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.ForeignKeyConstraint(['org_id'], ['orgs.org_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_id')
    )
    
    # Rules
    op.create_table('rules',
        sa.Column('rule_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('provider', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('resource_types', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('expression_lang', sa.String(), nullable=False),
        sa.Column('expression', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('cwe', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('cis', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('nist_800_53', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('mitre_attack', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('version', sa.Integer(), nullable=False, default=1),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.CheckConstraint("expression_lang IN ('sql','rego','cel')", name='rules_expression_lang_check'),
        sa.CheckConstraint("severity IN ('critical','high','medium','low','info')", name='rules_severity_check'),
        sa.ForeignKeyConstraint(['policy_id'], ['policies.policy_id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('rule_id')
    )
    op.create_index('ix_rules_is_active', 'rules', ['is_active'])
    op.create_index('ix_rules_provider', 'rules', ['provider'], postgresql_using='gin')
    op.create_index('ix_rules_resource_types', 'rules', ['resource_types'], postgresql_using='gin')
    
    # IAM Edges
    op.create_table('iam_edges',
        sa.Column('edge_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('account_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider', sa.String(), nullable=False),
        sa.Column('principal_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('permission', sa.String(), nullable=False),
        sa.Column('via', sa.String(), nullable=True),
        sa.Column('effective_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_admin', sa.Boolean(), nullable=False, default=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.account_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['principal_id'], ['principals.principal_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['resource_id'], ['resources.resource_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('edge_id'),
        sa.UniqueConstraint('account_id', 'provider', 'principal_id', 'resource_id', 'permission', 'effective_at', 'via')
    )
    op.create_index('ix_iam_edges_principal', 'iam_edges', ['principal_id'])
    op.create_index('ix_iam_edges_resource', 'iam_edges', ['resource_id'])
    op.create_index('ix_iam_edges_is_admin', 'iam_edges', ['is_admin'])
    op.create_index('ix_iam_edges_effective_at', 'iam_edges', ['effective_at'])
    
    # Findings
    op.create_table('findings',
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('account_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider', sa.String(), nullable=False),
        sa.Column('rule_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('rule_version', sa.Integer(), nullable=False),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('principal_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('fingerprint', sa.String(), nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.CheckConstraint("status IN ('open','suppressed','accepted_risk','fixed')", name='findings_status_check'),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.account_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['org_id'], ['orgs.org_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['principal_id'], ['principals.principal_id']),
        sa.ForeignKeyConstraint(['resource_id'], ['resources.resource_id']),
        sa.ForeignKeyConstraint(['rule_id'], ['rules.rule_id']),
        sa.PrimaryKeyConstraint('finding_id'),
        sa.UniqueConstraint('org_id', 'fingerprint')
    )
    op.create_index('ix_findings_last_seen', 'findings', ['last_seen'])
    op.create_index('ix_findings_severity', 'findings', ['severity'])
    op.create_index('ix_findings_status', 'findings', ['status'])
    
    # Evidence Artifacts
    op.create_table('evidence_artifacts',
        sa.Column('artifact_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('captured_at', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.Column('kind', sa.String(), nullable=False),
        sa.Column('uri', sa.String(), nullable=True),
        sa.Column('blob', sa.LargeBinary(), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.finding_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('artifact_id')
    )
    
    # Audit Events
    op.create_table('audit_events',
        sa.Column('event_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('account_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider', sa.String(), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('actor_external_id', sa.String(), nullable=True),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('resource_external_id', sa.String(), nullable=True),
        sa.Column('raw', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.account_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('event_id')
    )
    op.create_index('ix_audit_events_occurred_at', 'audit_events', ['occurred_at'])
    op.create_index('ix_audit_events_provider_action', 'audit_events', ['provider', 'action'])
    op.create_index('ix_audit_events_raw', 'audit_events', ['raw'], postgresql_using='gin')
    
    # Suppressions
    op.create_table('suppressions',
        sa.Column('suppression_id', postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('rule_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('resource_pattern', sa.String(), nullable=True),
        sa.Column('principal_pattern', sa.String(), nullable=True),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True, default=sa.text('now()')),
        sa.ForeignKeyConstraint(['org_id'], ['orgs.org_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['rule_id'], ['rules.rule_id']),
        sa.PrimaryKeyConstraint('suppression_id')
    )


def downgrade() -> None:
    op.drop_table('suppressions')
    op.drop_table('audit_events')
    op.drop_table('evidence_artifacts')
    op.drop_table('findings')
    op.drop_table('iam_edges')
    op.drop_table('rules')
    op.drop_table('policies')
    op.drop_table('config_snapshots')
    op.drop_table('resources')
    op.drop_table('principals')
    op.drop_table('accounts')
    op.drop_table('orgs')
