package postgres

import "context"

var ensureAuditStateStatements = []string{
	`CREATE TABLE IF NOT EXISTS grc_audit_engagements (
  tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, aggregate_version BIGINT NOT NULL,
  current_revision BIGINT NOT NULL, current_revision_id TEXT NOT NULL, status TEXT NOT NULL,
  state_json JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, engagement_id)
)`,
	`CREATE TABLE IF NOT EXISTS grc_audit_engagement_revisions (
  tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, revision_id TEXT NOT NULL,
  revision BIGINT NOT NULL, predecessor_id TEXT NOT NULL DEFAULT '', revision_hash TEXT NOT NULL,
  revision_json JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, engagement_id, revision_id),
  UNIQUE (tenant_id, engagement_id, revision),
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES grc_audit_engagements (tenant_id, engagement_id)
)`,
	`CREATE TABLE IF NOT EXISTS grc_audit_participants (
  tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, participant_id TEXT NOT NULL,
  principal_id TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL, version BIGINT NOT NULL,
  participant_json JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, engagement_id, participant_id),
  UNIQUE (tenant_id, engagement_id, principal_id),
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES grc_audit_engagements (tenant_id, engagement_id)
)`,
	`CREATE INDEX IF NOT EXISTS grc_audit_participants_principal_idx ON grc_audit_participants (tenant_id, principal_id, status, engagement_id)`,
	`CREATE TABLE IF NOT EXISTS grc_audit_evidence_requests (
  tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, request_id TEXT NOT NULL,
  aggregate_version BIGINT NOT NULL, current_revision BIGINT NOT NULL,
  current_revision_id TEXT NOT NULL, status TEXT NOT NULL, state_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, engagement_id, request_id),
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES grc_audit_engagements (tenant_id, engagement_id)
)`,
	`CREATE TABLE IF NOT EXISTS grc_audit_evidence_request_revisions (
  tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, request_id TEXT NOT NULL,
  revision_id TEXT NOT NULL, revision BIGINT NOT NULL, predecessor_id TEXT NOT NULL DEFAULT '',
  revision_hash TEXT NOT NULL, revision_json JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, engagement_id, request_id, revision_id),
  UNIQUE (tenant_id, engagement_id, request_id, revision),
  FOREIGN KEY (tenant_id, engagement_id, request_id) REFERENCES grc_audit_evidence_requests (tenant_id, engagement_id, request_id)
)`,
	`CREATE TABLE IF NOT EXISTS grc_audit_evidence_submissions (
  tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, request_id TEXT NOT NULL,
  submission_id TEXT NOT NULL, request_version BIGINT NOT NULL, submission_hash TEXT NOT NULL,
  submission_json JSONB NOT NULL, submitted_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, engagement_id, request_id, submission_id),
  FOREIGN KEY (tenant_id, engagement_id, request_id) REFERENCES grc_audit_evidence_requests (tenant_id, engagement_id, request_id)
)`,
	`CREATE TABLE IF NOT EXISTS grc_audit_sample_revisions (
  tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, request_id TEXT NOT NULL,
  population_id TEXT NOT NULL, sample_revision_id TEXT NOT NULL, revision BIGINT NOT NULL,
  predecessor_id TEXT NOT NULL DEFAULT '', revision_hash TEXT NOT NULL,
  sample_json JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, engagement_id, request_id, population_id, sample_revision_id),
  UNIQUE (tenant_id, engagement_id, request_id, population_id, revision),
  FOREIGN KEY (tenant_id, engagement_id, request_id) REFERENCES grc_audit_evidence_requests (tenant_id, engagement_id, request_id)
)`,
	`CREATE TABLE IF NOT EXISTS grc_audit_packages (
  tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, package_id TEXT NOT NULL,
  current_revision BIGINT NOT NULL, current_digest TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, engagement_id, package_id),
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES grc_audit_engagements (tenant_id, engagement_id)
)`,
	`CREATE TABLE IF NOT EXISTS grc_audit_package_manifests (
  tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, package_id TEXT NOT NULL,
  revision BIGINT NOT NULL, semantic_digest TEXT NOT NULL, predecessor_digest TEXT NOT NULL DEFAULT '',
  manifest_json JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, engagement_id, package_id, revision),
  UNIQUE (tenant_id, package_id, semantic_digest),
  FOREIGN KEY (tenant_id, engagement_id, package_id) REFERENCES grc_audit_packages (tenant_id, engagement_id, package_id)
)`,
	`CREATE TABLE IF NOT EXISTS grc_audit_package_manifest_entries (
  tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, package_id TEXT NOT NULL,
  package_revision BIGINT NOT NULL, entry_path TEXT NOT NULL, logical_type TEXT NOT NULL,
  stable_id TEXT NOT NULL, revision_id TEXT NOT NULL, redaction_action TEXT NOT NULL,
  entry_json JSONB NOT NULL,
  PRIMARY KEY (tenant_id, engagement_id, package_id, package_revision, entry_path),
  FOREIGN KEY (tenant_id, engagement_id, package_id, package_revision) REFERENCES grc_audit_package_manifests (tenant_id, engagement_id, package_id, revision)
)`,
	`CREATE TABLE IF NOT EXISTS grc_audit_capability_state (
  tenant_id TEXT NOT NULL, capability_id TEXT NOT NULL, kind TEXT NOT NULL,
  enabled BOOLEAN NOT NULL, version BIGINT NOT NULL, state_json JSONB NOT NULL,
  updated_by TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, capability_id)
)`,
	`CREATE TABLE IF NOT EXISTS grc_audit_access_grants (
  tenant_id TEXT NOT NULL, engagement_id TEXT NOT NULL, grant_id TEXT NOT NULL,
  principal_id TEXT NOT NULL, permission TEXT NOT NULL, status TEXT NOT NULL,
  version BIGINT NOT NULL, grant_json JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, engagement_id, grant_id),
  FOREIGN KEY (tenant_id, engagement_id) REFERENCES grc_audit_engagements (tenant_id, engagement_id)
)`,
	`CREATE INDEX IF NOT EXISTS grc_audit_access_grants_principal_idx ON grc_audit_access_grants (tenant_id, principal_id, status, engagement_id)`,
	`CREATE TABLE IF NOT EXISTS grc_audit_event_application_receipts (
  tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, event_digest TEXT NOT NULL,
  aggregate_type TEXT NOT NULL, aggregate_id TEXT NOT NULL, aggregate_version BIGINT NOT NULL,
  operation TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, event_id)
)`,
	`ALTER TABLE grc_audit_event_application_receipts ADD COLUMN IF NOT EXISTS event_digest TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS grc_audit_event_receipts_aggregate_idx ON grc_audit_event_application_receipts (tenant_id, aggregate_type, aggregate_id, aggregate_version)`,
}

func (s *Store) ensureAuditStateTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.auditState, "grc audit state", ensureAuditStateStatements)
}
