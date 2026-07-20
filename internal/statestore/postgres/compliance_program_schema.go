package postgres

import "context"

var ensureComplianceProgramStatements = []string{
	`CREATE TABLE IF NOT EXISTS grc_programs (
  tenant_id TEXT NOT NULL,
  program_id TEXT NOT NULL,
  name TEXT NOT NULL,
  owner_team TEXT NOT NULL,
  risk_owner TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  scope_id TEXT NOT NULL DEFAULT '',
  current_scope_revision_id TEXT NOT NULL DEFAULT '',
  aggregate_version BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, program_id)
)`,
	`CREATE INDEX IF NOT EXISTS grc_programs_tenant_status_updated_idx ON grc_programs (tenant_id, status, updated_at DESC, program_id)`,
	`CREATE TABLE IF NOT EXISTS grc_program_scope_revisions (
  tenant_id TEXT NOT NULL,
  program_id TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  revision_version BIGINT NOT NULL,
  state TEXT NOT NULL,
  content_digest TEXT NOT NULL,
  predecessor_id TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  change_summary TEXT NOT NULL,
  specification_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, program_id, revision_id),
  UNIQUE (tenant_id, program_id, scope_id, revision_version),
  FOREIGN KEY (tenant_id, program_id) REFERENCES grc_programs (tenant_id, program_id)
)`,
	`CREATE INDEX IF NOT EXISTS grc_program_scope_revisions_tenant_scope_version_idx ON grc_program_scope_revisions (tenant_id, program_id, scope_id, revision_version DESC)`,
	`CREATE TABLE IF NOT EXISTS grc_program_scope_selectors (
  tenant_id TEXT NOT NULL,
  program_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  selector_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  mode TEXT NOT NULL,
  resolution_state TEXT NOT NULL,
  unresolved_reason TEXT NOT NULL DEFAULT '',
  selector_json JSONB NOT NULL,
  PRIMARY KEY (tenant_id, program_id, revision_id, selector_id),
  FOREIGN KEY (tenant_id, program_id, revision_id) REFERENCES grc_program_scope_revisions (tenant_id, program_id, revision_id)
)`,
	`ALTER TABLE grc_program_scope_selectors ADD COLUMN IF NOT EXISTS resolution_state TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE grc_program_scope_selectors ADD COLUMN IF NOT EXISTS unresolved_reason TEXT NOT NULL DEFAULT ''`,
	`CREATE TABLE IF NOT EXISTS grc_program_scope_subjects (
  tenant_id TEXT NOT NULL,
  program_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, program_id, revision_id, subject_type, subject_id),
  FOREIGN KEY (tenant_id, program_id, revision_id) REFERENCES grc_program_scope_revisions (tenant_id, program_id, revision_id)
)`,
	`CREATE INDEX IF NOT EXISTS grc_program_scope_subjects_tenant_subject_idx ON grc_program_scope_subjects (tenant_id, subject_type, subject_id, program_id)`,
	`CREATE TABLE IF NOT EXISTS grc_control_implementations (
  tenant_id TEXT NOT NULL,
  program_id TEXT NOT NULL,
  implementation_id TEXT NOT NULL,
  current_revision_id TEXT NOT NULL,
  aggregate_version BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, program_id, implementation_id),
  FOREIGN KEY (tenant_id, program_id) REFERENCES grc_programs (tenant_id, program_id)
)`,
	`CREATE TABLE IF NOT EXISTS grc_control_implementation_revisions (
  tenant_id TEXT NOT NULL,
  program_id TEXT NOT NULL,
  implementation_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  revision_version BIGINT NOT NULL,
  scope_revision_id TEXT NOT NULL,
  content_digest TEXT NOT NULL,
  predecessor_id TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  change_summary TEXT NOT NULL,
  specification_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, program_id, implementation_id, revision_id),
  UNIQUE (tenant_id, program_id, implementation_id, revision_version),
  FOREIGN KEY (tenant_id, program_id, implementation_id) REFERENCES grc_control_implementations (tenant_id, program_id, implementation_id),
  FOREIGN KEY (tenant_id, program_id, scope_revision_id) REFERENCES grc_program_scope_revisions (tenant_id, program_id, revision_id)
)`,
	`CREATE INDEX IF NOT EXISTS grc_control_implementation_revisions_scope_idx ON grc_control_implementation_revisions (tenant_id, program_id, scope_revision_id, implementation_id)`,
	`CREATE TABLE IF NOT EXISTS grc_control_mapping_revisions (
  tenant_id TEXT NOT NULL,
  program_id TEXT NOT NULL,
  implementation_id TEXT NOT NULL,
  implementation_revision_id TEXT NOT NULL,
  mapping_id TEXT NOT NULL,
  mapping_revision_id TEXT NOT NULL,
  relationship TEXT NOT NULL,
  source_revision_id TEXT NOT NULL,
  target_revision_id TEXT NOT NULL,
  mapping_json JSONB NOT NULL,
  PRIMARY KEY (tenant_id, program_id, implementation_id, implementation_revision_id, mapping_id, mapping_revision_id),
  FOREIGN KEY (tenant_id, program_id, implementation_id, implementation_revision_id) REFERENCES grc_control_implementation_revisions (tenant_id, program_id, implementation_id, revision_id)
)`,
	`CREATE INDEX IF NOT EXISTS grc_control_mapping_revisions_target_idx ON grc_control_mapping_revisions (tenant_id, target_revision_id, relationship)`,
	`CREATE TABLE IF NOT EXISTS grc_compliance_event_application_receipts (
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_digest TEXT NOT NULL,
  aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  revision_id TEXT NOT NULL DEFAULT '',
  aggregate_version BIGINT NOT NULL,
  operation TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, event_id)
)`,
	`ALTER TABLE grc_compliance_event_application_receipts ADD COLUMN IF NOT EXISTS event_digest TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS grc_compliance_event_application_receipts_aggregate_idx ON grc_compliance_event_application_receipts (tenant_id, aggregate_type, aggregate_id, aggregate_version)`,
}

func (s *Store) ensureComplianceProgramTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.complianceProgram, "grc compliance program", ensureComplianceProgramStatements)
}
