package postgres

import "context"

var ensureAssessmentSamplingStatements = []string{
	`CREATE TABLE IF NOT EXISTS compliance_assessment_activities (
  tenant_id TEXT NOT NULL, activity_id TEXT NOT NULL, run_id TEXT NOT NULL,
  aggregate_version BIGINT NOT NULL, execution_state TEXT NOT NULL,
  activity_json JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, activity_id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_assessment_activities_run_state_idx ON compliance_assessment_activities (tenant_id, run_id, execution_state, activity_id)`,
	`CREATE TABLE IF NOT EXISTS compliance_assessment_activity_revisions (
  tenant_id TEXT NOT NULL, activity_id TEXT NOT NULL, aggregate_version BIGINT NOT NULL,
  execution_state TEXT NOT NULL, content_digest TEXT NOT NULL,
  activity_json JSONB NOT NULL, recorded_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, activity_id, aggregate_version),
  FOREIGN KEY (tenant_id, activity_id) REFERENCES compliance_assessment_activities (tenant_id, activity_id)
)`,
	`CREATE TABLE IF NOT EXISTS compliance_assessment_populations (
  tenant_id TEXT NOT NULL, population_id TEXT NOT NULL, run_id TEXT NOT NULL,
  objective_id TEXT NOT NULL, expected_count BIGINT NOT NULL, observed_count BIGINT NOT NULL,
  complete BOOLEAN NOT NULL, content_digest TEXT NOT NULL, snapshot_json JSONB NOT NULL,
  source_watermark TIMESTAMPTZ NOT NULL, recorded_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, population_id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_assessment_populations_run_objective_idx ON compliance_assessment_populations (tenant_id, run_id, objective_id, population_id)`,
	`CREATE TABLE IF NOT EXISTS compliance_assessment_population_subjects (
  tenant_id TEXT NOT NULL, population_id TEXT NOT NULL, subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, population_id, subject_type, subject_id),
  FOREIGN KEY (tenant_id, population_id) REFERENCES compliance_assessment_populations (tenant_id, population_id)
)`,
	`CREATE TABLE IF NOT EXISTS compliance_assessment_samples (
  tenant_id TEXT NOT NULL, sample_id TEXT NOT NULL, population_id TEXT NOT NULL,
  algorithm TEXT NOT NULL, seed TEXT NOT NULL, requested_size INTEGER NOT NULL,
  population_digest TEXT NOT NULL, selection_digest TEXT NOT NULL,
  selection_json JSONB NOT NULL, recorded_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, sample_id),
  FOREIGN KEY (tenant_id, population_id) REFERENCES compliance_assessment_populations (tenant_id, population_id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_assessment_samples_population_idx ON compliance_assessment_samples (tenant_id, population_id, sample_id)`,
	`CREATE TABLE IF NOT EXISTS compliance_assessment_sample_subjects (
  tenant_id TEXT NOT NULL, sample_id TEXT NOT NULL, subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, sample_id, subject_type, subject_id),
  UNIQUE (tenant_id, sample_id, ordinal),
  FOREIGN KEY (tenant_id, sample_id) REFERENCES compliance_assessment_samples (tenant_id, sample_id)
)`,
	`CREATE TABLE IF NOT EXISTS compliance_sampling_event_application_receipts (
  tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, event_digest TEXT NOT NULL,
  aggregate_type TEXT NOT NULL, aggregate_id TEXT NOT NULL, aggregate_version BIGINT NOT NULL,
  operation TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, event_id)
)`,
	`ALTER TABLE compliance_sampling_event_application_receipts ADD COLUMN IF NOT EXISTS event_digest TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS compliance_sampling_event_receipts_aggregate_idx ON compliance_sampling_event_application_receipts (tenant_id, aggregate_type, aggregate_id, aggregate_version)`,
}

func (s *Store) ensureAssessmentSamplingTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.assessmentSampling, "compliance assessment sampling", ensureAssessmentSamplingStatements)
}
