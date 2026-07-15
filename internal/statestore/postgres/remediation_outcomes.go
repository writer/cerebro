package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

var ensureRemediationOutcomeStatements = []string{
	`CREATE TABLE IF NOT EXISTS platform_remediation_outcomes (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  episode_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  finding_fingerprint TEXT NOT NULL,
  finding_revision TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  decision_id TEXT NOT NULL DEFAULT '',
  proposal_id TEXT NOT NULL DEFAULT '',
  action_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  action_version TEXT NOT NULL,
  execution_id TEXT NOT NULL,
  provider_capability_version TEXT NOT NULL,
  verification_id TEXT NOT NULL DEFAULT '',
  evaluation_run_id TEXT NOT NULL DEFAULT '',
  verification_state TEXT NOT NULL,
  censored_reason TEXT NOT NULL DEFAULT '',
  source_health TEXT NOT NULL,
  source_runtime_id TEXT NOT NULL,
  provider_succeeded BOOLEAN NOT NULL DEFAULT FALSE,
  verified_resolution BOOLEAN NOT NULL DEFAULT FALSE,
  action_completed_at TIMESTAMPTZ,
  verified_at TIMESTAMPTZ,
  observed_at TIMESTAMPTZ NOT NULL,
  verification_latency_ns BIGINT NOT NULL DEFAULT 0,
  digest TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, digest),
  CHECK (NOT verified_resolution OR verification_state = 'verified_closed'),
  CHECK (verification_state <> 'censored' OR censored_reason <> '')
)`,
	`CREATE INDEX IF NOT EXISTS platform_remediation_outcomes_finding_idx ON platform_remediation_outcomes (tenant_id, finding_id, observed_at DESC)`,
	`CREATE INDEX IF NOT EXISTS platform_remediation_outcomes_rule_action_idx ON platform_remediation_outcomes (tenant_id, rule_id, action_type, observed_at DESC)`,
	`CREATE TABLE IF NOT EXISTS platform_resolution_episodes (
  tenant_id TEXT NOT NULL,
  episode_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  finding_fingerprint TEXT NOT NULL,
  finding_revision TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  resolution_type TEXT NOT NULL DEFAULT '',
  verification_id TEXT NOT NULL DEFAULT '',
  outcome_id TEXT NOT NULL DEFAULT '',
  source_health TEXT NOT NULL,
  source_runtime_id TEXT NOT NULL,
  durability_state TEXT NOT NULL,
  opened_at TIMESTAMPTZ NOT NULL,
  resolved_at TIMESTAMPTZ,
  reopened_at TIMESTAMPTZ,
  as_of TIMESTAMPTZ NOT NULL,
  time_to_resolution_ns BIGINT NOT NULL DEFAULT 0,
  time_to_recurrence_ns BIGINT NOT NULL DEFAULT 0,
  revision_digest TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, episode_id),
  CHECK (resolution_type <> 'verified' OR (verification_id <> '' AND outcome_id <> '')),
  CHECK (resolution_type <> 'manual' OR verification_id = '')
)`,
	`CREATE INDEX IF NOT EXISTS platform_resolution_episodes_finding_idx ON platform_resolution_episodes (tenant_id, finding_id, opened_at DESC)`,
	`CREATE INDEX IF NOT EXISTS platform_resolution_episodes_rule_state_idx ON platform_resolution_episodes (tenant_id, rule_id, durability_state, as_of DESC)`,
}

const remediationOutcomeColumns = `tenant_id, id, episode_id, finding_id, finding_fingerprint,
  finding_revision, rule_id, rule_version, decision_id, proposal_id, action_id,
  action_type, action_version, execution_id, provider_capability_version,
  verification_id, evaluation_run_id, verification_state, censored_reason,
  source_health, source_runtime_id, provider_succeeded, verified_resolution,
  action_completed_at, verified_at, observed_at, verification_latency_ns, digest, created_at`

const resolutionEpisodeColumns = `tenant_id, episode_id, finding_id, finding_fingerprint,
  finding_revision, rule_id, rule_version, resolution_type, verification_id,
  outcome_id, source_health, source_runtime_id, durability_state, opened_at,
  resolved_at, reopened_at, as_of, time_to_resolution_ns, time_to_recurrence_ns,
  revision_digest, created_at, updated_at`

const resolutionEpisodeNewerObservationGuard = `EXCLUDED.as_of > platform_resolution_episodes.as_of
  OR (EXCLUDED.as_of = platform_resolution_episodes.as_of
    AND EXCLUDED.revision_digest > platform_resolution_episodes.revision_digest)`

// RecordRemediationOutcome inserts one immutable derived result. Replaying the
// same canonical inputs returns the existing row by deterministic digest.
func (s *Store) RecordRemediationOutcome(ctx context.Context, record *ports.RemediationOutcomeRecord) (*ports.RemediationOutcomeRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureRemediationOutcomeTables(ctx); err != nil {
		return nil, err
	}
	normalized, err := normalizeRemediationOutcome(record)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO platform_remediation_outcomes (`+remediationOutcomeColumns+`)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
  $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, NOW())
ON CONFLICT (tenant_id, digest) DO UPDATE SET digest = EXCLUDED.digest
RETURNING `+remediationOutcomeColumns,
		normalized.TenantID, normalized.ID, normalized.EpisodeID, normalized.FindingID,
		normalized.FindingFingerprint, normalized.FindingRevision, normalized.RuleID,
		normalized.RuleVersion, normalized.DecisionID, normalized.ProposalID,
		normalized.ActionID, normalized.ActionType, normalized.ActionVersion,
		normalized.ExecutionID, normalized.ProviderCapabilityVersion,
		normalized.VerificationID, normalized.EvaluationRunID, normalized.VerificationState,
		normalized.CensoredReason, normalized.SourceHealth, normalized.SourceRuntimeID,
		normalized.ProviderSucceeded, normalized.VerifiedResolution,
		nullableTimeArg(normalized.ActionCompletedAt), nullableTimeArg(normalized.VerifiedAt),
		normalized.ObservedAt, normalized.VerificationLatency.Nanoseconds(), normalized.Digest,
	)
	return scanRemediationOutcome(row)
}

// UpsertResolutionEpisode advances the current episode projection. Older
// replayed observations cannot overwrite a newer as_of state.
func (s *Store) UpsertResolutionEpisode(ctx context.Context, record *ports.ResolutionEpisodeRecord) (*ports.ResolutionEpisodeRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureRemediationOutcomeTables(ctx); err != nil {
		return nil, err
	}
	normalized, err := normalizeResolutionEpisode(record)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO platform_resolution_episodes (`+resolutionEpisodeColumns+`)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
  $16, $17, $18, $19, $20, NOW(), NOW())
ON CONFLICT (tenant_id, episode_id) DO UPDATE SET
  finding_id = EXCLUDED.finding_id,
  finding_fingerprint = EXCLUDED.finding_fingerprint,
  finding_revision = EXCLUDED.finding_revision,
  rule_id = EXCLUDED.rule_id,
  rule_version = EXCLUDED.rule_version,
  resolution_type = EXCLUDED.resolution_type,
  verification_id = EXCLUDED.verification_id,
  outcome_id = EXCLUDED.outcome_id,
  source_health = EXCLUDED.source_health,
  source_runtime_id = EXCLUDED.source_runtime_id,
  durability_state = EXCLUDED.durability_state,
  opened_at = EXCLUDED.opened_at,
  resolved_at = EXCLUDED.resolved_at,
  reopened_at = EXCLUDED.reopened_at,
  as_of = EXCLUDED.as_of,
  time_to_resolution_ns = EXCLUDED.time_to_resolution_ns,
  time_to_recurrence_ns = EXCLUDED.time_to_recurrence_ns,
  revision_digest = EXCLUDED.revision_digest,
  updated_at = NOW()
WHERE `+resolutionEpisodeNewerObservationGuard+`
RETURNING `+resolutionEpisodeColumns,
		normalized.TenantID, normalized.EpisodeID, normalized.FindingID,
		normalized.FindingFingerprint, normalized.FindingRevision, normalized.RuleID,
		normalized.RuleVersion, normalized.ResolutionType, normalized.VerificationID,
		normalized.OutcomeID, normalized.SourceHealth, normalized.SourceRuntimeID,
		normalized.DurabilityState, normalized.OpenedAt, nullableTimeArg(normalized.ResolvedAt),
		nullableTimeArg(normalized.ReopenedAt), normalized.AsOf,
		normalized.TimeToResolution.Nanoseconds(), normalized.TimeToRecurrence.Nanoseconds(),
		normalized.RevisionDigest,
	)
	stored, scanErr := scanResolutionEpisode(row)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return s.getResolutionEpisode(ctx, normalized.TenantID, normalized.EpisodeID)
	}
	return stored, scanErr
}

func (s *Store) ListRemediationOutcomes(ctx context.Context, request ports.ListRemediationOutcomesRequest) ([]*ports.RemediationOutcomeRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureRemediationOutcomeTables(ctx); err != nil {
		return nil, err
	}
	query, args, err := remediationOutcomeListQuery(request)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list remediation outcomes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.RemediationOutcomeRecord{}
	for rows.Next() {
		record, scanErr := scanRemediationOutcome(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) ListResolutionEpisodes(ctx context.Context, request ports.ListResolutionEpisodesRequest) ([]*ports.ResolutionEpisodeRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureRemediationOutcomeTables(ctx); err != nil {
		return nil, err
	}
	query, args, err := resolutionEpisodeListQuery(request)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list resolution episodes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.ResolutionEpisodeRecord{}
	for rows.Next() {
		record, scanErr := scanResolutionEpisode(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func remediationOutcomeListQuery(request ports.ListRemediationOutcomesRequest) (string, []any, error) {
	clauses, args, err := remediationListClauses(request.TenantID, map[string]string{
		"finding_id": request.FindingID, "rule_id": request.RuleID,
		"action_type": request.ActionType, "verification_state": request.VerificationState,
	})
	if err != nil {
		return "", nil, err
	}
	args = append(args, boundedRemediationLimit(request.Limit))
	// #nosec G201 -- predicates and columns are fixed above.
	return fmt.Sprintf("SELECT %s FROM platform_remediation_outcomes WHERE %s ORDER BY observed_at DESC, id ASC LIMIT $%d", remediationOutcomeColumns, strings.Join(clauses, " AND "), len(args)), args, nil
}

func resolutionEpisodeListQuery(request ports.ListResolutionEpisodesRequest) (string, []any, error) {
	clauses, args, err := remediationListClauses(request.TenantID, map[string]string{
		"finding_id": request.FindingID, "rule_id": request.RuleID, "durability_state": request.DurabilityState,
	})
	if err != nil {
		return "", nil, err
	}
	args = append(args, boundedRemediationLimit(request.Limit))
	// #nosec G201 -- predicates and columns are fixed above.
	return fmt.Sprintf("SELECT %s FROM platform_resolution_episodes WHERE %s ORDER BY as_of DESC, episode_id ASC LIMIT $%d", resolutionEpisodeColumns, strings.Join(clauses, " AND "), len(args)), args, nil
}

func remediationListClauses(tenantID string, filters map[string]string) ([]string, []any, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, nil, errors.New("tenant_id is required")
	}
	clauses := []string{"tenant_id = $1"}
	args := []any{tenantID}
	for _, column := range []string{"finding_id", "rule_id", "action_type", "verification_state", "durability_state"} {
		if value := strings.TrimSpace(filters[column]); value != "" {
			args = append(args, value)
			clauses = append(clauses, fmt.Sprintf("%s = $%d", column, len(args)))
		}
	}
	return clauses, args, nil
}

func (s *Store) getResolutionEpisode(ctx context.Context, tenantID, episodeID string) (*ports.ResolutionEpisodeRecord, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+resolutionEpisodeColumns+" FROM platform_resolution_episodes WHERE tenant_id = $1 AND episode_id = $2", tenantID, episodeID)
	return scanResolutionEpisode(row)
}

func (s *Store) ensureRemediationOutcomeTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.findingIntel.remediation, "remediation_outcomes", ensureRemediationOutcomeStatements)
}

type remediationScanner interface{ Scan(...any) error }

func scanRemediationOutcome(scanner remediationScanner) (*ports.RemediationOutcomeRecord, error) {
	var record ports.RemediationOutcomeRecord
	var actionCompletedAt, verifiedAt sql.NullTime
	var latencyNS int64
	if err := scanner.Scan(
		&record.TenantID, &record.ID, &record.EpisodeID, &record.FindingID,
		&record.FindingFingerprint, &record.FindingRevision, &record.RuleID, &record.RuleVersion,
		&record.DecisionID, &record.ProposalID, &record.ActionID, &record.ActionType,
		&record.ActionVersion, &record.ExecutionID, &record.ProviderCapabilityVersion,
		&record.VerificationID, &record.EvaluationRunID, &record.VerificationState,
		&record.CensoredReason, &record.SourceHealth, &record.SourceRuntimeID,
		&record.ProviderSucceeded, &record.VerifiedResolution, &actionCompletedAt, &verifiedAt,
		&record.ObservedAt, &latencyNS, &record.Digest, &record.CreatedAt,
	); err != nil {
		return nil, err
	}
	if actionCompletedAt.Valid {
		record.ActionCompletedAt = actionCompletedAt.Time
	}
	if verifiedAt.Valid {
		record.VerifiedAt = verifiedAt.Time
	}
	record.VerificationLatency = time.Duration(latencyNS)
	return &record, nil
}

func scanResolutionEpisode(scanner remediationScanner) (*ports.ResolutionEpisodeRecord, error) {
	var record ports.ResolutionEpisodeRecord
	var resolvedAt, reopenedAt sql.NullTime
	var resolutionNS, recurrenceNS int64
	if err := scanner.Scan(
		&record.TenantID, &record.EpisodeID, &record.FindingID, &record.FindingFingerprint,
		&record.FindingRevision, &record.RuleID, &record.RuleVersion, &record.ResolutionType,
		&record.VerificationID, &record.OutcomeID, &record.SourceHealth, &record.SourceRuntimeID,
		&record.DurabilityState, &record.OpenedAt, &resolvedAt, &reopenedAt, &record.AsOf,
		&resolutionNS, &recurrenceNS, &record.RevisionDigest, &record.CreatedAt, &record.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if resolvedAt.Valid {
		record.ResolvedAt = resolvedAt.Time
	}
	if reopenedAt.Valid {
		record.ReopenedAt = reopenedAt.Time
	}
	record.TimeToResolution = time.Duration(resolutionNS)
	record.TimeToRecurrence = time.Duration(recurrenceNS)
	return &record, nil
}

func normalizeRemediationOutcome(record *ports.RemediationOutcomeRecord) (ports.RemediationOutcomeRecord, error) {
	if record == nil {
		return ports.RemediationOutcomeRecord{}, errors.New("remediation outcome is required")
	}
	normalized := *record
	trimRemediationOutcome(&normalized)
	if normalized.ID == "" || normalized.TenantID == "" || normalized.EpisodeID == "" || normalized.FindingID == "" ||
		normalized.FindingFingerprint == "" || normalized.FindingRevision == "" || normalized.RuleID == "" ||
		normalized.RuleVersion == "" || normalized.ActionID == "" || normalized.ActionType == "" ||
		normalized.ActionVersion == "" || normalized.ExecutionID == "" || normalized.ProviderCapabilityVersion == "" ||
		normalized.SourceRuntimeID == "" || normalized.VerificationState == "" || normalized.SourceHealth == "" ||
		normalized.ObservedAt.IsZero() || normalized.Digest == "" {
		return ports.RemediationOutcomeRecord{}, errors.New("remediation outcome canonical ids, versions, state, source, observed_at, and digest are required")
	}
	if normalized.VerifiedResolution && normalized.VerificationState != "verified_closed" {
		return ports.RemediationOutcomeRecord{}, errors.New("verified resolution requires verified_closed state")
	}
	if normalized.VerificationState == "censored" && normalized.CensoredReason == "" {
		return ports.RemediationOutcomeRecord{}, errors.New("censored outcome requires a reason")
	}
	return normalized, nil
}

func normalizeResolutionEpisode(record *ports.ResolutionEpisodeRecord) (ports.ResolutionEpisodeRecord, error) {
	if record == nil {
		return ports.ResolutionEpisodeRecord{}, errors.New("resolution episode is required")
	}
	normalized := *record
	trimResolutionEpisode(&normalized)
	if normalized.EpisodeID == "" || normalized.TenantID == "" || normalized.FindingID == "" ||
		normalized.FindingFingerprint == "" || normalized.FindingRevision == "" || normalized.RuleID == "" ||
		normalized.RuleVersion == "" || normalized.SourceRuntimeID == "" || normalized.SourceHealth == "" ||
		normalized.DurabilityState == "" || normalized.OpenedAt.IsZero() || normalized.AsOf.IsZero() || normalized.RevisionDigest == "" {
		return ports.ResolutionEpisodeRecord{}, errors.New("resolution episode canonical ids, versions, state, source, timestamps, and digest are required")
	}
	return normalized, nil
}

func trimRemediationOutcome(record *ports.RemediationOutcomeRecord) {
	values := []*string{&record.ID, &record.TenantID, &record.EpisodeID, &record.FindingID,
		&record.FindingFingerprint, &record.FindingRevision, &record.RuleID, &record.RuleVersion,
		&record.DecisionID, &record.ProposalID, &record.ActionID, &record.ActionType,
		&record.ActionVersion, &record.ExecutionID, &record.ProviderCapabilityVersion,
		&record.VerificationID, &record.EvaluationRunID, &record.VerificationState,
		&record.CensoredReason, &record.SourceHealth, &record.SourceRuntimeID, &record.Digest}
	for _, value := range values {
		*value = strings.TrimSpace(*value)
	}
}

func trimResolutionEpisode(record *ports.ResolutionEpisodeRecord) {
	values := []*string{&record.EpisodeID, &record.TenantID, &record.FindingID,
		&record.FindingFingerprint, &record.FindingRevision, &record.RuleID, &record.RuleVersion,
		&record.ResolutionType, &record.VerificationID, &record.OutcomeID, &record.SourceHealth,
		&record.SourceRuntimeID, &record.DurabilityState, &record.RevisionDigest}
	for _, value := range values {
		*value = strings.TrimSpace(*value)
	}
}

func boundedRemediationLimit(limit uint32) uint32 {
	if limit == 0 || limit > 500 {
		return 50
	}
	return limit
}
