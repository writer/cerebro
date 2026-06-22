package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultFindingCandidateListLimit = uint32(500)
	maxFindingCandidateListLimit     = uint32(500)
)

var ensureFindingCandidateStatements = []string{
	`CREATE TABLE IF NOT EXISTS finding_candidate_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  status TEXT NOT NULL,
  event_limit INTEGER NOT NULL DEFAULT 0,
  events_evaluated INTEGER NOT NULL DEFAULT 0,
  events_matched INTEGER NOT NULL DEFAULT 0,
  candidates INTEGER NOT NULL DEFAULT 0,
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  error TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS finding_candidate_runs_runtime_idx ON finding_candidate_runs (tenant_id, runtime_id, started_at DESC)`,
	`CREATE INDEX IF NOT EXISTS finding_candidate_runs_rule_idx ON finding_candidate_runs (tenant_id, rule_id, started_at DESC)`,
	`CREATE INDEX IF NOT EXISTS finding_candidate_runs_status_idx ON finding_candidate_runs (tenant_id, status, started_at DESC)`,
	`CREATE TABLE IF NOT EXISTS finding_candidates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL,
  finding_json JSONB NOT NULL,
  evidence_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  last_run_id TEXT NOT NULL,
  observation_count INTEGER NOT NULL DEFAULT 0,
  first_observed_at TIMESTAMPTZ NOT NULL,
  last_observed_at TIMESTAMPTZ NOT NULL,
  promoted_finding_id TEXT NOT NULL DEFAULT '',
  decision_id TEXT NOT NULL DEFAULT '',
  promoted_by TEXT NOT NULL DEFAULT '',
  promotion_rationale TEXT NOT NULL DEFAULT '',
  change_ticket TEXT NOT NULL DEFAULT '',
  promoted_at TIMESTAMPTZ,
  rejected_by TEXT NOT NULL DEFAULT '',
  rejection_rationale TEXT NOT NULL DEFAULT '',
  rejected_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`ALTER TABLE finding_candidates ADD COLUMN IF NOT EXISTS rejected_by TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE finding_candidates ADD COLUMN IF NOT EXISTS rejection_rationale TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE finding_candidates ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMPTZ`,
	`CREATE INDEX IF NOT EXISTS finding_candidates_runtime_idx ON finding_candidates (tenant_id, runtime_id, last_observed_at DESC, id)`,
	`CREATE INDEX IF NOT EXISTS finding_candidates_rule_idx ON finding_candidates (tenant_id, rule_id, last_observed_at DESC, id)`,
	`CREATE INDEX IF NOT EXISTS finding_candidates_status_idx ON finding_candidates (tenant_id, status, last_observed_at DESC, id)`,
	`CREATE INDEX IF NOT EXISTS finding_candidates_fingerprint_idx ON finding_candidates (tenant_id, fingerprint)`,
}

// PutFindingCandidateRun upserts one candidate evaluation run.
func (s *Store) PutFindingCandidateRun(ctx context.Context, run *ports.FindingCandidateRun) error {
	if run == nil {
		return errors.New("finding candidate run is required")
	}
	id := strings.TrimSpace(run.ID)
	if id == "" {
		return errors.New("finding candidate run id is required")
	}
	tenantID := strings.TrimSpace(run.TenantID)
	if tenantID == "" {
		return errors.New("finding candidate run tenant id is required")
	}
	runtimeID := strings.TrimSpace(run.RuntimeID)
	if runtimeID == "" {
		return errors.New("finding candidate run runtime id is required")
	}
	ruleID := strings.TrimSpace(run.RuleID)
	if ruleID == "" {
		return errors.New("finding candidate run rule id is required")
	}
	status := strings.TrimSpace(run.Status)
	if status == "" {
		return errors.New("finding candidate run status is required")
	}
	startedAt := run.StartedAt.UTC()
	if startedAt.IsZero() {
		return errors.New("finding candidate run started_at is required")
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureFindingCandidateTables(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO finding_candidate_runs (
  id, tenant_id, runtime_id, rule_id, status, event_limit, events_evaluated,
  events_matched, candidates, started_at, finished_at, error
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (id)
DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  runtime_id = EXCLUDED.runtime_id,
  rule_id = EXCLUDED.rule_id,
  status = EXCLUDED.status,
  event_limit = EXCLUDED.event_limit,
  events_evaluated = EXCLUDED.events_evaluated,
  events_matched = EXCLUDED.events_matched,
  candidates = EXCLUDED.candidates,
  started_at = EXCLUDED.started_at,
  finished_at = EXCLUDED.finished_at,
  error = EXCLUDED.error,
  updated_at = NOW()`,
		id,
		tenantID,
		runtimeID,
		ruleID,
		status,
		int64(run.EventLimit),
		int64(run.EventsEvaluated),
		int64(run.EventsMatched),
		int64(run.Candidates),
		startedAt,
		nullableTime(run.FinishedAt),
		strings.TrimSpace(run.Error),
	)
	if err != nil {
		return fmt.Errorf("upsert finding candidate run %q: %w", id, err)
	}
	return nil
}

// GetFindingCandidateRun loads one candidate evaluation run.
func (s *Store) GetFindingCandidateRun(ctx context.Context, runID string) (*ports.FindingCandidateRun, error) {
	id := strings.TrimSpace(runID)
	if id == "" {
		return nil, errors.New("finding candidate run id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingCandidateTables(ctx); err != nil {
		return nil, err
	}
	run := &ports.FindingCandidateRun{}
	var finishedAt sql.NullTime
	if err := s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, runtime_id, rule_id, status, event_limit, events_evaluated,
  events_matched, candidates, started_at, finished_at, error
FROM finding_candidate_runs
WHERE id = $1`, id).Scan(
		&run.ID,
		&run.TenantID,
		&run.RuntimeID,
		&run.RuleID,
		&run.Status,
		&run.EventLimit,
		&run.EventsEvaluated,
		&run.EventsMatched,
		&run.Candidates,
		&run.StartedAt,
		&finishedAt,
		&run.Error,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrFindingEvaluationRunNotFound, id)
		}
		return nil, fmt.Errorf("query finding candidate run %q: %w", id, err)
	}
	if finishedAt.Valid {
		run.FinishedAt = finishedAt.Time.UTC()
	}
	return run, nil
}

// ListFindingCandidateRuns lists candidate evaluation runs for one tenant/runtime scope.
func (s *Store) ListFindingCandidateRuns(ctx context.Context, request ports.ListFindingCandidatesRequest) (_ []*ports.FindingCandidateRun, err error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingCandidateTables(ctx); err != nil {
		return nil, err
	}
	query, args, err := findingCandidateRunListQuery(request)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query finding candidate runs: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close finding candidate run rows: %w", closeErr)
		}
	}()
	runs := []*ports.FindingCandidateRun{}
	for rows.Next() {
		run := &ports.FindingCandidateRun{}
		var finishedAt sql.NullTime
		if err := rows.Scan(&run.ID, &run.TenantID, &run.RuntimeID, &run.RuleID, &run.Status, &run.EventLimit, &run.EventsEvaluated, &run.EventsMatched, &run.Candidates, &run.StartedAt, &finishedAt, &run.Error); err != nil {
			return nil, fmt.Errorf("scan finding candidate run: %w", err)
		}
		if finishedAt.Valid {
			run.FinishedAt = finishedAt.Time.UTC()
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding candidate run rows: %w", err)
	}
	return runs, nil
}

// UpsertFindingCandidate persists one non-production candidate snapshot.
func (s *Store) UpsertFindingCandidate(ctx context.Context, candidate *ports.FindingCandidateRecord) (*ports.FindingCandidateRecord, error) {
	if candidate == nil {
		return nil, errors.New("finding candidate is required")
	}
	if err := validateFindingCandidate(candidate); err != nil {
		return nil, err
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingCandidateTables(ctx); err != nil {
		return nil, err
	}
	findingJSON, err := json.Marshal(candidate.Finding)
	if err != nil {
		return nil, fmt.Errorf("marshal finding candidate finding: %w", err)
	}
	evidenceJSON, err := json.Marshal(candidate.Evidence)
	if err != nil {
		return nil, fmt.Errorf("marshal finding candidate evidence: %w", err)
	}
	status := strings.TrimSpace(candidate.Status)
	if status == "" {
		status = "candidate"
	}
	observations := candidate.ObservationCount
	if observations == 0 {
		observations = 1
	}
	firstObservedAt := candidate.FirstObservedAt.UTC()
	if firstObservedAt.IsZero() {
		firstObservedAt = candidate.Finding.FirstObservedAt.UTC()
	}
	lastObservedAt := candidate.LastObservedAt.UTC()
	if lastObservedAt.IsZero() {
		lastObservedAt = candidate.Finding.LastObservedAt.UTC()
	}
	now := time.Now().UTC()
	row, err := s.queryFindingCandidate(ctx, `
INSERT INTO finding_candidates (
  id, tenant_id, runtime_id, rule_id, fingerprint, status, finding_json, evidence_json,
  last_run_id, observation_count, first_observed_at, last_observed_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, $11, $12)
ON CONFLICT (id)
DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  runtime_id = EXCLUDED.runtime_id,
  rule_id = EXCLUDED.rule_id,
  fingerprint = EXCLUDED.fingerprint,
  status = CASE WHEN finding_candidates.status IN ('promoted', 'rejected') THEN finding_candidates.status ELSE EXCLUDED.status END,
  finding_json = EXCLUDED.finding_json,
  evidence_json = EXCLUDED.evidence_json,
  last_run_id = EXCLUDED.last_run_id,
  observation_count = finding_candidates.observation_count + EXCLUDED.observation_count,
  first_observed_at = LEAST(finding_candidates.first_observed_at, EXCLUDED.first_observed_at),
  last_observed_at = GREATEST(finding_candidates.last_observed_at, EXCLUDED.last_observed_at),
  updated_at = $13
RETURNING `+findingCandidateSelectColumns,
		strings.TrimSpace(candidate.ID),
		strings.TrimSpace(candidate.TenantID),
		strings.TrimSpace(candidate.RuntimeID),
		strings.TrimSpace(candidate.RuleID),
		strings.TrimSpace(candidate.Fingerprint),
		status,
		string(findingJSON),
		string(evidenceJSON),
		strings.TrimSpace(candidate.LastRunID),
		int64(observations),
		firstObservedAt,
		lastObservedAt,
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("upsert finding candidate %q: %w", strings.TrimSpace(candidate.ID), err)
	}
	return row, nil
}

// GetFindingCandidate loads one candidate by id.
func (s *Store) GetFindingCandidate(ctx context.Context, candidateID string) (*ports.FindingCandidateRecord, error) {
	id := strings.TrimSpace(candidateID)
	if id == "" {
		return nil, errors.New("finding candidate id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingCandidateTables(ctx); err != nil {
		return nil, err
	}
	candidate, err := s.queryFindingCandidate(ctx, `SELECT `+findingCandidateSelectColumns+` FROM finding_candidates WHERE id = $1`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrFindingCandidateNotFound, id)
		}
		return nil, fmt.Errorf("query finding candidate %q: %w", id, err)
	}
	return candidate, nil
}

// ListFindingCandidates lists candidate finding snapshots.
func (s *Store) ListFindingCandidates(ctx context.Context, request ports.ListFindingCandidatesRequest) (_ []*ports.FindingCandidateRecord, err error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingCandidateTables(ctx); err != nil {
		return nil, err
	}
	query, args, err := findingCandidateListQuery(request)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query finding candidates: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close finding candidate rows: %w", closeErr)
		}
	}()
	candidates := []*ports.FindingCandidateRecord{}
	for rows.Next() {
		candidate, err := scanFindingCandidate(rows)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding candidate rows: %w", err)
	}
	return candidates, nil
}

// MarkFindingCandidatePromoted records promotion metadata on one candidate row.
func (s *Store) MarkFindingCandidatePromoted(ctx context.Context, promotion ports.FindingCandidatePromotion) (*ports.FindingCandidateRecord, error) {
	id := strings.TrimSpace(promotion.CandidateID)
	if id == "" {
		return nil, errors.New("finding candidate id is required")
	}
	if strings.TrimSpace(promotion.PromotedFindingID) == "" {
		return nil, errors.New("promoted finding id is required")
	}
	if strings.TrimSpace(promotion.PromotedBy) == "" {
		return nil, errors.New("promoted by is required")
	}
	if strings.TrimSpace(promotion.Rationale) == "" {
		return nil, errors.New("promotion rationale is required")
	}
	if strings.TrimSpace(promotion.ChangeTicket) == "" {
		return nil, errors.New("promotion change ticket is required")
	}
	promotedAt := promotion.PromotedAt.UTC()
	if promotedAt.IsZero() {
		promotedAt = time.Now().UTC()
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingCandidateTables(ctx); err != nil {
		return nil, err
	}
	candidate, err := s.queryFindingCandidate(ctx, `
UPDATE finding_candidates
SET status = 'promoted',
  promoted_finding_id = $2,
  decision_id = $3,
  promoted_by = $4,
  promotion_rationale = $5,
  change_ticket = $6,
  promoted_at = $7,
  updated_at = NOW()
WHERE id = $1
  AND status = 'candidate'
RETURNING `+findingCandidateSelectColumns,
		id,
		strings.TrimSpace(promotion.PromotedFindingID),
		strings.TrimSpace(promotion.DecisionID),
		strings.TrimSpace(promotion.PromotedBy),
		strings.TrimSpace(promotion.Rationale),
		strings.TrimSpace(promotion.ChangeTicket),
		promotedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrFindingCandidateNotFound, id)
		}
		return nil, fmt.Errorf("mark finding candidate %q promoted: %w", id, err)
	}
	return candidate, nil
}

// MarkFindingCandidateRejected records rejection metadata on one candidate row.
func (s *Store) MarkFindingCandidateRejected(ctx context.Context, rejection ports.FindingCandidateRejection) (*ports.FindingCandidateRecord, error) {
	id := strings.TrimSpace(rejection.CandidateID)
	if id == "" {
		return nil, errors.New("finding candidate id is required")
	}
	if strings.TrimSpace(rejection.DecisionID) == "" {
		return nil, errors.New("rejection decision id is required")
	}
	if strings.TrimSpace(rejection.RejectedBy) == "" {
		return nil, errors.New("rejected by is required")
	}
	if strings.TrimSpace(rejection.Rationale) == "" {
		return nil, errors.New("rejection rationale is required")
	}
	rejectedAt := rejection.RejectedAt.UTC()
	if rejectedAt.IsZero() {
		rejectedAt = time.Now().UTC()
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingCandidateTables(ctx); err != nil {
		return nil, err
	}
	candidate, err := s.queryFindingCandidate(ctx, `
UPDATE finding_candidates
SET status = 'rejected',
  decision_id = $2,
  rejected_by = $3,
  rejection_rationale = $4,
  rejected_at = $5,
  updated_at = NOW()
WHERE id = $1
  AND status = 'candidate'
RETURNING `+findingCandidateSelectColumns,
		id,
		strings.TrimSpace(rejection.DecisionID),
		strings.TrimSpace(rejection.RejectedBy),
		strings.TrimSpace(rejection.Rationale),
		rejectedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrFindingCandidateNotFound, id)
		}
		return nil, fmt.Errorf("mark finding candidate %q rejected: %w", id, err)
	}
	return candidate, nil
}

const findingCandidateSelectColumns = `id, tenant_id, runtime_id, rule_id, fingerprint, status,
  finding_json::text, evidence_json::text, last_run_id, observation_count, first_observed_at,
  last_observed_at, promoted_finding_id, decision_id, promoted_by, promotion_rationale,
  change_ticket, promoted_at, rejected_by, rejection_rationale, rejected_at, created_at, updated_at`

type findingCandidateScanner interface {
	Scan(dest ...any) error
}

func (s *Store) queryFindingCandidate(ctx context.Context, query string, args ...any) (*ports.FindingCandidateRecord, error) {
	return scanFindingCandidate(s.db.QueryRowContext(ctx, query, args...))
}

func scanFindingCandidate(scanner findingCandidateScanner) (*ports.FindingCandidateRecord, error) {
	candidate := &ports.FindingCandidateRecord{}
	var findingJSON string
	var evidenceJSON string
	var promotedAt sql.NullTime
	var rejectedAt sql.NullTime
	if err := scanner.Scan(
		&candidate.ID,
		&candidate.TenantID,
		&candidate.RuntimeID,
		&candidate.RuleID,
		&candidate.Fingerprint,
		&candidate.Status,
		&findingJSON,
		&evidenceJSON,
		&candidate.LastRunID,
		&candidate.ObservationCount,
		&candidate.FirstObservedAt,
		&candidate.LastObservedAt,
		&candidate.PromotedFindingID,
		&candidate.DecisionID,
		&candidate.PromotedBy,
		&candidate.PromotionRationale,
		&candidate.ChangeTicket,
		&promotedAt,
		&candidate.RejectedBy,
		&candidate.RejectionRationale,
		&rejectedAt,
		&candidate.CreatedAt,
		&candidate.UpdatedAt,
	); err != nil {
		return nil, err
	}
	finding := &ports.FindingRecord{}
	if err := json.Unmarshal([]byte(findingJSON), finding); err != nil {
		return nil, fmt.Errorf("decode finding candidate finding %q: %w", candidate.ID, err)
	}
	var evidence []*cerebrov1.FindingEvidence
	if err := json.Unmarshal([]byte(evidenceJSON), &evidence); err != nil {
		return nil, fmt.Errorf("decode finding candidate evidence %q: %w", candidate.ID, err)
	}
	candidate.Finding = finding
	candidate.Evidence = evidence
	if promotedAt.Valid {
		candidate.PromotedAt = promotedAt.Time.UTC()
	}
	if rejectedAt.Valid {
		candidate.RejectedAt = rejectedAt.Time.UTC()
	}
	return candidate, nil
}

func validateFindingCandidate(candidate *ports.FindingCandidateRecord) error {
	if strings.TrimSpace(candidate.ID) == "" {
		return errors.New("finding candidate id is required")
	}
	if strings.TrimSpace(candidate.TenantID) == "" {
		return errors.New("finding candidate tenant id is required")
	}
	if strings.TrimSpace(candidate.RuntimeID) == "" {
		return errors.New("finding candidate runtime id is required")
	}
	if strings.TrimSpace(candidate.RuleID) == "" {
		return errors.New("finding candidate rule id is required")
	}
	if strings.TrimSpace(candidate.Fingerprint) == "" {
		return errors.New("finding candidate fingerprint is required")
	}
	if strings.TrimSpace(candidate.LastRunID) == "" {
		return errors.New("finding candidate last run id is required")
	}
	if candidate.Finding == nil {
		return errors.New("finding candidate finding is required")
	}
	return nil
}

func (s *Store) ensureFindingCandidateTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.findingIntel.candidate, "finding candidate", ensureFindingCandidateStatements)
}

func findingCandidateRunListQuery(request ports.ListFindingCandidatesRequest) (string, []any, error) {
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return "", nil, errors.New("finding candidate tenant id is required")
	}
	clauses := []string{"tenant_id = $1"}
	args := []any{tenantID}
	addFindingCandidateFilter(&clauses, &args, "runtime_id", request.RuntimeID)
	addFindingCandidateFilter(&clauses, &args, "rule_id", request.RuleID)
	addFindingCandidateFilter(&clauses, &args, "status", request.Status)
	query := `
SELECT id, tenant_id, runtime_id, rule_id, status, event_limit, events_evaluated,
  events_matched, candidates, started_at, finished_at, error
FROM finding_candidate_runs
WHERE ` + strings.Join(clauses, " AND ") + `
ORDER BY started_at DESC, id`
	args = append(args, int64(findingCandidateListLimit(request.Limit)))
	query += fmt.Sprintf(" LIMIT $%d", len(args))
	return query, args, nil
}

func findingCandidateListQuery(request ports.ListFindingCandidatesRequest) (string, []any, error) {
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return "", nil, errors.New("finding candidate tenant id is required")
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	ruleID := strings.TrimSpace(request.RuleID)
	candidateID := strings.TrimSpace(request.CandidateID)
	if runtimeID == "" && ruleID == "" && candidateID == "" {
		return "", nil, errors.New("finding candidate runtime id, rule id, or candidate id is required")
	}
	clauses := []string{"tenant_id = $1"}
	args := []any{tenantID}
	addFindingCandidateFilter(&clauses, &args, "id", candidateID)
	addFindingCandidateFilter(&clauses, &args, "runtime_id", runtimeID)
	addFindingCandidateFilter(&clauses, &args, "rule_id", ruleID)
	addFindingCandidateFilter(&clauses, &args, "status", request.Status)
	addFindingCandidateFilter(&clauses, &args, "fingerprint", request.Fingerprint)
	query := `SELECT ` + findingCandidateSelectColumns + `
FROM finding_candidates
WHERE ` + strings.Join(clauses, " AND ") + `
ORDER BY last_observed_at DESC, id`
	args = append(args, int64(findingCandidateListLimit(request.Limit)))
	query += fmt.Sprintf(" LIMIT $%d", len(args))
	return query, args, nil
}

func findingCandidateListLimit(limit uint32) uint32 {
	if limit == 0 || limit > maxFindingCandidateListLimit {
		return defaultFindingCandidateListLimit
	}
	return limit
}

func addFindingCandidateFilter(clauses *[]string, args *[]any, column string, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}
	*args = append(*args, trimmed)
	*clauses = append(*clauses, fmt.Sprintf("%s = $%d", column, len(*args)))
}
