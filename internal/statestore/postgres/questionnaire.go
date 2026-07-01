package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

var ensureQuestionnaireRunStatements = []string{
	`CREATE TABLE IF NOT EXISTS grc_questionnaire_runs (
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  direction TEXT NOT NULL DEFAULT '',
  requester TEXT NOT NULL DEFAULT '',
  customer_name TEXT NOT NULL DEFAULT '',
  vendor_urn TEXT NOT NULL DEFAULT '',
  vendor_id TEXT NOT NULL DEFAULT '',
  source_id TEXT NOT NULL DEFAULT '',
  runtime_id TEXT NOT NULL DEFAULT '',
  upload_id TEXT NOT NULL DEFAULT '',
  source_filename TEXT NOT NULL DEFAULT '',
  source_format TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  owner_id TEXT NOT NULL DEFAULT '',
  assigned_team TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL DEFAULT '',
  decision_reason TEXT NOT NULL DEFAULT '',
  ready_answer_count INTEGER NOT NULL DEFAULT 0,
  blocked_answer_count INTEGER NOT NULL DEFAULT 0,
  review_answer_count INTEGER NOT NULL DEFAULT 0,
  missing_evidence_count INTEGER NOT NULL DEFAULT 0,
  stale_evidence_count INTEGER NOT NULL DEFAULT 0,
  unassigned_count INTEGER NOT NULL DEFAULT 0,
  questions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  answers_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  assignments_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  decisions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  comments_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  timeline_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  due_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, run_id)
)`,
	`CREATE INDEX IF NOT EXISTS grc_questionnaire_runs_tenant_status_idx ON grc_questionnaire_runs (tenant_id, status, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS grc_questionnaire_runs_tenant_direction_idx ON grc_questionnaire_runs (tenant_id, direction, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS grc_questionnaire_runs_tenant_vendor_idx ON grc_questionnaire_runs (tenant_id, vendor_urn, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS grc_questionnaire_runs_tenant_owner_idx ON grc_questionnaire_runs (tenant_id, owner_id, updated_at DESC)`,
	`CREATE TABLE IF NOT EXISTS grc_questionnaire_run_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor_id TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  version INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS grc_questionnaire_run_events_run_version_uidx ON grc_questionnaire_run_events (tenant_id, run_id, version)`,
	`CREATE INDEX IF NOT EXISTS grc_questionnaire_run_events_run_idx ON grc_questionnaire_run_events (tenant_id, run_id, version DESC)`,
}

func questionnaireRunAdvisoryLockSQL() string {
	return `SELECT pg_advisory_xact_lock(hashtext('grc_questionnaire_run'), hashtext($1))`
}

func (s *Store) UpsertQuestionnaireRun(ctx context.Context, record ports.QuestionnaireRunRecord, event ports.QuestionnaireRunEventRecord) (*ports.QuestionnaireRunRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureQuestionnaireRunTables(ctx); err != nil {
		return nil, err
	}
	record = normalizeQuestionnaireRun(record)
	if err := validateQuestionnaireRun(record); err != nil {
		return nil, err
	}
	jsonFields, err := marshalQuestionnaireRunJSON(record)
	if err != nil {
		return nil, err
	}
	event = normalizeQuestionnaireRunEvent(record, event)
	eventPayload, err := json.Marshal(emptyStringMap(event.Payload))
	if err != nil {
		return nil, fmt.Errorf("marshal questionnaire run event payload: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin questionnaire run upsert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, questionnaireRunAdvisoryLockSQL(), record.TenantID+"\x00"+record.RunID); err != nil {
		return nil, fmt.Errorf("lock questionnaire run: %w", err)
	}
	var previousVersion int
	err = tx.QueryRowContext(ctx, `
SELECT COALESCE(MAX(version), 0)
FROM grc_questionnaire_run_events
WHERE tenant_id = $1 AND run_id = $2`, record.TenantID, record.RunID).Scan(&previousVersion)
	if err != nil {
		return nil, fmt.Errorf("load previous questionnaire run event version: %w", err)
	}
	event.Version = previousVersion + 1
	if event.ID == "" {
		event.ID = fmt.Sprintf("grc-questionnaire-%s-%d", record.RunID, event.Version)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO grc_questionnaire_run_events (
  id, tenant_id, run_id, event_type, actor_id, summary, payload_json, version, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, COALESCE(NULLIF($9, TIMESTAMPTZ '0001-01-01 00:00:00+00'), NOW()))`,
		event.ID, record.TenantID, record.RunID, event.EventType, event.ActorID, event.Summary, string(eventPayload), event.Version, event.CreatedAt); err != nil {
		return nil, fmt.Errorf("insert questionnaire run event: %w", err)
	}
	// #nosec G201 -- column list is fixed repository code and values are parameterized.
	query := fmt.Sprintf(`
INSERT INTO grc_questionnaire_runs (
  tenant_id, run_id, title, direction, requester, customer_name, vendor_urn, vendor_id,
  source_id, runtime_id, upload_id, source_filename, source_format, status, owner_id,
  assigned_team, decision, decision_reason, ready_answer_count, blocked_answer_count,
  review_answer_count, missing_evidence_count, stale_evidence_count, unassigned_count,
  questions_json, answers_json, assignments_json, decisions_json, comments_json, timeline_json,
  attributes_json, due_at, created_at, updated_at
)
VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8,
  $9, $10, $11, $12, $13, $14, $15,
  $16, $17, $18, $19, $20,
  $21, $22, $23, $24,
  $25::jsonb, $26::jsonb, $27::jsonb, $28::jsonb, $29::jsonb, $30::jsonb,
  $31::jsonb, $32, COALESCE(NULLIF($33, TIMESTAMPTZ '0001-01-01 00:00:00+00'), NOW()), NOW()
)
ON CONFLICT (tenant_id, run_id)
DO UPDATE SET title = EXCLUDED.title,
              direction = EXCLUDED.direction,
              requester = EXCLUDED.requester,
              customer_name = EXCLUDED.customer_name,
              vendor_urn = EXCLUDED.vendor_urn,
              vendor_id = EXCLUDED.vendor_id,
              source_id = EXCLUDED.source_id,
              runtime_id = EXCLUDED.runtime_id,
              upload_id = EXCLUDED.upload_id,
              source_filename = EXCLUDED.source_filename,
              source_format = EXCLUDED.source_format,
              status = EXCLUDED.status,
              owner_id = EXCLUDED.owner_id,
              assigned_team = EXCLUDED.assigned_team,
              decision = EXCLUDED.decision,
              decision_reason = EXCLUDED.decision_reason,
              ready_answer_count = EXCLUDED.ready_answer_count,
              blocked_answer_count = EXCLUDED.blocked_answer_count,
              review_answer_count = EXCLUDED.review_answer_count,
              missing_evidence_count = EXCLUDED.missing_evidence_count,
              stale_evidence_count = EXCLUDED.stale_evidence_count,
              unassigned_count = EXCLUDED.unassigned_count,
              questions_json = EXCLUDED.questions_json,
              answers_json = EXCLUDED.answers_json,
              assignments_json = EXCLUDED.assignments_json,
              decisions_json = EXCLUDED.decisions_json,
              comments_json = EXCLUDED.comments_json,
              timeline_json = EXCLUDED.timeline_json,
              attributes_json = EXCLUDED.attributes_json,
              due_at = EXCLUDED.due_at,
              updated_at = NOW()
RETURNING %s`, questionnaireRunColumns())
	row := tx.QueryRowContext(ctx, query,
		record.TenantID, record.RunID, record.Title, record.Direction, record.Requester, record.CustomerName, record.VendorURN, record.VendorID,
		record.SourceID, record.RuntimeID, record.UploadID, record.SourceFilename, record.SourceFormat, record.Status, record.OwnerID,
		record.AssignedTeam, record.Decision, record.DecisionReason, record.ReadyAnswerCount, record.BlockedAnswerCount,
		record.ReviewAnswerCount, record.MissingEvidence, record.StaleEvidence, record.UnassignedCount,
		jsonFields.questions, jsonFields.answers, jsonFields.assignments, jsonFields.decisions, jsonFields.comments, jsonFields.timeline,
		jsonFields.attributes, record.DueAt, record.CreatedAt)
	result, err := scanQuestionnaireRun(row)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit questionnaire run upsert: %w", err)
	}
	return result, nil
}

func (s *Store) GetQuestionnaireRun(ctx context.Context, filter ports.QuestionnaireRunFilter) (*ports.QuestionnaireRunRecord, error) {
	filter.Limit = 1
	records, err := s.ListQuestionnaireRuns(ctx, filter)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, ports.ErrQuestionnaireRunNotFound
	}
	return records[0], nil
}

func (s *Store) ListQuestionnaireRuns(ctx context.Context, filter ports.QuestionnaireRunFilter) ([]*ports.QuestionnaireRunRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureQuestionnaireRunTables(ctx); err != nil {
		return nil, err
	}
	clauses, args := questionnaireRunWhere(filter)
	limit := filter.Limit
	if limit == 0 || limit > 500 {
		limit = 500
	}
	args = append(args, limit)
	// #nosec G201 -- clauses are fixed column predicates and values remain parameterized.
	query := fmt.Sprintf(`
SELECT %s
FROM grc_questionnaire_runs
WHERE %s
ORDER BY updated_at DESC, run_id ASC
LIMIT $%d`, questionnaireRunColumns(), strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list questionnaire runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.QuestionnaireRunRecord{}
	for rows.Next() {
		record, err := scanQuestionnaireRun(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) SummarizeQuestionnaireRuns(ctx context.Context, filter ports.QuestionnaireRunFilter) (ports.QuestionnaireRunSummary, error) {
	if s == nil || s.db == nil {
		return ports.QuestionnaireRunSummary{}, errors.New("postgres is not configured")
	}
	if err := s.ensureQuestionnaireRunTables(ctx); err != nil {
		return ports.QuestionnaireRunSummary{}, err
	}
	clauses, args := questionnaireRunWhere(filter)
	// #nosec G201 -- clauses are fixed column predicates and values remain parameterized.
	query := fmt.Sprintf(`
SELECT
  COUNT(*),
  COUNT(*) FILTER (WHERE direction = 'vendor_review'),
  COUNT(*) FILTER (WHERE due_at IS NOT NULL AND due_at <= NOW() AND status NOT IN ('approved', 'rejected')),
  COALESCE(SUM(CASE WHEN status NOT IN ('approved', 'rejected') THEN blocked_answer_count ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN status NOT IN ('approved', 'rejected') THEN review_answer_count ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN status NOT IN ('approved', 'rejected') THEN ready_answer_count ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN status NOT IN ('approved', 'rejected') THEN stale_evidence_count ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN status NOT IN ('approved', 'rejected') THEN missing_evidence_count ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN status NOT IN ('approved', 'rejected') THEN unassigned_count ELSE 0 END), 0)
FROM grc_questionnaire_runs
WHERE %s`, strings.Join(clauses, " AND "))
	var summary ports.QuestionnaireRunSummary
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&summary.TotalRuns,
		&summary.VendorRuns,
		&summary.DueRuns,
		&summary.BlockedAnswers,
		&summary.ReviewAnswers,
		&summary.ReadyAnswers,
		&summary.StaleEvidence,
		&summary.MissingEvidence,
		&summary.UnassignedQuestions,
	); err != nil {
		return ports.QuestionnaireRunSummary{}, fmt.Errorf("summarize questionnaire runs: %w", err)
	}
	return summary, nil
}

func (s *Store) ListQuestionnaireVendorRollups(ctx context.Context, filter ports.QuestionnaireVendorRollupFilter) ([]ports.QuestionnaireVendorRollupRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureQuestionnaireRunTables(ctx); err != nil {
		return nil, err
	}
	filter.VendorURNs = normalizedNonEmptyStrings(filter.VendorURNs)
	if len(filter.VendorURNs) == 0 {
		return nil, nil
	}
	if filter.Now.IsZero() {
		filter.Now = time.Now().UTC()
	}
	query, args := questionnaireVendorRollupQuery(filter)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list questionnaire vendor rollups: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []ports.QuestionnaireVendorRollupRecord{}
	for rows.Next() {
		var record ports.QuestionnaireVendorRollupRecord
		if err := rows.Scan(
			&record.VendorURN,
			&record.QuestionnaireCount,
			&record.DueQuestionnaires,
			&record.ReadyAnswers,
			&record.BlockedAnswers,
			&record.ReviewAnswers,
			&record.MissingEvidence,
			&record.StaleEvidence,
			&record.OpenAssignments,
		); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func questionnaireVendorRollupQuery(filter ports.QuestionnaireVendorRollupFilter) (string, []any) {
	clauses := []string{"vendor_urn <> ''"}
	args := []any{}
	addTextFilter(&clauses, &args, "tenant_id", filter.TenantID)
	addStringInFilter(&clauses, &args, "vendor_urn", filter.VendorURNs)
	args = append(args, filter.Now)
	nowPlaceholder := len(args)
	questionnaireID := "COALESCE(NULLIF(attributes_json->>'questionnaire_urn', ''), run_id)"
	activeRun := "status NOT IN ('approved', 'rejected')"
	// #nosec G201 -- clauses are fixed column predicates and values remain parameterized.
	query := fmt.Sprintf(`
SELECT
  vendor_urn,
  COUNT(DISTINCT %s),
  COUNT(DISTINCT CASE WHEN due_at IS NOT NULL AND due_at <= $%d AND %s THEN %s END),
  COALESCE(SUM(CASE WHEN %s THEN ready_answer_count ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN %s THEN blocked_answer_count ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN %s THEN review_answer_count ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN %s THEN missing_evidence_count ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN %s THEN stale_evidence_count ELSE 0 END), 0),
	  COALESCE(SUM(CASE WHEN %s THEN (
	    SELECT COUNT(*)
	    FROM jsonb_array_elements(%s) AS assignment
	    WHERE COALESCE(assignment->>'status', '') = '' OR assignment->>'status' = 'open'
	  ) ELSE 0 END), 0)
FROM grc_questionnaire_runs
WHERE %s
GROUP BY vendor_urn
ORDER BY vendor_urn ASC`,
		questionnaireID,
		nowPlaceholder,
		activeRun,
		questionnaireID,
		activeRun,
		activeRun,
		activeRun,
		activeRun,
		activeRun,
		activeRun,
		questionnaireAssignmentsArraySQL(),
		strings.Join(clauses, " AND "))
	return query, args
}

func questionnaireAssignmentsArraySQL() string {
	return "CASE WHEN jsonb_typeof(assignments_json) = 'array' THEN assignments_json ELSE '[]'::jsonb END"
}

func questionnaireRunWhere(filter ports.QuestionnaireRunFilter) ([]string, []any) {
	clauses := []string{"1=1"}
	args := []any{}
	addTextFilter(&clauses, &args, "tenant_id", filter.TenantID)
	addTextFilter(&clauses, &args, "run_id", filter.RunID)
	addTextFilter(&clauses, &args, "direction", filter.Direction)
	addTextFilter(&clauses, &args, "status", filter.Status)
	addTextFilter(&clauses, &args, "vendor_urn", filter.VendorURN)
	addTextFilter(&clauses, &args, "requester", filter.Requester)
	addTextFilter(&clauses, &args, "customer_name", filter.Customer)
	if ownerID := strings.TrimSpace(filter.OwnerID); ownerID != "" {
		args = append(args, "%"+strings.ToLower(ownerID)+"%")
		clauses = append(clauses, fmt.Sprintf(`(
				lower(owner_id) LIKE $%d
				OR lower(assigned_team) LIKE $%d
				OR EXISTS (
					SELECT 1 FROM jsonb_array_elements(%s) AS assignment
					WHERE lower(assignment->>'owner_id') LIKE $%d OR lower(assignment->>'team') LIKE $%d
				)
			)`, len(args), len(args), questionnaireAssignmentsArraySQL(), len(args), len(args)))
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		args = append(args, "%"+strings.ToLower(query)+"%")
		clauses = append(clauses, fmt.Sprintf(`(
			lower(title) LIKE $%d
			OR lower(requester) LIKE $%d
			OR lower(customer_name) LIKE $%d
			OR lower(vendor_id) LIKE $%d
			OR lower(questions_json::text) LIKE $%d
			OR lower(answers_json::text) LIKE $%d
			OR lower(assignments_json::text) LIKE $%d
		)`, len(args), len(args), len(args), len(args), len(args), len(args), len(args)))
	}
	return clauses, args
}

func (s *Store) ListQuestionnaireRunEvents(ctx context.Context, filter ports.QuestionnaireRunEventFilter) ([]*ports.QuestionnaireRunEventRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureQuestionnaireRunTables(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1=1"}
	args := []any{}
	addTextFilter(&clauses, &args, "tenant_id", filter.TenantID)
	addTextFilter(&clauses, &args, "run_id", filter.RunID)
	limit := filter.Limit
	if limit == 0 || limit > 500 {
		limit = 500
	}
	args = append(args, limit)
	// #nosec G201 -- clauses are fixed column predicates and values remain parameterized.
	query := fmt.Sprintf(`
SELECT id, tenant_id, run_id, event_type, actor_id, summary, payload_json::text, version, created_at
FROM grc_questionnaire_run_events
WHERE %s
ORDER BY created_at ASC, version ASC, id ASC
LIMIT $%d`, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list questionnaire run events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.QuestionnaireRunEventRecord{}
	for rows.Next() {
		record, err := scanQuestionnaireRunEvent(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) ensureQuestionnaireRunTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.questionnaireRun, "grc questionnaire run", ensureQuestionnaireRunStatements)
}

type questionnaireRunJSONFields struct {
	questions   string
	answers     string
	assignments string
	decisions   string
	comments    string
	timeline    string
	attributes  string
}

func marshalQuestionnaireRunJSON(record ports.QuestionnaireRunRecord) (questionnaireRunJSONFields, error) {
	marshal := func(label string, value any) (string, error) {
		raw, err := json.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("marshal %s: %w", label, err)
		}
		return string(raw), nil
	}
	var fields questionnaireRunJSONFields
	var err error
	if fields.questions, err = marshal("questions", emptySlice(record.Questions)); err != nil {
		return fields, err
	}
	if fields.answers, err = marshal("answers", emptySlice(record.Answers)); err != nil {
		return fields, err
	}
	if fields.assignments, err = marshal("assignments", emptySlice(record.Assignments)); err != nil {
		return fields, err
	}
	if fields.decisions, err = marshal("decisions", emptySlice(record.Decisions)); err != nil {
		return fields, err
	}
	if fields.comments, err = marshal("comments", emptySlice(record.Comments)); err != nil {
		return fields, err
	}
	if fields.timeline, err = marshal("timeline", emptySlice(record.Timeline)); err != nil {
		return fields, err
	}
	if fields.attributes, err = marshal("attributes", emptyStringMap(record.Attributes)); err != nil {
		return fields, err
	}
	return fields, nil
}

func emptySlice[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

func scanQuestionnaireRun(row scanner) (*ports.QuestionnaireRunRecord, error) {
	record := &ports.QuestionnaireRunRecord{}
	var questions, answers, assignments, decisions, comments, timeline, attrs string
	var dueAt sql.NullTime
	if err := row.Scan(
		&record.TenantID, &record.RunID, &record.Title, &record.Direction, &record.Requester, &record.CustomerName, &record.VendorURN, &record.VendorID,
		&record.SourceID, &record.RuntimeID, &record.UploadID, &record.SourceFilename, &record.SourceFormat, &record.Status, &record.OwnerID,
		&record.AssignedTeam, &record.Decision, &record.DecisionReason, &record.ReadyAnswerCount, &record.BlockedAnswerCount,
		&record.ReviewAnswerCount, &record.MissingEvidence, &record.StaleEvidence, &record.UnassignedCount,
		&questions, &answers, &assignments, &decisions, &comments, &timeline, &attrs, &dueAt, &record.CreatedAt, &record.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(questions), &record.Questions)
	_ = json.Unmarshal([]byte(answers), &record.Answers)
	_ = json.Unmarshal([]byte(assignments), &record.Assignments)
	_ = json.Unmarshal([]byte(decisions), &record.Decisions)
	_ = json.Unmarshal([]byte(comments), &record.Comments)
	_ = json.Unmarshal([]byte(timeline), &record.Timeline)
	record.Attributes = map[string]string{}
	_ = json.Unmarshal([]byte(attrs), &record.Attributes)
	if dueAt.Valid {
		value := dueAt.Time.UTC()
		record.DueAt = &value
	}
	return record, nil
}

func scanQuestionnaireRunEvent(row scanner) (*ports.QuestionnaireRunEventRecord, error) {
	record := &ports.QuestionnaireRunEventRecord{}
	var payload string
	if err := row.Scan(&record.ID, &record.TenantID, &record.RunID, &record.EventType, &record.ActorID, &record.Summary, &payload, &record.Version, &record.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, err
	}
	record.Payload = map[string]string{}
	_ = json.Unmarshal([]byte(payload), &record.Payload)
	return record, nil
}

func questionnaireRunColumns() string {
	return `tenant_id, run_id, title, direction, requester, customer_name, vendor_urn, vendor_id,
source_id, runtime_id, upload_id, source_filename, source_format, status, owner_id,
assigned_team, decision, decision_reason, ready_answer_count, blocked_answer_count,
review_answer_count, missing_evidence_count, stale_evidence_count, unassigned_count,
questions_json::text, answers_json::text, assignments_json::text, decisions_json::text,
comments_json::text, timeline_json::text, attributes_json::text, due_at, created_at, updated_at`
}

func normalizeQuestionnaireRun(record ports.QuestionnaireRunRecord) ports.QuestionnaireRunRecord {
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.RunID = strings.TrimSpace(record.RunID)
	record.Title = strings.TrimSpace(record.Title)
	record.Direction = strings.TrimSpace(record.Direction)
	record.Requester = strings.TrimSpace(record.Requester)
	record.CustomerName = strings.TrimSpace(record.CustomerName)
	record.VendorURN = strings.TrimSpace(record.VendorURN)
	record.VendorID = strings.TrimSpace(record.VendorID)
	record.SourceID = strings.TrimSpace(record.SourceID)
	record.RuntimeID = strings.TrimSpace(record.RuntimeID)
	record.UploadID = strings.TrimSpace(record.UploadID)
	record.SourceFilename = strings.TrimSpace(record.SourceFilename)
	record.SourceFormat = strings.TrimSpace(record.SourceFormat)
	record.Status = strings.TrimSpace(record.Status)
	record.OwnerID = strings.TrimSpace(record.OwnerID)
	record.AssignedTeam = strings.TrimSpace(record.AssignedTeam)
	record.Decision = strings.TrimSpace(record.Decision)
	record.DecisionReason = strings.TrimSpace(record.DecisionReason)
	if record.Status == "" {
		record.Status = ports.QuestionnaireStatusIntake
	}
	if record.Decision == "" {
		record.Decision = ports.QuestionnaireDecisionNeedsInput
	}
	record.Attributes = emptyStringMap(record.Attributes)
	return record
}

func normalizeQuestionnaireRunEvent(record ports.QuestionnaireRunRecord, event ports.QuestionnaireRunEventRecord) ports.QuestionnaireRunEventRecord {
	event.ID = strings.TrimSpace(event.ID)
	event.TenantID = record.TenantID
	event.RunID = record.RunID
	event.EventType = strings.TrimSpace(event.EventType)
	event.ActorID = strings.TrimSpace(event.ActorID)
	event.Summary = strings.TrimSpace(event.Summary)
	event.Payload = emptyStringMap(event.Payload)
	if event.EventType == "" {
		event.EventType = ports.QuestionnaireEventProcessed
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	return event
}

func validateQuestionnaireRun(record ports.QuestionnaireRunRecord) error {
	if record.TenantID == "" || record.RunID == "" {
		return errors.New("tenant_id and run_id are required")
	}
	if !ports.IsQuestionnaireDirection(record.Direction) {
		return errors.New("questionnaire direction is invalid")
	}
	if len(record.Questions) == 0 {
		return errors.New("questionnaire questions are required")
	}
	if !ports.IsQuestionnaireStatus(record.Status) {
		return errors.New("questionnaire status is invalid")
	}
	if !ports.IsQuestionnaireDecision(record.Decision) {
		return errors.New("questionnaire decision is invalid")
	}
	return nil
}
