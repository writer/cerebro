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

var ensureGRCVendorQuestionnaireStatements = []string{
	`CREATE TABLE IF NOT EXISTS grc_vendor_questionnaire_reviews (
  tenant_id TEXT NOT NULL,
  review_id TEXT NOT NULL,
  vendor_urn TEXT NOT NULL DEFAULT '',
  vendor_id TEXT NOT NULL DEFAULT '',
  source_id TEXT NOT NULL DEFAULT '',
  runtime_id TEXT NOT NULL DEFAULT '',
  upload_id TEXT NOT NULL DEFAULT '',
  questionnaire_urn TEXT NOT NULL DEFAULT '',
  questionnaire_type TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL DEFAULT '',
  decision_reason TEXT NOT NULL DEFAULT '',
  confidence TEXT NOT NULL DEFAULT '',
  reviewer_user_id TEXT NOT NULL DEFAULT '',
  current_owner_user_id TEXT NOT NULL DEFAULT '',
  assigned_team TEXT NOT NULL DEFAULT '',
  assignments_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_matches_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  missing_questions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  answer_suggestions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  approvals_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  comments_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  timeline_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, review_id)
)`,
	`CREATE INDEX IF NOT EXISTS grc_vendor_questionnaire_reviews_tenant_vendor_idx ON grc_vendor_questionnaire_reviews (tenant_id, vendor_urn, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS grc_vendor_questionnaire_reviews_tenant_vendor_id_idx ON grc_vendor_questionnaire_reviews (tenant_id, vendor_id, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS grc_vendor_questionnaire_reviews_tenant_status_idx ON grc_vendor_questionnaire_reviews (tenant_id, status, updated_at DESC)`,
	`CREATE TABLE IF NOT EXISTS grc_vendor_questionnaire_review_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  review_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor_id TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  version INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS grc_vendor_questionnaire_review_events_review_version_uidx ON grc_vendor_questionnaire_review_events (tenant_id, review_id, version)`,
	`CREATE INDEX IF NOT EXISTS grc_vendor_questionnaire_review_events_review_idx ON grc_vendor_questionnaire_review_events (tenant_id, review_id, version DESC)`,
}

func grcVendorQuestionnaireReviewAdvisoryLockSQL() string {
	return `SELECT pg_advisory_xact_lock(hashtext('grc_vendor_questionnaire_review'), hashtext($1))`
}

func (s *Store) UpsertGRCVendorQuestionnaireReview(ctx context.Context, record ports.GRCVendorQuestionnaireReviewRecord, event ports.GRCVendorQuestionnaireReviewEventRecord) (*ports.GRCVendorQuestionnaireReviewRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCVendorQuestionnaireTables(ctx); err != nil {
		return nil, err
	}
	record = normalizeGRCVendorQuestionnaireReview(record)
	if err := validateGRCVendorQuestionnaireReview(record); err != nil {
		return nil, err
	}
	jsonFields, err := marshalGRCVendorQuestionnaireReviewJSON(record)
	if err != nil {
		return nil, err
	}
	event = normalizeGRCVendorQuestionnaireReviewEvent(record, event)
	eventPayload, err := json.Marshal(emptyStringMap(event.Payload))
	if err != nil {
		return nil, fmt.Errorf("marshal vendor questionnaire review event payload: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin vendor questionnaire review upsert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, grcVendorQuestionnaireReviewAdvisoryLockSQL(), record.TenantID+"\x00"+record.ReviewID); err != nil {
		return nil, fmt.Errorf("lock vendor questionnaire review: %w", err)
	}
	var previousVersion int
	err = tx.QueryRowContext(ctx, `
SELECT COALESCE(MAX(version), 0)
FROM grc_vendor_questionnaire_review_events
WHERE tenant_id = $1 AND review_id = $2`, record.TenantID, record.ReviewID).Scan(&previousVersion)
	if err != nil {
		return nil, fmt.Errorf("load previous vendor questionnaire review event version: %w", err)
	}
	version := previousVersion + 1
	if version <= 0 {
		version = 1
	}
	event.Version = version
	if strings.TrimSpace(event.ID) == "" {
		event.ID = fmt.Sprintf("grc-vendor-questionnaire-%s-%d", record.ReviewID, version)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO grc_vendor_questionnaire_review_events (
  id, tenant_id, review_id, event_type, actor_id, summary, payload_json, version, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, COALESCE(NULLIF($9, TIMESTAMPTZ '0001-01-01 00:00:00+00'), NOW()))`,
		event.ID, record.TenantID, record.ReviewID, event.EventType, event.ActorID, event.Summary, string(eventPayload), event.Version, event.CreatedAt); err != nil {
		return nil, fmt.Errorf("insert vendor questionnaire review event: %w", err)
	}
	// #nosec G201 -- the RETURNING column list is fixed repository code; values remain parameterized.
	upsertReviewSQL := fmt.Sprintf(`
INSERT INTO grc_vendor_questionnaire_reviews (
  tenant_id, review_id, vendor_urn, vendor_id, source_id, runtime_id, upload_id,
  questionnaire_urn, questionnaire_type, title, status, decision, decision_reason,
  confidence, reviewer_user_id, current_owner_user_id, assigned_team,
  assignments_json, evidence_matches_json, missing_questions_json, answer_suggestions_json,
  approvals_json, comments_json, timeline_json, attributes_json, created_at, updated_at
)
VALUES (
  $1, $2, $3, $4, $5, $6, $7,
  $8, $9, $10, $11, $12, $13,
  $14, $15, $16, $17,
  $18::jsonb, $19::jsonb, $20::jsonb, $21::jsonb,
  $22::jsonb, $23::jsonb, $24::jsonb, $25::jsonb,
  COALESCE(NULLIF($26, TIMESTAMPTZ '0001-01-01 00:00:00+00'), NOW()), NOW()
)
ON CONFLICT (tenant_id, review_id)
DO UPDATE SET vendor_urn = EXCLUDED.vendor_urn,
              vendor_id = EXCLUDED.vendor_id,
              source_id = EXCLUDED.source_id,
              runtime_id = EXCLUDED.runtime_id,
              upload_id = EXCLUDED.upload_id,
              questionnaire_urn = EXCLUDED.questionnaire_urn,
              questionnaire_type = EXCLUDED.questionnaire_type,
              title = EXCLUDED.title,
              status = EXCLUDED.status,
              decision = EXCLUDED.decision,
              decision_reason = EXCLUDED.decision_reason,
              confidence = EXCLUDED.confidence,
              reviewer_user_id = EXCLUDED.reviewer_user_id,
              current_owner_user_id = EXCLUDED.current_owner_user_id,
              assigned_team = EXCLUDED.assigned_team,
              assignments_json = EXCLUDED.assignments_json,
              evidence_matches_json = EXCLUDED.evidence_matches_json,
              missing_questions_json = EXCLUDED.missing_questions_json,
              answer_suggestions_json = EXCLUDED.answer_suggestions_json,
              approvals_json = EXCLUDED.approvals_json,
              comments_json = EXCLUDED.comments_json,
              timeline_json = EXCLUDED.timeline_json,
              attributes_json = EXCLUDED.attributes_json,
              updated_at = NOW()
RETURNING %s`, grcVendorQuestionnaireReviewColumns())
	row := tx.QueryRowContext(ctx, upsertReviewSQL,
		record.TenantID, record.ReviewID, record.VendorURN, record.VendorID, record.SourceID, record.RuntimeID, record.UploadID,
		record.QuestionnaireURN, record.QuestionnaireType, record.Title, record.Status, record.Decision, record.DecisionReason,
		record.Confidence, record.ReviewerUserID, record.CurrentOwnerUserID, record.AssignedTeam,
		jsonFields.assignments, jsonFields.evidenceMatches, jsonFields.missingQuestions, jsonFields.answerSuggestions,
		jsonFields.approvals, jsonFields.comments, jsonFields.timeline, jsonFields.attributes, record.CreatedAt)
	result, err := scanGRCVendorQuestionnaireReview(row)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit vendor questionnaire review upsert: %w", err)
	}
	return result, nil
}

func (s *Store) GetGRCVendorQuestionnaireReview(ctx context.Context, filter ports.GRCVendorQuestionnaireReviewFilter) (*ports.GRCVendorQuestionnaireReviewRecord, error) {
	filter.Limit = 1
	records, err := s.ListGRCVendorQuestionnaireReviews(ctx, filter)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, ports.ErrGRCVendorQuestionnaireReviewNotFound
	}
	return records[0], nil
}

func (s *Store) ListGRCVendorQuestionnaireReviews(ctx context.Context, filter ports.GRCVendorQuestionnaireReviewFilter) ([]*ports.GRCVendorQuestionnaireReviewRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCVendorQuestionnaireTables(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1=1"}
	args := []any{}
	addTextFilter(&clauses, &args, "tenant_id", filter.TenantID)
	addTextFilter(&clauses, &args, "review_id", filter.ReviewID)
	addTextFilter(&clauses, &args, "vendor_urn", filter.VendorURN)
	addTextFilter(&clauses, &args, "vendor_id", filter.VendorID)
	addTextFilter(&clauses, &args, "source_id", filter.SourceID)
	addTextFilter(&clauses, &args, "status", filter.Status)
	limit := filter.Limit
	if limit == 0 || limit > 500 {
		limit = 500
	}
	args = append(args, limit)
	// #nosec G201 -- clauses are fixed column predicates and values remain parameterized.
	query := fmt.Sprintf(`
SELECT %s
FROM grc_vendor_questionnaire_reviews
WHERE %s
ORDER BY updated_at DESC, review_id ASC
LIMIT $%d`, grcVendorQuestionnaireReviewColumns(), strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list vendor questionnaire reviews: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.GRCVendorQuestionnaireReviewRecord{}
	for rows.Next() {
		record, err := scanGRCVendorQuestionnaireReview(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) ListGRCVendorQuestionnaireReviewEvents(ctx context.Context, filter ports.GRCVendorQuestionnaireReviewEventFilter) ([]*ports.GRCVendorQuestionnaireReviewEventRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCVendorQuestionnaireTables(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1=1"}
	args := []any{}
	addTextFilter(&clauses, &args, "tenant_id", filter.TenantID)
	addTextFilter(&clauses, &args, "review_id", filter.ReviewID)
	limit := filter.Limit
	if limit == 0 || limit > 500 {
		limit = 500
	}
	args = append(args, limit)
	// #nosec G201 -- clauses are fixed column predicates and values remain parameterized.
	query := fmt.Sprintf(`
SELECT id, tenant_id, review_id, event_type, actor_id, summary, payload_json::text, version, created_at
FROM grc_vendor_questionnaire_review_events
WHERE %s
ORDER BY created_at ASC, version ASC, id ASC
LIMIT $%d`, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list vendor questionnaire review events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.GRCVendorQuestionnaireReviewEventRecord{}
	for rows.Next() {
		record, err := scanGRCVendorQuestionnaireReviewEvent(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) ensureGRCVendorQuestionnaireTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.vendorQuestionnaire, "grc vendor questionnaire review", ensureGRCVendorQuestionnaireStatements)
}

type grcVendorQuestionnaireJSONFields struct {
	assignments       string
	evidenceMatches   string
	missingQuestions  string
	answerSuggestions string
	approvals         string
	comments          string
	timeline          string
	attributes        string
}

func marshalGRCVendorQuestionnaireReviewJSON(record ports.GRCVendorQuestionnaireReviewRecord) (grcVendorQuestionnaireJSONFields, error) {
	marshal := func(label string, value any) (string, error) {
		raw, err := json.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("marshal %s: %w", label, err)
		}
		return string(raw), nil
	}
	var fields grcVendorQuestionnaireJSONFields
	var err error
	if fields.assignments, err = marshal("assignments", record.Assignments); err != nil {
		return fields, err
	}
	if fields.evidenceMatches, err = marshal("evidence matches", record.EvidenceMatches); err != nil {
		return fields, err
	}
	if fields.missingQuestions, err = marshal("missing questions", record.MissingQuestions); err != nil {
		return fields, err
	}
	if fields.answerSuggestions, err = marshal("answer suggestions", record.AnswerSuggestions); err != nil {
		return fields, err
	}
	if fields.approvals, err = marshal("approvals", record.Approvals); err != nil {
		return fields, err
	}
	if fields.comments, err = marshal("comments", record.Comments); err != nil {
		return fields, err
	}
	if fields.timeline, err = marshal("timeline", record.Timeline); err != nil {
		return fields, err
	}
	if fields.attributes, err = marshal("attributes", emptyStringMap(record.Attributes)); err != nil {
		return fields, err
	}
	return fields, nil
}

func scanGRCVendorQuestionnaireReview(row scanner) (*ports.GRCVendorQuestionnaireReviewRecord, error) {
	record := &ports.GRCVendorQuestionnaireReviewRecord{}
	var assignments, evidenceMatches, missingQuestions, answerSuggestions, approvals, comments, timeline, attrs string
	if err := row.Scan(
		&record.TenantID, &record.ReviewID, &record.VendorURN, &record.VendorID, &record.SourceID, &record.RuntimeID, &record.UploadID,
		&record.QuestionnaireURN, &record.QuestionnaireType, &record.Title, &record.Status, &record.Decision, &record.DecisionReason,
		&record.Confidence, &record.ReviewerUserID, &record.CurrentOwnerUserID, &record.AssignedTeam,
		&assignments, &evidenceMatches, &missingQuestions, &answerSuggestions, &approvals, &comments, &timeline, &attrs,
		&record.CreatedAt, &record.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(assignments), &record.Assignments)
	_ = json.Unmarshal([]byte(evidenceMatches), &record.EvidenceMatches)
	_ = json.Unmarshal([]byte(missingQuestions), &record.MissingQuestions)
	_ = json.Unmarshal([]byte(answerSuggestions), &record.AnswerSuggestions)
	_ = json.Unmarshal([]byte(approvals), &record.Approvals)
	_ = json.Unmarshal([]byte(comments), &record.Comments)
	_ = json.Unmarshal([]byte(timeline), &record.Timeline)
	record.Attributes = map[string]string{}
	_ = json.Unmarshal([]byte(attrs), &record.Attributes)
	return record, nil
}

func scanGRCVendorQuestionnaireReviewEvent(row scanner) (*ports.GRCVendorQuestionnaireReviewEventRecord, error) {
	record := &ports.GRCVendorQuestionnaireReviewEventRecord{}
	var payload string
	if err := row.Scan(&record.ID, &record.TenantID, &record.ReviewID, &record.EventType, &record.ActorID, &record.Summary, &payload, &record.Version, &record.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, err
	}
	record.Payload = map[string]string{}
	_ = json.Unmarshal([]byte(payload), &record.Payload)
	return record, nil
}

func grcVendorQuestionnaireReviewColumns() string {
	return `tenant_id, review_id, vendor_urn, vendor_id, source_id, runtime_id, upload_id,
questionnaire_urn, questionnaire_type, title, status, decision, decision_reason,
confidence, reviewer_user_id, current_owner_user_id, assigned_team,
assignments_json::text, evidence_matches_json::text, missing_questions_json::text, answer_suggestions_json::text,
approvals_json::text, comments_json::text, timeline_json::text, attributes_json::text, created_at, updated_at`
}

func normalizeGRCVendorQuestionnaireReview(record ports.GRCVendorQuestionnaireReviewRecord) ports.GRCVendorQuestionnaireReviewRecord {
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.ReviewID = strings.TrimSpace(record.ReviewID)
	record.VendorURN = strings.TrimSpace(record.VendorURN)
	record.VendorID = strings.TrimSpace(record.VendorID)
	record.SourceID = strings.TrimSpace(record.SourceID)
	record.RuntimeID = strings.TrimSpace(record.RuntimeID)
	record.UploadID = strings.TrimSpace(record.UploadID)
	record.QuestionnaireURN = strings.TrimSpace(record.QuestionnaireURN)
	record.QuestionnaireType = strings.TrimSpace(record.QuestionnaireType)
	record.Title = strings.TrimSpace(record.Title)
	record.Status = strings.TrimSpace(record.Status)
	record.Decision = strings.TrimSpace(record.Decision)
	record.DecisionReason = strings.TrimSpace(record.DecisionReason)
	record.Confidence = strings.TrimSpace(record.Confidence)
	record.ReviewerUserID = strings.TrimSpace(record.ReviewerUserID)
	record.CurrentOwnerUserID = strings.TrimSpace(record.CurrentOwnerUserID)
	record.AssignedTeam = strings.TrimSpace(record.AssignedTeam)
	if record.Status == "" {
		record.Status = ports.GRCVendorQuestionnaireStatusIntake
	}
	if record.Decision == "" {
		record.Decision = ports.GRCVendorQuestionnaireDecisionNeedsReview
	}
	if record.Confidence == "" {
		record.Confidence = "low"
	}
	return record
}

func normalizeGRCVendorQuestionnaireReviewEvent(record ports.GRCVendorQuestionnaireReviewRecord, event ports.GRCVendorQuestionnaireReviewEventRecord) ports.GRCVendorQuestionnaireReviewEventRecord {
	event.ID = strings.TrimSpace(event.ID)
	event.TenantID = record.TenantID
	event.ReviewID = record.ReviewID
	event.EventType = strings.TrimSpace(event.EventType)
	event.ActorID = strings.TrimSpace(event.ActorID)
	event.Summary = strings.TrimSpace(event.Summary)
	event.Payload = emptyStringMap(event.Payload)
	if event.EventType == "" {
		event.EventType = ports.GRCVendorQuestionnaireEventProcessed
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	return event
}

func validateGRCVendorQuestionnaireReview(record ports.GRCVendorQuestionnaireReviewRecord) error {
	if record.TenantID == "" || record.ReviewID == "" || record.VendorURN == "" {
		return errors.New("tenant_id, review_id, and vendor_urn are required")
	}
	if !ports.IsGRCVendorQuestionnaireStatus(record.Status) {
		return errors.New("questionnaire status is invalid")
	}
	if !ports.IsGRCVendorQuestionnaireDecision(record.Decision) {
		return errors.New("questionnaire decision is invalid")
	}
	return nil
}
