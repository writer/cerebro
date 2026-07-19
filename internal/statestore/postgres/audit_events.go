package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/writer/cerebro/internal/auditevents"
	"github.com/writer/cerebro/internal/ports"
)

var _ ports.AuditEventReader = (*Store)(nil)
var _ ports.AuditEventProjectionWriter = (*Store)(nil)

var ensureAuditEventStatements = []string{
	`CREATE TABLE IF NOT EXISTS platform_audit_events (
  tenant_id TEXT NOT NULL,
  event_id TEXT COLLATE "C" NOT NULL,
  source_sequence BIGINT NOT NULL,
  event_digest TEXT NOT NULL,
  action TEXT NOT NULL,
  actor_id TEXT NOT NULL DEFAULT '',
  actor_kind TEXT NOT NULL DEFAULT '',
  actor_label TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT '',
  duration_ms BIGINT,
  occurred_at TIMESTAMPTZ NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied', 'unknown')),
  request_id TEXT NOT NULL DEFAULT '',
  resource_id TEXT NOT NULL DEFAULT '',
  resource_type TEXT NOT NULL DEFAULT '',
  resource_label TEXT NOT NULL DEFAULT '',
  service TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  trace_id TEXT NOT NULL DEFAULT '',
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (source_sequence),
  CHECK (source_sequence > 0),
  CHECK (duration_ms IS NULL OR duration_ms >= 0)
)`,
	`CREATE INDEX IF NOT EXISTS platform_audit_events_time_idx ON platform_audit_events (tenant_id, occurred_at DESC, event_id COLLATE "C" DESC)`,
	`DROP INDEX IF EXISTS platform_audit_events_action_idx`,
	`DROP INDEX IF EXISTS platform_audit_events_outcome_idx`,
	`DROP INDEX IF EXISTS platform_audit_events_service_idx`,
	`CREATE INDEX IF NOT EXISTS platform_audit_events_action_lower_idx ON platform_audit_events (tenant_id, LOWER(action), occurred_at DESC, event_id COLLATE "C" DESC)`,
	`CREATE INDEX IF NOT EXISTS platform_audit_events_outcome_lower_idx ON platform_audit_events (tenant_id, LOWER(outcome), occurred_at DESC, event_id COLLATE "C" DESC)`,
	`CREATE INDEX IF NOT EXISTS platform_audit_events_service_lower_idx ON platform_audit_events (tenant_id, LOWER(service), occurred_at DESC, event_id COLLATE "C" DESC)`,
}

const auditEventColumns = `event_id, tenant_id, action, actor_id, actor_kind, actor_label,
category, duration_ms, occurred_at, outcome, request_id, resource_id, resource_type,
resource_label, service, summary, trace_id`

const auditEventIDKeysetExpression = `event_id COLLATE "C"`

func (s *Store) ensureAuditEventTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.platform.auditEvents, "platform audit events", ensureAuditEventStatements)
}

// ProjectAuditEvent inserts one normalized read-model record derived from the
// durable append log. Reusing an event ID or source sequence for different
// allowlisted content fails instead of rewriting projected history.
func (s *Store) ProjectAuditEvent(ctx context.Context, input ports.AuditEventProjectionV1) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if input.SourceSequence == 0 || input.SourceSequence > math.MaxInt64 {
		return fmt.Errorf("%w: source sequence is outside the supported range", ports.ErrAuditEventInvalid)
	}
	sourceSequence := int64(input.SourceSequence) // #nosec G115 -- bounded above by MaxInt64.
	event, err := auditevents.Normalize(input.Event)
	if err != nil {
		return err
	}
	digest, err := auditevents.Digest(event)
	if err != nil {
		return err
	}
	if err := s.ensureAuditEventTables(ctx); err != nil {
		return err
	}
	actorID, actorKind, actorLabel := "", "", ""
	if event.Actor != nil {
		actorID, actorKind, actorLabel = event.Actor.ID, event.Actor.Kind, event.Actor.Label
	}
	resourceID, resourceType, resourceLabel := "", "", ""
	if event.Resource != nil {
		resourceID, resourceType, resourceLabel = event.Resource.ID, event.Resource.Type, event.Resource.Label
	}
	var duration any
	if event.DurationMS != nil {
		duration = *event.DurationMS
	}
	var recordedID string
	err = s.db.QueryRowContext(ctx, `
INSERT INTO platform_audit_events (
  tenant_id, event_id, source_sequence, event_digest, action, actor_id, actor_kind, actor_label,
  category, duration_ms, occurred_at, outcome, request_id, resource_id,
  resource_type, resource_label, service, summary, trace_id
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
ON CONFLICT (tenant_id, event_id) DO UPDATE
SET event_digest = platform_audit_events.event_digest
WHERE platform_audit_events.event_digest = EXCLUDED.event_digest
  AND platform_audit_events.source_sequence = EXCLUDED.source_sequence
RETURNING event_id`, event.TenantID, event.ID, sourceSequence, digest, event.Action, actorID, actorKind, actorLabel,
		event.Category, duration, event.OccurredAt, event.Outcome, event.RequestID, resourceID,
		resourceType, resourceLabel, event.Service, event.Summary, event.TraceID).Scan(&recordedID)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %s", ports.ErrAuditEventConflict, event.ID)
	}
	if auditEventUniqueViolation(err) {
		return fmt.Errorf("%w: source sequence %d", ports.ErrAuditEventConflict, input.SourceSequence)
	}
	if err != nil {
		return fmt.Errorf("project audit event: %w", err)
	}
	return nil
}

func auditEventUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}

// ListAuditEvents returns one deterministic descending keyset page for a
// single tenant and immutable time window.
func (s *Store) ListAuditEvents(ctx context.Context, query ports.AuditEventQueryV1) (ports.AuditEventPageV1, error) {
	if s == nil || s.db == nil {
		return ports.AuditEventPageV1{}, errors.New("postgres is not configured")
	}
	if err := auditevents.ValidateQuery(query); err != nil {
		return ports.AuditEventPageV1{}, err
	}
	if err := s.ensureAuditEventTables(ctx); err != nil {
		return ports.AuditEventPageV1{}, err
	}
	clauses := []string{"tenant_id = $1", "occurred_at >= $2", "occurred_at <= $3"}
	args := []any{strings.TrimSpace(query.TenantID), query.After.UTC(), query.Before.UTC()}
	addAuditEventExactFilter(&clauses, &args, "action", query.Action)
	addAuditEventActorFilter(&clauses, &args, query.Actor)
	addAuditEventExactFilter(&clauses, &args, "outcome", query.Outcome)
	addAuditEventExactFilter(&clauses, &args, "resource_type", query.ResourceType)
	addAuditEventExactFilter(&clauses, &args, "service", query.Service)
	addAuditEventExactFilter(&clauses, &args, "trace_id", query.TraceID)
	addAuditEventTextFilter(&clauses, &args, query.Query)
	if !query.PageBeforeOccurredAt.IsZero() {
		args = append(args, query.PageBeforeOccurredAt.UTC(), strings.TrimSpace(query.PageBeforeID))
		clauses = append(clauses, fmt.Sprintf("(occurred_at < $%d OR (occurred_at = $%d AND %s < $%d))", len(args)-1, len(args)-1, auditEventIDKeysetExpression, len(args)))
	}
	args = append(args, query.Limit+1)
	// #nosec G201 -- the columns and predicates are fixed; all values are parameterized.
	statement := fmt.Sprintf("SELECT %s FROM platform_audit_events WHERE %s ORDER BY occurred_at DESC, %s DESC LIMIT $%d", auditEventColumns, strings.Join(clauses, " AND "), auditEventIDKeysetExpression, len(args))
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return ports.AuditEventPageV1{}, fmt.Errorf("list audit events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	events := make([]*ports.AuditEventV1, 0, query.Limit)
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return ports.AuditEventPageV1{}, fmt.Errorf("scan audit event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return ports.AuditEventPageV1{}, fmt.Errorf("list audit events: %w", err)
	}
	hasMore := uint64(len(events)) > uint64(query.Limit)
	if hasMore {
		events = events[:query.Limit]
	}
	return ports.AuditEventPageV1{Events: events, HasMore: hasMore}, nil
}

func addAuditEventExactFilter(clauses *[]string, args *[]any, column string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	*args = append(*args, value)
	*clauses = append(*clauses, fmt.Sprintf("LOWER(%s) = LOWER($%d)", column, len(*args)))
}

func addAuditEventActorFilter(clauses *[]string, args *[]any, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	*args = append(*args, value)
	*clauses = append(*clauses, fmt.Sprintf("(LOWER(actor_id) = LOWER($%d) OR LOWER(actor_label) = LOWER($%d))", len(*args), len(*args)))
}

func addAuditEventTextFilter(clauses *[]string, args *[]any, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	value = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
	*args = append(*args, "%"+value+"%")
	placeholder := len(*args)
	*clauses = append(*clauses, fmt.Sprintf("(action ILIKE $%d ESCAPE '\\' OR actor_label ILIKE $%d ESCAPE '\\' OR resource_label ILIKE $%d ESCAPE '\\' OR summary ILIKE $%d ESCAPE '\\')", placeholder, placeholder, placeholder, placeholder))
}

func scanAuditEvent(row scanner) (*ports.AuditEventV1, error) {
	var event ports.AuditEventV1
	var actor ports.AuditEventActorV1
	var resource ports.AuditEventResourceV1
	var duration sql.NullInt64
	if err := row.Scan(
		&event.ID, &event.TenantID, &event.Action,
		&actor.ID, &actor.Kind, &actor.Label,
		&event.Category, &duration, &event.OccurredAt, &event.Outcome, &event.RequestID,
		&resource.ID, &resource.Type, &resource.Label,
		&event.Service, &event.Summary, &event.TraceID,
	); err != nil {
		return nil, err
	}
	if actor.ID != "" || actor.Kind != "" || actor.Label != "" {
		event.Actor = &actor
	}
	if resource.ID != "" || resource.Type != "" || resource.Label != "" {
		event.Resource = &resource
	}
	if duration.Valid {
		event.DurationMS = &duration.Int64
	}
	return auditevents.Normalize(&event)
}
