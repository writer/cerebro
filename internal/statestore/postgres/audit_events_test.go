package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestAuditEventFilterBuildersParameterizeValues(t *testing.T) {
	clauses := []string{}
	args := []any{}
	addAuditEventExactFilter(&clauses, &args, "action", "read' OR true --")
	addAuditEventTextFilter(&clauses, &args, `50%_done`)
	joined := strings.Join(clauses, " ")
	if strings.Contains(joined, "OR true") || len(args) != 2 {
		t.Fatalf("filters were not parameterized: clauses=%q args=%v", joined, args)
	}
	if got := args[1]; got != `%50\%\_done%` {
		t.Fatalf("text filter argument = %q", got)
	}
}

func TestAuditEventStoreRejectsUnconfiguredDatabase(t *testing.T) {
	store := &Store{}
	if err := store.ProjectAuditEvent(context.Background(), auditEventProjection(1, auditEventTestRecord("event-1", "tenant-a", time.Now()))); err == nil {
		t.Fatal("ProjectAuditEvent() error = nil")
	}
	if _, err := store.ListAuditEvents(context.Background(), ports.AuditEventQueryV1{}); err == nil {
		t.Fatal("ListAuditEvents() error = nil")
	}
}

func TestAuditEventUniqueViolation(t *testing.T) {
	if !auditEventUniqueViolation(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("auditEventUniqueViolation() = false")
	}
	if auditEventUniqueViolation(errors.New("other")) {
		t.Fatal("auditEventUniqueViolation(other) = true")
	}
}

func TestAuditEventKeysetUsesDeterministicEventIDCollation(t *testing.T) {
	if auditEventIDKeysetExpression != `event_id COLLATE "C"` {
		t.Fatalf("auditEventIDKeysetExpression = %q", auditEventIDKeysetExpression)
	}
	statements := strings.Join(ensureAuditEventStatements, "\n")
	for _, required := range []string{
		`event_id TEXT COLLATE "C" NOT NULL`,
		`occurred_at DESC, event_id COLLATE "C" DESC`,
		`DROP INDEX IF EXISTS platform_audit_events_action_idx`,
		`platform_audit_events_action_lower_idx ON platform_audit_events (tenant_id, LOWER(action), occurred_at DESC, event_id COLLATE "C" DESC)`,
		`platform_audit_events_outcome_lower_idx ON platform_audit_events (tenant_id, LOWER(outcome), occurred_at DESC, event_id COLLATE "C" DESC)`,
		`platform_audit_events_service_lower_idx ON platform_audit_events (tenant_id, LOWER(service), occurred_at DESC, event_id COLLATE "C" DESC)`,
	} {
		if !strings.Contains(statements, required) {
			t.Fatalf("audit event schema is missing %q", required)
		}
	}
}

func TestAuditEventPersistenceAndKeysetPagination(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run audit event persistence integration test")
	}
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	tenantID := "audit-event-test-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	otherTenantID := tenantID + "-other"
	collationTenantID := tenantID + "-collation"
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(ctx, `DELETE FROM platform_audit_events WHERE tenant_id IN ($1, $2, $3)`, tenantID, otherTenantID, collationTenantID)
	})
	now := time.Now().UTC().Truncate(time.Microsecond)
	sequenceBase := uint64(time.Now().UnixNano())
	for index, id := range []string{"event-1", "event-2", "event-3"} {
		event := auditEventTestRecord(id, tenantID, now.Add(-time.Duration(index)*time.Minute))
		if err := store.ProjectAuditEvent(ctx, auditEventProjection(sequenceBase+uint64(index), event)); err != nil {
			t.Fatalf("ProjectAuditEvent(%s) error = %v", id, err)
		}
	}
	if err := store.ProjectAuditEvent(ctx, auditEventProjection(sequenceBase, auditEventTestRecord("event-1", tenantID, now))); err != nil {
		t.Fatalf("idempotent ProjectAuditEvent() error = %v", err)
	}
	conflict := auditEventTestRecord("event-1", tenantID, now)
	conflict.Action = "changed.action"
	if err := store.ProjectAuditEvent(ctx, auditEventProjection(sequenceBase, conflict)); !errors.Is(err, ports.ErrAuditEventConflict) {
		t.Fatalf("conflicting ProjectAuditEvent() error = %v", err)
	}
	if err := store.ProjectAuditEvent(ctx, auditEventProjection(sequenceBase+3, auditEventTestRecord("event-other", otherTenantID, now))); err != nil {
		t.Fatalf("other tenant ProjectAuditEvent() error = %v", err)
	}
	query := ports.AuditEventQueryV1{TenantID: tenantID, After: now.Add(-time.Hour), Before: now, Limit: 2}
	first, err := store.ListAuditEvents(ctx, query)
	if err != nil {
		t.Fatalf("ListAuditEvents(first) error = %v", err)
	}
	if len(first.Events) != 2 || !first.HasMore || first.Events[0].ID != "event-1" || first.Events[1].ID != "event-2" {
		t.Fatalf("first page = %+v", first)
	}
	query.PageBeforeOccurredAt = first.Events[1].OccurredAt
	query.PageBeforeID = first.Events[1].ID
	second, err := store.ListAuditEvents(ctx, query)
	if err != nil {
		t.Fatalf("ListAuditEvents(second) error = %v", err)
	}
	if len(second.Events) != 1 || second.HasMore || second.Events[0].ID != "event-3" {
		t.Fatalf("second page = %+v", second)
	}

	for index, id := range []string{"event-Z", "event-a", "event-ä"} {
		event := auditEventTestRecord(id, collationTenantID, now)
		if err := store.ProjectAuditEvent(ctx, auditEventProjection(sequenceBase+10+uint64(index), event)); err != nil {
			t.Fatalf("ProjectAuditEvent(%s) error = %v", id, err)
		}
	}
	collationQuery := ports.AuditEventQueryV1{TenantID: collationTenantID, After: now.Add(-time.Hour), Before: now, Limit: 2}
	collationFirst, err := store.ListAuditEvents(ctx, collationQuery)
	if err != nil {
		t.Fatalf("ListAuditEvents(collation first) error = %v", err)
	}
	if len(collationFirst.Events) != 2 || !collationFirst.HasMore || collationFirst.Events[0].ID != "event-ä" || collationFirst.Events[1].ID != "event-a" {
		t.Fatalf("collation first page = %+v", collationFirst)
	}
	collationQuery.PageBeforeOccurredAt = collationFirst.Events[1].OccurredAt
	collationQuery.PageBeforeID = collationFirst.Events[1].ID
	collationSecond, err := store.ListAuditEvents(ctx, collationQuery)
	if err != nil {
		t.Fatalf("ListAuditEvents(collation second) error = %v", err)
	}
	if len(collationSecond.Events) != 1 || collationSecond.HasMore || collationSecond.Events[0].ID != "event-Z" {
		t.Fatalf("collation second page = %+v", collationSecond)
	}
}

func auditEventProjection(sequence uint64, event *ports.AuditEventV1) ports.AuditEventProjectionV1 {
	return ports.AuditEventProjectionV1{SourceSequence: sequence, Event: event}
}

func auditEventTestRecord(id string, tenantID string, occurredAt time.Time) *ports.AuditEventV1 {
	return &ports.AuditEventV1{
		ID: id, TenantID: tenantID, Action: "record.read", Category: "access",
		OccurredAt: occurredAt, Outcome: ports.AuditEventOutcomeSuccess,
		Actor:    &ports.AuditEventActorV1{ID: "actor-1", Kind: "service", Label: "Service actor"},
		Resource: &ports.AuditEventResourceV1{ID: "resource-1", Type: "record", Label: "Record"},
		Service:  "api", Summary: "Read a record", TraceID: "trace-1", RequestID: "request-1",
	}
}
