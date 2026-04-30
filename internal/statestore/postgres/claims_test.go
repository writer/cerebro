package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestUpsertClaimRejectsNilClaim(t *testing.T) {
	store := &Store{}
	if _, err := store.UpsertClaim(context.Background(), nil); err == nil {
		t.Fatal("UpsertClaim() error = nil, want non-nil")
	}
}

func TestClaimMessageTimeAllowsNilTimestamp(t *testing.T) {
	if got := claimMessageTime(nil); !got.IsZero() {
		t.Fatalf("claimMessageTime(nil) = %v, want zero", got)
	}
}

func TestUpsertClaimRejectsMissingPredicate(t *testing.T) {
	store := &Store{}
	_, err := store.UpsertClaim(context.Background(), &ports.ClaimRecord{
		ID:         "claim_1",
		RuntimeID:  "writer-jira",
		TenantID:   "writer",
		SubjectURN: "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123",
		ClaimType:  "attribute",
		Status:     "asserted",
	})
	if err == nil {
		t.Fatal("UpsertClaim() error = nil, want non-nil")
	}
}

func TestUpsertClaimRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	_, err := store.UpsertClaim(context.Background(), &ports.ClaimRecord{
		ID:          "claim_1",
		RuntimeID:   "writer-jira",
		TenantID:    "writer",
		SubjectURN:  "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123",
		Predicate:   "status",
		ObjectValue: "in_progress",
		ClaimType:   "attribute",
		Status:      "asserted",
	})
	if err == nil {
		t.Fatal("UpsertClaim() error = nil, want non-nil")
	}
}

func TestListClaimsRejectsMissingRuntimeID(t *testing.T) {
	store := &Store{}
	if _, err := store.ListClaims(context.Background(), ports.ListClaimsRequest{}); err == nil {
		t.Fatal("ListClaims() error = nil, want non-nil")
	}
}

func TestListClaimsRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if _, err := store.ListClaims(context.Background(), ports.ListClaimsRequest{RuntimeID: "writer-jira"}); err == nil {
		t.Fatal("ListClaims() error = nil, want non-nil")
	}
}

func TestClaimSchemaScopesPrimaryKeyByTenantAndRuntime(t *testing.T) {
	create := ensureClaimStatements[0]
	if !strings.Contains(create, "PRIMARY KEY (tenant_id, runtime_id, id)") {
		t.Fatalf("claims schema primary key does not include tenant/runtime/id:\n%s", create)
	}
	migration := ensureClaimStatements[1]
	if !strings.Contains(migration, "LOCK TABLE claims IN ACCESS EXCLUSIVE MODE") ||
		!strings.Contains(migration, "IF pk_cols IS DISTINCT FROM ARRAY['tenant_id', 'runtime_id', 'id']::TEXT[] THEN") ||
		!strings.Contains(migration, "ARRAY['id']") ||
		!strings.Contains(migration, "DROP CONSTRAINT IF EXISTS") {
		t.Fatalf("claims schema migration does not conditionally replace legacy id-only primary key:\n%s", migration)
	}
}

func TestClaimRecordFromJSONRestoresRefsAndTimes(t *testing.T) {
	payload := `{"id":"claim_1","subject_urn":"urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123","subject_ref":{"urn":"urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123","entity_type":"ticket","label":"ENG-123"},"predicate":"assigned_to","object_urn":"urn:cerebro:writer:runtime:writer-jira:user:acct:42","object_ref":{"urn":"urn:cerebro:writer:runtime:writer-jira:user:acct:42","entity_type":"user","label":"Alice"},"claim_type":"relation","status":"asserted","observed_at":"2026-04-23T12:00:00Z","attributes":{"source":"jira"}}`
	record, err := claimRecordFromJSON("writer-jira", "writer", payload)
	if err != nil {
		t.Fatalf("claimRecordFromJSON() error = %v", err)
	}
	if got := record.RuntimeID; got != "writer-jira" {
		t.Fatalf("record.RuntimeID = %q, want writer-jira", got)
	}
	if got := record.SubjectRef.GetEntityType(); got != "ticket" {
		t.Fatalf("record.SubjectRef.EntityType = %q, want ticket", got)
	}
	if got := record.ObjectRef.GetLabel(); got != "Alice" {
		t.Fatalf("record.ObjectRef.Label = %q, want Alice", got)
	}
	if got := record.ObservedAt; !got.Equal(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("record.ObservedAt = %v, want 2026-04-23T12:00:00Z", got)
	}
	if got := record.Attributes["source"]; got != "jira" {
		t.Fatalf("record.Attributes[source] = %q, want jira", got)
	}
}

func TestClaimJSONIncludesTimestampsForRoundTrip(t *testing.T) {
	payload, err := claimJSON(&ports.ClaimRecord{
		ID:          "claim_1",
		RuntimeID:   "writer-jira",
		TenantID:    "writer",
		SubjectURN:  "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123",
		SubjectRef:  &cerebrov1.EntityRef{Urn: "urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123", EntityType: "ticket", Label: "ENG-123"},
		Predicate:   "status",
		ObjectValue: "in_progress",
		ClaimType:   "attribute",
		Status:      "asserted",
		ObservedAt:  timestamppb.New(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)).AsTime(),
	})
	if err != nil {
		t.Fatalf("claimJSON() error = %v", err)
	}
	record, err := claimRecordFromJSON("writer-jira", "writer", payload)
	if err != nil {
		t.Fatalf("claimRecordFromJSON() error = %v", err)
	}
	if got := record.ObjectValue; got != "in_progress" {
		t.Fatalf("record.ObjectValue = %q, want in_progress", got)
	}
	if got := record.ObservedAt; !got.Equal(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("record.ObservedAt = %v, want 2026-04-23T12:00:00Z", got)
	}
}
