package postgres

import (
	"context"
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

func TestClaimRecordFromJSONPreservesMissingTimestamps(t *testing.T) {
	payload := `{"id":"claim_1","subject_urn":"urn:cerebro:writer:runtime:writer-jira:ticket:ENG-123","predicate":"status","object_value":"in_progress","claim_type":"attribute","status":"asserted"}`
	record, err := claimRecordFromJSON("writer-jira", "writer", payload)
	if err != nil {
		t.Fatalf("claimRecordFromJSON() error = %v", err)
	}
	if !record.ObservedAt.IsZero() {
		t.Fatalf("record.ObservedAt = %v, want zero time", record.ObservedAt)
	}
	if !record.ValidFrom.IsZero() {
		t.Fatalf("record.ValidFrom = %v, want zero time", record.ValidFrom)
	}
	if !record.ValidTo.IsZero() {
		t.Fatalf("record.ValidTo = %v, want zero time", record.ValidTo)
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
