package postgres

import (
	"context"
	"testing"

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
