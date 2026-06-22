package graphfacts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

type stubClaimStore struct {
	claims      []*ports.ClaimRecord
	lastRequest ports.ListClaimsRequest
	err         error
}

func (s *stubClaimStore) Ping(context.Context) error { return nil }

func (s *stubClaimStore) UpsertClaim(context.Context, *ports.ClaimRecord) (*ports.ClaimRecord, error) {
	return nil, errors.New("not implemented")
}

func (s *stubClaimStore) ListClaims(_ context.Context, request ports.ListClaimsRequest) ([]*ports.ClaimRecord, error) {
	s.lastRequest = request
	if s.err != nil {
		return nil, s.err
	}
	return s.claims, nil
}

func TestListReturnsGraphFactsFromClaims(t *testing.T) {
	observedAt := time.Date(2026, 6, 22, 14, 0, 0, 0, time.UTC)
	store := &stubClaimStore{claims: []*ports.ClaimRecord{{
		ID:            "fact-1",
		RuntimeID:     "runtime-1",
		TenantID:      "writer",
		SubjectURN:    "urn:cerebro:writer:identity:alice",
		Predicate:     "can_admin",
		ObjectURN:     "urn:cerebro:writer:aws_account:prod",
		ClaimType:     "relation",
		Status:        "asserted",
		SourceEventID: "event-1",
		ObservedAt:    observedAt,
		Attributes:    map[string]string{"confidence": "high", "empty": " ", "private_context": "should-not-leak"},
	}}}
	service := New(store)

	response, err := service.List(context.Background(), ListRequest{
		TenantID:  "writer",
		RuntimeID: "runtime-1",
		Predicate: "can_admin",
		Limit:     1000,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if store.lastRequest.Limit != maxListLimit {
		t.Fatalf("ListClaims limit = %d, want %d", store.lastRequest.Limit, maxListLimit)
	}
	if got := len(response.Facts); got != 1 {
		t.Fatalf("len(Facts) = %d, want 1", got)
	}
	fact := response.Facts[0]
	if fact.ID != "fact-1" || fact.Confidence != "high" || fact.ObservedAt != "2026-06-22T14:00:00Z" {
		t.Fatalf("unexpected fact: %#v", fact)
	}
	if _, ok := fact.Attributes["empty"]; ok {
		t.Fatalf("blank attribute was not trimmed: %#v", fact.Attributes)
	}
	if _, ok := fact.Attributes["private_context"]; ok {
		t.Fatalf("sensitive attribute was not filtered: %#v", fact.Attributes)
	}
}

func TestListRequiresTenantOrRuntimeScope(t *testing.T) {
	_, err := New(&stubClaimStore{}).List(context.Background(), ListRequest{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("List() error = %v, want ErrInvalidRequest", err)
	}
}

func TestExplainReturnsEdgeEvidenceAndFreshness(t *testing.T) {
	store := &stubClaimStore{claims: []*ports.ClaimRecord{{
		ID:            "fact-1",
		RuntimeID:     "runtime-1",
		TenantID:      "writer",
		SubjectURN:    "urn:cerebro:writer:identity:alice",
		Predicate:     "can_admin",
		ObjectURN:     "urn:cerebro:writer:aws_account:prod",
		ClaimType:     "relation",
		Status:        "asserted",
		SourceEventID: "event-1",
		Attributes: map[string]string{
			"evidence_urn": "urn:cerebro:writer:evidence:1, urn:cerebro:writer:evidence:2",
		},
	}}}
	response, err := New(store).Explain(context.Background(), ExplainRequest{TenantID: "writer", FactID: "fact-1"})
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if response.Edge == nil || response.Edge.Relation != "can_admin" {
		t.Fatalf("Edge = %#v, want can_admin edge", response.Edge)
	}
	if got := len(response.Evidence); got != 3 {
		t.Fatalf("len(Evidence) = %d, want source event plus 2 evidence URNs", got)
	}
	if response.Freshness.Status != "asserted" {
		t.Fatalf("Freshness.Status = %q, want asserted", response.Freshness.Status)
	}
}

func TestExplainRequiresFactOrEdgeSelector(t *testing.T) {
	_, err := New(&stubClaimStore{}).Explain(context.Background(), ExplainRequest{TenantID: "writer"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Explain() error = %v, want ErrInvalidRequest", err)
	}
}
