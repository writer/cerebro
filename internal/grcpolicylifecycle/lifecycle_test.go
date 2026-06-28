package grcpolicylifecycle

import (
	"context"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestMissingLifecycleStatusDoesNotCreateWork(t *testing.T) {
	if grcPolicyPendingStatus("") {
		t.Fatalf("empty lifecycle status should not be pending work")
	}
	if grcPolicyExceptionOpen("") {
		t.Fatalf("empty exception status should not be open work")
	}
}

func TestBuildAppliesEntityLimitPerLifecycleType(t *testing.T) {
	store := &recordingPolicyLifecycleStore{}
	_, err := Build(context.Background(), store, Scope{
		TenantID:  "writer",
		SourceID:  "grc",
		RuntimeID: "rt-1",
		Limit:     25,
	})
	if err != nil {
		t.Fatalf("Build error = %v", err)
	}
	if len(store.requests) != 2 {
		t.Fatalf("requests len = %d, want entity and relation reads", len(store.requests))
	}
	entityRequest := store.requests[0]
	if entityRequest.Params["type_limit"] != 25 {
		t.Fatalf("entity params = %#v, want per-type limit", entityRequest.Params)
	}
	wantRowLimit := 25 * len(grcPolicyLifecycleEntityTypes)
	if entityRequest.RowLimit != wantRowLimit {
		t.Fatalf("entity row limit = %d, want %d", entityRequest.RowLimit, wantRowLimit)
	}
	if !strings.Contains(entityRequest.Query, "UNWIND $entity_types AS entity_type") || !strings.Contains(entityRequest.Query, "LIMIT $type_limit") {
		t.Fatalf("entity query %q does not apply a per-type limit", entityRequest.Query)
	}
}

func TestEntityTypeLimitStaysWithinGraphRowCeiling(t *testing.T) {
	typeLimit := grcPolicyLifecycleEntityTypeLimit(500)
	if got := grcPolicyLifecycleEntityRowLimit(typeLimit); got > ports.MaxCypherQueryRows {
		t.Fatalf("entity row limit = %d, want <= %d", got, ports.MaxCypherQueryRows)
	}
}

type recordingPolicyLifecycleStore struct {
	requests []ports.CypherQueryRequest
}

func (s *recordingPolicyLifecycleStore) Ping(context.Context) error {
	return nil
}

func (s *recordingPolicyLifecycleStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, ports.ErrGraphEntityNotFound
}

func (s *recordingPolicyLifecycleStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.requests = append(s.requests, request)
	return nil, nil
}
