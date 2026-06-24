package graphprovenance

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/ports"
)

func TestServiceGetReturnsProjectionProvenance(t *testing.T) {
	store := &recordingStore{rows: []ports.CypherRow{{
		Values: map[string]any{
			"urn":             "urn:cerebro:tenant-a:runtime_evidence:evidence-1",
			"tenant_id":       "tenant-a",
			"entity_type":     "runtime.evidence",
			"label":           "Evidence",
			"source_id":       "evidence_cas",
			"runtime_id":      "runtime-1",
			"attributes_json": `{"source_event_id":"evt-1","last_observed_at":"2026-06-16T00:00:00Z"}`,
		},
	}}}

	response, err := New(store).Get(context.Background(), Request{URN: "urn:cerebro:tenant-a:runtime_evidence:evidence-1"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if response.ProjectionClass != "evidence" || response.ProjectionReason != "evidence_reference" {
		t.Fatalf("projection = class:%q reason:%q", response.ProjectionClass, response.ProjectionReason)
	}
	if len(response.Provenance.SourceURNs) != 2 || response.Provenance.SourceURNs[1] != "event:evt-1" {
		t.Fatalf("source urns = %#v", response.Provenance.SourceURNs)
	}
	if len(response.Provenance.FreshnessSignals) != 1 {
		t.Fatalf("freshness = %#v", response.Provenance.FreshnessSignals)
	}
	if store.request.Params["tenant_id"] != "tenant-a" || store.request.Params["urn"] != "urn:cerebro:tenant-a:runtime_evidence:evidence-1" {
		t.Fatalf("query params = %#v", store.request.Params)
	}
}

func TestTenantIDFromURNRejectsMalformedURN(t *testing.T) {
	if got := TenantIDFromURN("not-a-urn"); got != "" {
		t.Fatalf("TenantIDFromURN malformed = %q, want empty", got)
	}
	if got := TenantIDFromURN("urn:cerebro:tenant-a:asset"); got != "" {
		t.Fatalf("TenantIDFromURN kind-only = %q, want empty", got)
	}
	if got := TenantIDFromURN("urn:cerebro:tenant-a:asset:one"); got != "tenant-a" {
		t.Fatalf("TenantIDFromURN = %q, want tenant-a", got)
	}
}

func TestServiceGetRejectsKindOnlyURN(t *testing.T) {
	store := &recordingStore{}
	_, err := New(store).Get(context.Background(), Request{URN: "urn:cerebro:tenant-a:asset"})
	if !errors.Is(err, graphquery.ErrInvalidRequest) {
		t.Fatalf("Get() error = %v, want ErrInvalidRequest", err)
	}
	if store.called {
		t.Fatal("Get() queried store for kind-only URN")
	}
}

type recordingStore struct {
	rows    []ports.CypherRow
	request ports.CypherQueryRequest
	called  bool
}

func (s *recordingStore) Ping(context.Context) error { return nil }

func (s *recordingStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, ports.ErrGraphEntityNotFound
}

func (s *recordingStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.called = true
	s.request = request
	return s.rows, nil
}
