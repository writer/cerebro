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
	if store.catalogRequest.Filter.TenantID != "tenant-a" || store.catalogRequest.Filter.ExactAgentKey != "urn:cerebro:tenant-a:runtime_evidence:evidence-1" {
		t.Fatalf("catalog request = %#v", store.catalogRequest)
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
	rows           []ports.CypherRow
	request        ports.CypherQueryRequest
	called         bool
	catalogRequest ports.EntityCatalogPageRequest
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

func (s *recordingStore) ListEntities(_ context.Context, request ports.EntityCatalogPageRequest) (*ports.EntityCatalogPage, error) {
	s.called = true
	s.catalogRequest = request
	if len(s.rows) == 0 {
		return &ports.EntityCatalogPage{TenantID: request.Filter.TenantID}, nil
	}
	row := s.rows[0].Values
	attributes, _ := attributesFromRow(row["attributes_json"])
	return &ports.EntityCatalogPage{TenantID: request.Filter.TenantID, Entities: []ports.CatalogEntity{{URN: stringValue(row["urn"]), TenantID: stringValue(row["tenant_id"]), EntityType: stringValue(row["entity_type"]), Label: stringValue(row["label"]), SourceID: stringValue(row["source_id"]), RuntimeID: stringValue(row["runtime_id"]), Attributes: attributes}}}, nil
}
func (s *recordingStore) CountEntityKinds(context.Context, ports.EntityKindCountRequest) (*ports.EntityKindCountPage, error) {
	return nil, nil
}
func (s *recordingStore) ListEntityRelations(context.Context, ports.EntityRelationPageRequest) (*ports.EntityRelationPage, error) {
	return nil, nil
}
