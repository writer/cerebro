package grcvendor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

type stubGraphStore struct {
	requests     []ports.CypherQueryRequest
	rows         [][]ports.CypherRow
	neighborhood *ports.EntityNeighborhood
	rootURN      string
	limit        int
	err          error
}

func (s *stubGraphStore) Ping(context.Context) error { return s.err }

func (s *stubGraphStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.requests = append(s.requests, request)
	if len(s.rows) == 0 {
		return nil, nil
	}
	rows := s.rows[0]
	s.rows = s.rows[1:]
	return rows, nil
}

func (s *stubGraphStore) GetEntityNeighborhood(_ context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.rootURN = rootURN
	s.limit = limit
	if s.neighborhood == nil {
		return nil, ports.ErrGraphEntityNotFound
	}
	return s.neighborhood, nil
}

func TestListVendorsDerivesPostureAndAppliesFilters(t *testing.T) {
	store := &stubGraphStore{
		rows: [][]ports.CypherRow{{
			vendorRow("urn:cerebro:writer:vendor:vanta:acme", "Acme", `{"vendor_id":"acme","source_system":"vanta","status":"active","category":"analytics","inherent_risk_level":"High","next_security_review_due_date":"2026-01-10","services_provided":"Analytics processing"}`, 2, 1, 0, 1),
			vendorRow("urn:cerebro:writer:vendor:vanta:beta", "Beta", `{"vendor_id":"beta","source_system":"vanta","status":"active","business_owner_user_id":"user-2","residual_risk_level":"Low","next_security_review_due_date":"2026-04-01"}`, 0, 0, 0, 0),
		}},
	}
	service := New(store)
	service.now = func() time.Time { return time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC) }

	vendors, err := service.ListVendors(context.Background(), ListVendorsRequest{
		TenantID:    "writer",
		RiskLevel:   "high",
		ReviewState: "overdue",
		OwnerState:  "missing",
		Limit:       10,
	})
	if err != nil {
		t.Fatalf("ListVendors() error = %v", err)
	}
	if len(vendors) != 1 {
		t.Fatalf("vendors len = %d, want 1: %#v", len(vendors), vendors)
	}
	vendor := vendors[0]
	if vendor.Name != "Acme" || vendor.RiskLevel != "high" || vendor.OwnerState != OwnerStateMissing || vendor.ReviewState != ReviewStateOverdue {
		t.Fatalf("vendor posture = %#v", vendor)
	}
	if vendor.ContractCount != 2 || vendor.SecurityReviewCount != 1 || vendor.AssuranceDocumentCount != 1 {
		t.Fatalf("vendor counts = contracts %d reviews %d docs %d", vendor.ContractCount, vendor.SecurityReviewCount, vendor.AssuranceDocumentCount)
	}
	if len(store.requests) != 1 {
		t.Fatalf("cypher requests = %d, want 1", len(store.requests))
	}
	if store.requests[0].Params["tenant_id"] != "writer" {
		t.Fatalf("tenant param = %#v, want writer", store.requests[0].Params["tenant_id"])
	}
	if store.requests[0].RowLimit != maxVendorLimit {
		t.Fatalf("row limit = %d, want derived filter limit %d", store.requests[0].RowLimit, maxVendorLimit)
	}

	vendor.OpenFindings = 2
	vendor.CriticalFindings = 1
	vendor.EvidenceItems = 3
	summary := Summarize([]Vendor{vendor})
	if summary.TotalVendors != 1 || summary.HighRiskVendors != 1 || summary.OwnerMissingVendors != 1 || summary.ReviewOverdueVendors != 1 {
		t.Fatalf("summary posture = %#v", summary)
	}
	if summary.OpenFindings != 2 || summary.CriticalFindings != 1 || summary.EvidenceItems != 3 {
		t.Fatalf("summary finding counts = %#v", summary)
	}
}

func TestGetVendorReturnsRelationshipsAndGraph(t *testing.T) {
	urn := "urn:cerebro:writer:vendor:vanta:acme"
	store := &stubGraphStore{
		rows: [][]ports.CypherRow{
			{vendorRow(urn, "Acme", `{"vendor_id":"acme","source_system":"vanta","security_owner_user_id":"user-1","residual_risk_level":"Medium","next_security_review_due_date":"2026-02-01"}`, 1, 1, 1, 1)},
			{
				relatedRow("urn:cerebro:writer:contract:vanta:msa", "contract", "MSA", "associated_with"),
				relatedRow("urn:cerebro:writer:security_review:vanta:review-1", "security.review", "Review", "associated_with"),
				relatedRow("urn:cerebro:writer:user:vanta:user-1", "grc.user", "user-1", "owned_by"),
				relatedRow("urn:cerebro:writer:internet_host:acme.example", "internet.host", "acme.example", "has_identifier"),
			},
		},
		neighborhood: &ports.EntityNeighborhood{Root: &ports.NeighborhoodNode{URN: urn, EntityType: "vendor", Label: "Acme"}},
	}
	service := New(store)
	service.now = func() time.Time { return time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC) }

	detail, err := service.GetVendor(context.Background(), VendorDetailRequest{URN: urn, Limit: 100})
	if err != nil {
		t.Fatalf("GetVendor() error = %v", err)
	}
	if detail.Vendor.URN != urn || detail.Vendor.OwnerState != OwnerStateAssigned || detail.Vendor.ReviewState != ReviewStateDueSoon {
		t.Fatalf("vendor detail = %#v", detail.Vendor)
	}
	if len(detail.Relationships.Contracts) != 1 || len(detail.Relationships.SecurityReviews) != 1 || len(detail.Relationships.Owners) != 1 || len(detail.Relationships.Hosts) != 1 {
		t.Fatalf("relationships = %#v", detail.Relationships)
	}
	if store.rootURN != urn || store.limit != relatedLimit {
		t.Fatalf("neighborhood request = %q/%d, want %q/%d", store.rootURN, store.limit, urn, relatedLimit)
	}
}

func TestGetVendorAcceptsVendorID(t *testing.T) {
	urn := "urn:cerebro:writer:vendor:vanta:acme"
	store := &stubGraphStore{
		rows: [][]ports.CypherRow{
			{vendorRow(urn, "Acme", `{"vendor_id":"acme","source_system":"vanta"}`, 0, 0, 0, 0)},
			{},
		},
		neighborhood: &ports.EntityNeighborhood{Root: &ports.NeighborhoodNode{URN: urn, EntityType: "vendor", Label: "Acme"}},
	}
	service := New(store)

	detail, err := service.GetVendor(context.Background(), VendorDetailRequest{VendorID: "acme", TenantID: "writer", Limit: 10})
	if err != nil {
		t.Fatalf("GetVendor() error = %v", err)
	}
	if detail.Vendor.URN != urn {
		t.Fatalf("vendor urn = %q, want %q", detail.Vendor.URN, urn)
	}
	if store.requests[0].Params["vendor_id"] != "acme" || store.requests[0].Params["tenant_id"] != "writer" {
		t.Fatalf("detail params = %#v", store.requests[0].Params)
	}
	if store.rootURN != urn {
		t.Fatalf("neighborhood root = %q, want %q", store.rootURN, urn)
	}
}

func TestGetVendorRejectsMalformedURN(t *testing.T) {
	service := New(&stubGraphStore{})
	_, err := service.GetVendor(context.Background(), VendorDetailRequest{URN: "vendor:acme"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetVendor() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestListDiscoveriesAppliesSourceStatusAndOverlay(t *testing.T) {
	decisionTime := time.Date(2026, 1, 21, 12, 0, 0, 0, time.UTC)
	store := &stubGraphStore{
		rows: [][]ports.CypherRow{{
			discoveryRow("urn:cerebro:writer:vendor_discovery:grc:shadow", "Shadow SaaS", `{"discovered_vendor_id":"shadow","normalized_name":"shadow saas","source_system":"vanta","status":"discovered","category":"analytics"}`),
			discoveryRow("urn:cerebro:writer:vendor_discovery:grc:ignored", "Ignored SaaS", `{"discovered_vendor_id":"ignored","source_system":"vanta","status":"ignored"}`),
		}},
	}
	service := New(store)

	discoveries, err := service.ListDiscoveries(context.Background(), ListDiscoveriesRequest{TenantID: "writer", Status: "discovered", Limit: 10})
	if err != nil {
		t.Fatalf("ListDiscoveries() error = %v", err)
	}
	if len(discoveries) != 1 || discoveries[0].DiscoveryID != "shadow" || discoveries[0].DecisionState != DiscoveryStateDiscovered {
		t.Fatalf("discoveries = %#v", discoveries)
	}
	applied := ApplyDiscoveryDecisions(discoveries, []*ports.GRCVendorDiscoveryDecisionRecord{{
		TenantID:        "writer",
		DiscoveryURN:    discoveries[0].URN,
		Decision:        ports.GRCVendorDiscoveryDecisionLinked,
		LinkedVendorURN: "urn:cerebro:writer:vendor:vanta:shadow",
		Reason:          "Existing vendor row",
		UpdatedBy:       "operator",
		UpdatedAt:       decisionTime,
	}})
	if applied[0].DecisionState != DiscoveryStateLinked || applied[0].LinkedVendorURN == "" || applied[0].DecisionUpdatedAt == nil {
		t.Fatalf("applied discovery = %#v", applied[0])
	}
	filtered := FilterDiscoveriesByDecisionState(applied, DiscoveryStateLinked)
	if len(filtered) != 1 || filtered[0].URN != applied[0].URN {
		t.Fatalf("filtered discoveries = %#v", filtered)
	}
	summary := SummarizeDiscoveries(applied)
	if summary.Linked != 1 || summary.Discovered != 0 {
		t.Fatalf("summary = %#v", summary)
	}
}

func vendorRow(urn string, label string, attrs string, contracts int64, reviews int64, questionnaires int64, documents int64) ports.CypherRow {
	return ports.CypherRow{Values: map[string]any{
		"urn":                      urn,
		"label":                    label,
		"source_id":                "grc",
		"runtime_id":               "writer-vanta",
		"attributes_json":          attrs,
		"contract_count":           contracts,
		"security_review_count":    reviews,
		"questionnaire_count":      questionnaires,
		"assurance_document_count": documents,
	}}
}

func discoveryRow(urn string, label string, attrs string) ports.CypherRow {
	return ports.CypherRow{Values: map[string]any{
		"urn":             urn,
		"label":           label,
		"source_id":       "grc",
		"runtime_id":      "writer-vanta",
		"attributes_json": attrs,
	}}
}

func relatedRow(urn string, entityType string, label string, relation string) ports.CypherRow {
	return ports.CypherRow{Values: map[string]any{
		"urn":             urn,
		"entity_type":     entityType,
		"label":           label,
		"source_id":       "grc",
		"runtime_id":      "writer-vanta",
		"relation":        relation,
		"attributes_json": "{}",
	}}
}
