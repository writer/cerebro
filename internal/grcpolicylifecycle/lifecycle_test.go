package grcpolicylifecycle

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/fabriccontract"
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

func TestFinalizeUsesLatestDatedVersion(t *testing.T) {
	policy := grcPolicyLifecyclePolicy{
		Versions: []grcPolicyVersionItem{
			{ID: "draft", URN: "urn:policy:version:draft", Version: "2", Status: "draft"},
			{ID: "approved", URN: "urn:policy:version:approved", Version: "1", Status: "approved", CreatedAt: "2026-01-15"},
		},
	}

	grcPolicyFinalize(&policy, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))

	if policy.LatestVersion != "1" || policy.VersionStatus != "approved" {
		t.Fatalf("latest version = %q/%q, want dated approved version", policy.LatestVersion, policy.VersionStatus)
	}
	if policy.Versions[0].ID != "approved" {
		t.Fatalf("first version = %q, want dated version before dateless draft", policy.Versions[0].ID)
	}
}

func TestAcceptanceRollupExcludesClosedUnacceptedAttestations(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	summary := grcPolicyAcceptanceRollup([]grcPolicyAcceptanceItem{
		{ID: "accepted", Status: "accepted"},
		{ID: "pending", Status: "pending", DueAt: "2026-02-15"},
		{ID: "overdue", Status: "pending", DueAt: "2026-01-15"},
		{ID: "sent", Status: "sent"},
		{ID: "rejected", Status: "rejected", DueAt: "2026-01-01"},
		{ID: "expired", Status: "expired", DueAt: "2026-01-01"},
		{ID: "stale-date", Status: "rejected", AcceptedAt: "2026-01-10"},
	}, now)

	if summary.Total != 4 || summary.Accepted != 1 || summary.Pending != 2 || summary.Overdue != 1 {
		t.Fatalf("rollup = %#v, want closed unaccepted attestations excluded", summary)
	}
}

func TestWorkQueueIncludesUnknownOpenAttestationStatus(t *testing.T) {
	items := grcPolicyLifecycleWorkQueue([]grcPolicyLifecyclePolicy{{
		ID:    "access",
		Title: "Access",
		Attestations: []grcPolicyAcceptanceItem{
			{URN: "urn:attestation:sent", Status: "sent"},
			{URN: "urn:attestation:missing-status"},
			{URN: "urn:attestation:rejected", Status: "rejected"},
		},
	}}, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if len(items) != 1 || items[0].RecordURN != "urn:attestation:sent" {
		t.Fatalf("work queue = %+v, want only open non-empty attestation status", items)
	}
}

func TestExceptionRollupSkipsMissingStatus(t *testing.T) {
	summary := grcPolicyExceptionRollup([]grcPolicyExceptionItem{
		{ID: "missing", Status: "", ExpiresAt: "2026-03-01"},
		{ID: "active", Status: "active", ExpiresAt: "2026-03-01"},
	}, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if summary.Active != 1 || summary.Expired != 0 || summary.Expiring != 1 {
		t.Fatalf("exception summary = %+v, want missing status skipped", summary)
	}
}

func TestFinalizeUsesSortedReviewMetadata(t *testing.T) {
	policy := grcPolicyLifecyclePolicy{
		Reviews: []grcPolicyReviewItem{
			{ID: "later", ReviewDueAt: "2026-06-15", Cadence: "quarterly", Reviewers: []string{"later@example.com"}},
			{ID: "earlier", ReviewDueAt: "2026-01-15", Cadence: "monthly", Reviewers: []string{"earlier@example.com"}},
		},
	}

	grcPolicyFinalize(&policy, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))

	if policy.Reviews[0].ID != "earlier" {
		t.Fatalf("first review = %q, want earliest due review", policy.Reviews[0].ID)
	}
	if policy.Reviewer != "earlier@example.com" || policy.ReviewCadence != "monthly" || policy.NextReviewDueAt != "2026-01-15" {
		t.Fatalf("review metadata = %q/%q/%q, want earliest review metadata", policy.Reviewer, policy.ReviewCadence, policy.NextReviewDueAt)
	}
}

func TestPolicyIDFallsBackToURNWhenPolicyIDMissing(t *testing.T) {
	left := policyLifecycleTestRow("urn:source-a:policy:policy-1", "policy", "Access A", map[string]string{"policy_type": "policy"})
	right := policyLifecycleTestRow("urn:source-b:policy:policy-1", "policy", "Access B", map[string]string{"policy_type": "policy"})

	response := grcPolicyLifecycleFromGraph([]ports.CypherRow{left, right}, nil, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if len(response.Policies) != 2 {
		t.Fatalf("policies len = %d, want both same-suffix policies", len(response.Policies))
	}
	ids := map[string]struct{}{}
	for _, policy := range response.Policies {
		ids[policy.ID] = struct{}{}
	}
	for _, want := range []string{"urn:source-a:policy:policy-1", "urn:source-b:policy:policy-1"} {
		if _, ok := ids[want]; !ok {
			t.Fatalf("policy ids = %+v, missing %q", ids, want)
		}
	}
}

func TestRelationEnrichmentDoesNotPromoteRelationOnlyPolicy(t *testing.T) {
	version := policyLifecycleTestRow("urn:source-a:policy_version:v1", "policy.version", "Access v1", map[string]string{
		"policy_id":         "access",
		"policy_version_id": "v1",
	})
	foreignPolicy := policyLifecycleTestRow("urn:source-b:policy:access", "policy", "Foreign Access", map[string]string{"policy_type": "policy"})
	relation := policyLifecycleTestRelation(version, fabriccontract.RelationBelongsTo, nil, foreignPolicy)

	response := grcPolicyLifecycleFromGraph([]ports.CypherRow{version}, []ports.CypherRow{relation}, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if len(response.Policies) != 1 {
		t.Fatalf("policies = %+v, want one policy created from in-scope version", response.Policies)
	}
	if response.Policies[0].URN == "urn:source-b:policy:access" {
		t.Fatalf("relation-only foreign policy promoted to top-level policy: %+v", response.Policies[0])
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

func policyLifecycleTestRow(urn string, entityType string, label string, attrs map[string]string) ports.CypherRow {
	rawAttrs, _ := json.Marshal(attrs)
	return ports.CypherRow{Values: map[string]any{
		"urn":             urn,
		"tenant_id":       "writer",
		"source_id":       "grc",
		"runtime_id":      "writer-grc",
		"entity_type":     entityType,
		"label":           label,
		"attributes_json": string(rawAttrs),
	}}
}

func policyLifecycleTestRelation(left ports.CypherRow, relation string, attrs map[string]string, right ports.CypherRow) ports.CypherRow {
	values := map[string]any{}
	for key, value := range left.Values {
		values["left_"+key] = value
	}
	for key, value := range right.Values {
		values["right_"+key] = value
	}
	rawAttrs, _ := json.Marshal(attrs)
	values["relation"] = relation
	values["relation_attributes_json"] = string(rawAttrs)
	return ports.CypherRow{Values: values}
}
