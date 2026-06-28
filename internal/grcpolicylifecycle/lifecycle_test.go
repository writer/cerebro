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
	foundLifecycleEvent := false
	for _, entityType := range entityRequest.Params["entity_types"].([]string) {
		if entityType == "policy.lifecycle.event" {
			foundLifecycleEvent = true
			break
		}
	}
	if !foundLifecycleEvent {
		t.Fatalf("entity types = %#v, want policy.lifecycle.event", entityRequest.Params["entity_types"])
	}
	if entityRequest.Params["risk_scenario_attr_fragment"] != grcPolicyLifecycleRiskScenarioAttrFragment {
		t.Fatalf("entity params = %#v, want risk scenario filter", entityRequest.Params)
	}
	documentFragments, ok := entityRequest.Params["document_attr_fragments"].([]string)
	if !ok || !stringSliceContains(documentFragments, `"policy_id":"`) || !stringSliceContains(documentFragments, `"risk_scenario_id":"`) {
		t.Fatalf("entity params = %#v, want document attr filters", entityRequest.Params)
	}
	if !strings.Contains(entityRequest.Query, "entity_type <> 'claim'") || !strings.Contains(entityRequest.Query, "entity_type <> 'document'") {
		t.Fatalf("entity query %q does not filter broad claim/document types", entityRequest.Query)
	}
	relationRequest := store.requests[1]
	if relationRequest.Params["risk_scenario_attr_fragment"] != grcPolicyLifecycleRiskScenarioAttrFragment {
		t.Fatalf("relation params = %#v, want risk scenario filter", relationRequest.Params)
	}
	anchorTypes, ok := relationRequest.Params["policy_anchor_entity_types"].([]string)
	if !ok || !stringSliceContains(anchorTypes, "policy.version") {
		t.Fatalf("relation params = %#v, want policy anchor types", relationRequest.Params)
	}
	if !strings.Contains(relationRequest.Query, "left.entity_type <> 'claim'") || !strings.Contains(relationRequest.Query, "right.entity_type <> 'document'") {
		t.Fatalf("relation query %q does not filter broad claim/document types", relationRequest.Query)
	}
}

func stringSliceContains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
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
		{ID: "date-only", AcceptedAt: "2026-01-10"},
		{ID: "pending", Status: "pending", DueAt: "2026-02-15"},
		{ID: "overdue", Status: "pending", DueAt: "2026-01-15"},
		{ID: "sent", Status: "sent"},
		{ID: "stale-open-date", Status: "sent", AcceptedAt: "2026-01-10"},
		{ID: "rejected", Status: "rejected", DueAt: "2026-01-01"},
		{ID: "expired", Status: "expired", DueAt: "2026-01-01"},
		{ID: "stale-date", Status: "rejected", AcceptedAt: "2026-01-10"},
	}, now)

	if summary.Total != 6 || summary.Accepted != 2 || summary.Pending != 3 || summary.Overdue != 1 {
		t.Fatalf("rollup = %#v, want closed unaccepted attestations excluded", summary)
	}
}

func TestWorkQueueIncludesUnknownOpenAttestationStatus(t *testing.T) {
	items := grcPolicyLifecycleWorkQueue([]grcPolicyLifecyclePolicy{{
		ID:    "access",
		Title: "Access",
		Attestations: []grcPolicyAcceptanceItem{
			{URN: "urn:attestation:sent", Status: "sent"},
			{URN: "urn:attestation:stale-open-date", Status: "sent", AcceptedAt: "2026-01-10"},
			{URN: "urn:attestation:missing-status"},
			{URN: "urn:attestation:rejected", Status: "rejected"},
		},
	}}, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if len(items) != 2 || items[0].RecordURN != "urn:attestation:sent" || items[1].RecordURN != "urn:attestation:stale-open-date" {
		t.Fatalf("work queue = %+v, want only open non-empty attestation status", items)
	}
}

func TestMissingReviewStatusDoesNotCreateOverdueWork(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if grcPolicyOverdue("2026-01-15", "", now) {
		t.Fatalf("missing lifecycle status should not be overdue")
	}
	policy := grcPolicyLifecyclePolicy{
		ID:    "access",
		Title: "Access",
		Reviews: []grcPolicyReviewItem{
			{URN: "urn:review:missing-status", ReviewDueAt: "2026-01-15"},
		},
	}
	summary := grcPolicyLifecycleSummaryFrom([]grcPolicyLifecyclePolicy{policy}, nil, nil, nil, nil, now)
	if summary.OverdueReviews != 0 {
		t.Fatalf("summary = %+v, want missing-status review excluded from overdue count", summary)
	}
	if items := grcPolicyLifecycleWorkQueue([]grcPolicyLifecyclePolicy{policy}, now); len(items) != 0 {
		t.Fatalf("work queue = %+v, want missing-status review excluded", items)
	}
}

func TestMissingDocumentStatusDoesNotCreateReviewWork(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	document := grcPolicyDocumentItem{
		ID:              "risk-register",
		URN:             "urn:document:risk-register",
		Title:           "Risk Register",
		DocumentClass:   "risk_register",
		NextReviewDueAt: "2026-01-15",
	}

	if grcPolicyDocumentDueForReview(document, now) {
		t.Fatalf("missing document status should not be due for review")
	}
	summary := grcPolicyLifecycleSummaryFrom(nil, nil, []grcPolicyDocumentItem{document}, nil, nil, now)
	if summary.DocumentsDueForReview != 0 {
		t.Fatalf("summary = %+v, want missing-status document excluded from due count", summary)
	}
	if items := grcPolicyDocumentWorkQueue([]grcPolicyDocumentItem{document}, nil, now); len(items) != 0 {
		t.Fatalf("document work queue = %+v, want missing-status document excluded", items)
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

func TestRelationEnrichmentDoesNotAttachRelationOnlyLifecycleChild(t *testing.T) {
	policy := policyLifecycleTestRow("urn:source-a:policy:access", "policy", "Access", map[string]string{
		"policy_id":   "access",
		"policy_type": "policy",
	})
	foreignVersion := policyLifecycleTestRow("urn:source-b:policy_version:v1", "policy.version", "Foreign Access v1", map[string]string{
		"policy_id":         "access",
		"policy_version_id": "v1",
	})
	relation := policyLifecycleTestRelation(foreignVersion, fabriccontract.RelationBelongsTo, nil, policy)

	response := grcPolicyLifecycleFromGraph([]ports.CypherRow{policy}, []ports.CypherRow{relation}, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if len(response.Policies) != 1 {
		t.Fatalf("policies = %+v, want one in-scope policy", response.Policies)
	}
	if len(response.Policies[0].Versions) != 0 {
		t.Fatalf("versions = %+v, want relation-only lifecycle child excluded", response.Policies[0].Versions)
	}
}

func TestBuildActionEventCreatesNormalizedLifecycleEvent(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 30, 0, 0, time.UTC)
	event, response, err := BuildActionEvent(ActionRequest{
		Action:          "approval.approve",
		TenantID:        "writer",
		SourceID:        "grc",
		RuntimeID:       "rt-1",
		PolicyID:        "access",
		PolicyVersionID: "access-2",
		RecordID:        "approval-1",
		ActorUserID:     "reviewer@example.com",
		Reason:          "Ready for publish",
		IdempotencyKey:  "approval-1-approved",
	}, now)
	if err != nil {
		t.Fatalf("BuildActionEvent() error = %v", err)
	}
	if event.GetKind() != "grc.policy_approval" || event.GetSchemaRef() != policyLifecycleSchemaRef {
		t.Fatalf("event kind/schema = %q/%q", event.GetKind(), event.GetSchemaRef())
	}
	if event.GetAttributes()["status"] != "approved" || event.GetAttributes()["approver_user_id"] != "reviewer@example.com" {
		t.Fatalf("event attributes = %#v", event.GetAttributes())
	}
	if response.EventID == "" || response.Status != "approved" {
		t.Fatalf("response = %#v", response)
	}
}

func TestLifecycleAggregateIncludesEventsActionsDiffsAndReminderPlan(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	policy := policyLifecycleTestRow("urn:cerebro:writer:policy:policyops:policy:access", "policy", "Access", map[string]string{
		"policy_id":   "access",
		"policy_type": "policy",
	})
	version := policyLifecycleTestRow("urn:cerebro:writer:policy_version:policyops:access-2", "policy.version", "Access v2", map[string]string{
		"policy_id":         "access",
		"policy_version_id": "access-2",
		"status":            "draft",
		"version":           "2",
		"change_summary":    "Updated owner review.",
		"diff_summary":      "Added review cadence.",
		"created_at":        "2026-01-20",
	})
	attestation := policyLifecycleTestRow("urn:cerebro:writer:policy_acceptance:policyops:attest-1", "policy.acceptance", "Access attestation", map[string]string{
		"acceptance_id":     "attest-1",
		"policy_id":         "access",
		"policy_version_id": "access-2",
		"status":            "pending",
		"due_at":            "2026-01-15",
	})
	event := policyLifecycleTestRow("urn:cerebro:writer:policy_lifecycle_event:policyops:event-1", "policy.lifecycle.event", "Approval event", map[string]string{
		"lifecycle_event_id": "event-1",
		"policy_id":          "access",
		"policy_version_id":  "access-2",
		"action":             "approval.request",
		"status":             "requested",
		"occurred_at":        "2026-01-20T10:00:00Z",
	})

	response := grcPolicyLifecycleFromGraph([]ports.CypherRow{policy, version, attestation, event}, nil, now)
	if response.Summary.LifecycleEvents != 1 || response.Summary.NextReminders != 1 {
		t.Fatalf("summary = %+v, want lifecycle events and reminder plan", response.Summary)
	}
	if len(response.Policies) != 1 {
		t.Fatalf("policies len = %d", len(response.Policies))
	}
	got := response.Policies[0]
	if len(got.Events) != 1 || len(got.Actions) == 0 || len(got.VersionDiffs) != 1 || len(got.ReminderPlan) != 1 {
		t.Fatalf("policy aggregate = %+v", got)
	}
	if len(response.VersionDiffs) != 1 || len(response.ReminderPlan) != 1 {
		t.Fatalf("response diffs/reminders = %+v/%+v", response.VersionDiffs, response.ReminderPlan)
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
