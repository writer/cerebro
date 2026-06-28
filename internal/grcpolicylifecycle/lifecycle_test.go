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
	for _, fragment := range []string{
		`"document_class":"control_narrative"`,
		`"document_class":"exception_register"`,
		`"document_class":"training_material"`,
		`"document_class":"waiver_register"`,
	} {
		if !stringSliceContains(documentFragments, fragment) {
			t.Fatalf("document fragments = %#v, want %s", documentFragments, fragment)
		}
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
	summary := grcPolicyLifecycleSummaryFrom([]grcPolicyLifecyclePolicy{policy}, nil, nil, nil, nil, nil, now)
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
	summary := grcPolicyLifecycleSummaryFrom(nil, nil, []grcPolicyDocumentItem{document}, nil, nil, nil, now)
	if summary.DocumentsDueForReview != 0 {
		t.Fatalf("summary = %+v, want missing-status document excluded from due count", summary)
	}
	if items := grcPolicyDocumentWorkQueue([]grcPolicyDocumentItem{document}, nil, now); len(items) != 0 {
		t.Fatalf("document work queue = %+v, want missing-status document excluded", items)
	}
}

func TestDraftDocumentDoesNotCreateReviewWork(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	document := grcPolicyDocumentItem{
		ID:              "secure-development-draft",
		URN:             "urn:document:secure-development-draft",
		Title:           "Secure Development Draft",
		DocumentClass:   "policy",
		Status:          "draft",
		NextReviewDueAt: "2026-01-15",
	}

	if grcPolicyDocumentDueForReview(document, now) {
		t.Fatalf("draft document should not be due for review")
	}
	summary := grcPolicyLifecycleSummaryFrom(nil, nil, []grcPolicyDocumentItem{document}, nil, nil, nil, now)
	if summary.DraftDocuments != 1 || summary.DocumentsDueForReview != 0 {
		t.Fatalf("summary = %+v, want one draft document and no due review", summary)
	}
	items := grcPolicyDocumentWorkQueue([]grcPolicyDocumentItem{document}, nil, now)
	if len(items) != 1 || items[0].Action != "Review draft document" {
		t.Fatalf("document work queue = %+v, want only draft review work", items)
	}
}

func TestHighRiskSummaryCountsOpenRisksOnly(t *testing.T) {
	summary := grcPolicyLifecycleSummaryFrom(nil, nil, nil, []grcPolicyRiskRegisterItem{
		{ID: "open-high", Status: "open", ResidualRisk: "high"},
		{ID: "closed-critical", Status: "closed", ResidualRisk: "critical"},
		{ID: "accepted-high", Status: "accepted", InherentRisk: "high"},
		{ID: "completed-high", Status: "completed", ResidualRisk: "high"},
		{ID: "acknowledged-high", Status: "acknowledged", ResidualRisk: "high"},
		{ID: "expired-high", Status: "expired", ResidualRisk: "high"},
		{ID: "rejected-high", Status: "rejected", ResidualRisk: "high"},
		{ID: "mitigated-high", Status: "mitigated", ResidualRisk: "high"},
		{ID: "remediated-high", Status: "remediated", ResidualRisk: "high"},
		{ID: "transferred-high", Status: "transferred", ResidualRisk: "high"},
		{ID: "open-medium", Status: "open", ResidualRisk: "medium"},
	}, nil, nil, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))

	if summary.OpenRisks != 2 || summary.HighRisks != 1 {
		t.Fatalf("risk summary = %+v, want two open risks and one open high risk", summary)
	}
}

func TestCompletedRiskDoesNotCreateWork(t *testing.T) {
	items := grcPolicyDocumentWorkQueue(nil, []grcPolicyRiskRegisterItem{
		{
			ID:             "completed-high",
			URN:            "urn:risk:completed-high",
			Title:          "Completed high risk",
			Status:         "completed",
			ResidualRisk:   "high",
			TreatmentDueAt: "2026-01-15",
		},
	}, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))

	if len(items) != 0 {
		t.Fatalf("risk work queue = %+v, want completed risk excluded", items)
	}
}

func TestRiskWorkQueueIncludesLinkedPolicy(t *testing.T) {
	items := grcPolicyDocumentWorkQueue(nil, []grcPolicyRiskRegisterItem{
		{
			ID:           "privileged-access",
			URN:          "urn:risk:privileged-access",
			Title:        "Privileged access drift",
			Status:       "open",
			ResidualRisk: "high",
			Policies: []grcPolicyDocumentRef{
				{ID: "access", URN: "urn:policy:access", Title: "Access Control Policy"},
			},
		},
	}, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))

	if len(items) != 1 {
		t.Fatalf("risk work queue = %+v, want one high-risk work item", items)
	}
	if items[0].RiskID != "privileged-access" || items[0].PolicyID != "access" {
		t.Fatalf("risk work item = %+v, want linked risk and policy IDs", items[0])
	}
}

func TestGovernanceGapsClassifyPolicyDocumentsAndRisks(t *testing.T) {
	document := grcPolicyDocumentItem{
		ID:            "secure-development",
		URN:           "urn:document:secure-development",
		Title:         "Secure Development Policy",
		DocumentClass: "policy",
		Status:        "approved",
	}
	draftDocument := grcPolicyDocumentItem{
		ID:            "draft-policy",
		URN:           "urn:document:draft-policy",
		Title:         "Draft Policy",
		DocumentClass: "policy",
		Status:        "draft",
	}
	missingStatusDocument := grcPolicyDocumentItem{
		ID:              "statusless-document",
		URN:             "urn:document:statusless-document",
		Title:           "Statusless document",
		DocumentClass:   "record",
		NextReviewDueAt: "2026-12-31",
		Policies: []grcPolicyDocumentRef{
			{ID: "secure-development", URN: "urn:policy:secure-development", Title: "Secure Development Policy"},
		},
	}
	openRisk := grcPolicyRiskRegisterItem{
		ID:           "privileged-access",
		URN:          "urn:risk:privileged-access",
		Title:        "Privileged access drift",
		Status:       "open",
		ResidualRisk: "high",
	}
	closedRisk := grcPolicyRiskRegisterItem{
		ID:           "closed-risk",
		URN:          "urn:risk:closed-risk",
		Title:        "Closed risk",
		Status:       "closed",
		ResidualRisk: "high",
	}

	gaps := grcPolicyGovernanceGaps([]grcPolicyDocumentItem{document, draftDocument, missingStatusDocument}, []grcPolicyRiskRegisterItem{openRisk, closedRisk})

	if !grcPolicyGapExists(gaps, "document", "secure-development", "Missing owner") ||
		!grcPolicyGapExists(gaps, "document", "secure-development", "Missing review date") ||
		!grcPolicyGapExists(gaps, "document", "secure-development", "No linked policy") ||
		!grcPolicyGapExists(gaps, "document", "secure-development", "No mapped controls") {
		t.Fatalf("document gaps = %+v, want owner, review date, policy, and controls", gaps)
	}
	for _, reason := range []string{"Missing owner", "Missing treatment", "Missing treatment date", "Missing review date", "No source document", "No linked policy", "No mapped controls", "No evidence"} {
		if !grcPolicyGapExists(gaps, "risk", "privileged-access", reason) {
			t.Fatalf("risk gaps = %+v, want %q", gaps, reason)
		}
	}
	if grcPolicyGapExists(gaps, "risk", "closed-risk", "Missing owner") {
		t.Fatalf("gaps = %+v, want closed risk excluded", gaps)
	}
	if grcPolicyGapExists(gaps, "document", "draft-policy", "Missing owner") {
		t.Fatalf("gaps = %+v, want draft document excluded", gaps)
	}
	if !grcPolicyGapExists(gaps, "document", "statusless-document", "Missing owner") {
		t.Fatalf("gaps = %+v, want missing-status document included for metadata completeness", gaps)
	}
	if len(gaps) == 0 || gaps[0].Subject != "risk" || gaps[0].Severity != "high" {
		t.Fatalf("first gap = %+v, want high risk gap first", gaps)
	}

	summary := grcPolicyLifecycleSummaryFrom(nil, nil, []grcPolicyDocumentItem{document, missingStatusDocument}, []grcPolicyRiskRegisterItem{openRisk, closedRisk}, nil, gaps, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if summary.GovernanceGaps != len(gaps) || summary.PolicyDocumentGaps != 5 || summary.RiskRegisterGaps != 8 {
		t.Fatalf("summary = %+v, want governance gap rollups", summary)
	}
}

func TestGovernanceGapEventsApplyStateTraceAndRollups(t *testing.T) {
	document := grcPolicyDocumentItem{
		ID:            "secure-development",
		URN:           "urn:document:secure-development",
		Title:         "Secure Development Policy",
		DocumentClass: "policy",
		Status:        "approved",
	}
	gapID := document.URN + ":gap:owner"
	events := []grcPolicyLifecycleEventItem{{
		ID:         "event-1",
		RecordURN:  gapID,
		RecordType: "governance.gap",
		Action:     "governance_gap.assign_owner",
		Status:     "in_progress",
		Actor:      "owner@example.com",
		Reason:     "Assigned for cleanup",
		OccurredAt: "2026-02-02T12:00:00Z",
		Attributes: map[string]string{
			"gap_id":            gapID,
			"gap_state":         "in_progress",
			"assigned_user_ids": "owner@example.com",
			"due_at":            "2026-02-15",
		},
	}}

	gaps := grcPolicyGovernanceGapsFor([]grcPolicyDocumentItem{document}, nil, grcPolicyGovernanceRules("baseline"), events, time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC))

	var ownerGap grcPolicyGovernanceGap
	for _, gap := range gaps {
		if gap.ID == gapID {
			ownerGap = gap
			break
		}
	}
	if ownerGap.ID == "" {
		t.Fatalf("gaps = %+v, want owner gap", gaps)
	}
	if ownerGap.GapState != "in_progress" || ownerGap.Owner != "owner@example.com" || ownerGap.DueAt != "2026-02-15" {
		t.Fatalf("owner gap = %+v, want assigned in-progress gap", ownerGap)
	}
	if ownerGap.RuleID != "document.owner" || ownerGap.ActionID != "governance_gap.assign_owner" || !stringSliceContains(ownerGap.MissingFields, "owner") || ownerGap.SourceFields["policy_count"] != "0" {
		t.Fatalf("owner gap metadata = %+v, want rule, action, missing field, and source fields", ownerGap)
	}
	if len(ownerGap.Trace) != 1 || ownerGap.Trace[0].EventID != "event-1" {
		t.Fatalf("trace = %+v, want event trace", ownerGap.Trace)
	}
	summary := grcPolicyLifecycleSummaryFrom(nil, nil, []grcPolicyDocumentItem{document}, nil, nil, gaps, time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC))
	if summary.InProgressGaps != 1 || summary.OpenGovernanceGaps != len(gaps)-1 || summary.HighGovernanceGaps != 0 {
		t.Fatalf("summary = %+v, want state counts", summary)
	}
	rollups := grcPolicyGovernanceGapRollupsFrom(gaps)
	if len(rollups.ByState) == 0 || rollups.ByState[0].Key != "open" || len(rollups.ByOwner) == 0 {
		t.Fatalf("rollups = %+v, want state and owner groups", rollups)
	}
}

func TestStrictGovernanceRulesRequireDocumentEvidence(t *testing.T) {
	document := grcPolicyDocumentItem{
		ID:              "secure-development",
		URN:             "urn:document:secure-development",
		Title:           "Secure Development Policy",
		DocumentClass:   "policy",
		Status:          "approved",
		Owner:           "owner@example.com",
		NextReviewDueAt: "2026-12-31",
		Policies: []grcPolicyDocumentRef{
			{ID: "secure-development", URN: "urn:policy:secure-development", Title: "Secure Development Policy"},
		},
		Controls: []grcPolicyControlRef{{URN: "urn:control:CC6.1", ControlID: "CC6.1"}},
	}

	baseline := grcPolicyGovernanceGapsFor([]grcPolicyDocumentItem{document}, nil, grcPolicyGovernanceRules("baseline"), nil, time.Time{})
	strict := grcPolicyGovernanceGapsFor([]grcPolicyDocumentItem{document}, nil, grcPolicyGovernanceRules("strict"), nil, time.Time{})

	if len(baseline) != 0 {
		t.Fatalf("baseline gaps = %+v, want none", baseline)
	}
	if len(strict) != 1 || strict[0].RuleID != "document.evidence" || strict[0].ActionID != "governance_gap.attach_evidence" {
		t.Fatalf("strict gaps = %+v, want document evidence gap", strict)
	}
}

func TestGovernanceGapLifecycleEventsDoNotCreateUnmappedPolicy(t *testing.T) {
	document := policyLifecycleTestRow("urn:document:secure-development", "document", "Secure Development Policy", map[string]string{
		"document_id":    "secure-development",
		"document_class": "policy",
		"status":         "approved",
	})
	gapEvent := policyLifecycleTestRow("urn:cerebro:writer:policy_lifecycle_event:policyops:gap-event-1", "policy.lifecycle.event", "Gap acknowledged", map[string]string{
		"lifecycle_event_id": "gap-event-1",
		"record_type":        "governance.gap",
		"record_urn":         "urn:document:secure-development:gap:owner",
		"gap_id":             "urn:document:secure-development:gap:owner",
		"gap_state":          "acknowledged",
		"action":             "governance_gap.acknowledge",
		"status":             "acknowledged",
		"occurred_at":        "2026-02-02T12:00:00Z",
	})

	response := grcPolicyLifecycleFromGraph([]ports.CypherRow{document, gapEvent}, nil, time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC))

	if len(response.Policies) != 0 {
		t.Fatalf("policies = %+v, want no unmapped policy for gap event", response.Policies)
	}
	if !grcPolicyGapHasState(response.GovernanceGaps, "urn:document:secure-development:gap:owner", "acknowledged") {
		t.Fatalf("gaps = %+v, want acknowledged owner gap", response.GovernanceGaps)
	}
}

func grcPolicyGapExists(gaps []grcPolicyGovernanceGap, subject string, subjectID string, reason string) bool {
	for _, gap := range gaps {
		if gap.Subject == subject && gap.SubjectID == subjectID && gap.Reason == reason {
			return true
		}
	}
	return false
}

func grcPolicyGapHasState(gaps []grcPolicyGovernanceGap, id string, state string) bool {
	for _, gap := range gaps {
		if gap.ID == id && gap.GapState == state {
			return true
		}
	}
	return false
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
		Action: "approval.approve",
		ActionRequestScope: ActionRequestScope{
			TenantID:       "writer",
			SourceID:       "grc",
			RuntimeID:      "rt-1",
			ActorUserID:    "reviewer@example.com",
			IdempotencyKey: "approval-1-approved",
		},
		ActionRequestTarget: ActionRequestTarget{
			PolicyID:        "access",
			PolicyVersionID: "access-2",
			RecordID:        "approval-1",
		},
		ActionRequestState: ActionRequestState{
			Reason: "Ready for publish",
		},
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

func TestBuildActionEventCreatesGovernanceGapEvent(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 30, 0, 0, time.UTC)
	gapID := "urn:document:secure-development:gap:owner"
	event, response, err := BuildActionEvent(ActionRequest{
		Action: "governance_gap.assign_owner",
		ActionRequestScope: ActionRequestScope{
			TenantID:       "writer",
			SourceID:       "grc",
			RuntimeID:      "rt-1",
			ActorUserID:    "operator@example.com",
			IdempotencyKey: "assign-owner",
		},
		ActionRequestTarget: ActionRequestTarget{
			GapID:     gapID,
			RecordURN: gapID,
		},
		ActionRequestState: ActionRequestState{
			Reason: "Owner found",
		},
		ActionRequestAssignments: ActionRequestAssignments{
			Assignees: []string{"owner@example.com"},
		},
	}, now)
	if err != nil {
		t.Fatalf("BuildActionEvent() error = %v", err)
	}
	attrs := event.GetAttributes()
	if event.GetKind() != "grc.policy_lifecycle_event" || attrs["gap_id"] != gapID || attrs["gap_state"] != "in_progress" || attrs["assigned_user_ids"] != "owner@example.com" {
		t.Fatalf("event kind/attrs = %q/%#v, want governance gap lifecycle event", event.GetKind(), attrs)
	}
	if attrs["record_type"] != "governance.gap" || attrs["record_urn"] != gapID || attrs["state_updated_at"] == "" {
		t.Fatalf("event attrs = %#v, want gap record metadata", attrs)
	}
	if response.Status != "in_progress" || response.EventKind != "grc.policy_lifecycle_event" {
		t.Fatalf("response = %#v, want governance gap response", response)
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
