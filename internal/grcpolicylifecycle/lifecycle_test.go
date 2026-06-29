package grcpolicylifecycle

import (
	"context"
	"encoding/json"
	"errors"
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
		ID:    "risk-register",
		URN:   "urn:document:risk-register",
		Title: "Risk Register",
		grcPolicyDocumentMetadata: grcPolicyDocumentMetadata{
			DocumentClass:   "risk_register",
			NextReviewDueAt: "2026-01-15",
		},
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
		ID:    "secure-development-draft",
		URN:   "urn:document:secure-development-draft",
		Title: "Secure Development Draft",
		grcPolicyDocumentMetadata: grcPolicyDocumentMetadata{
			DocumentClass:   "policy",
			Status:          "draft",
			NextReviewDueAt: "2026-01-15",
		},
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
		ID:    "secure-development",
		URN:   "urn:document:secure-development",
		Title: "Secure Development Policy",
		grcPolicyDocumentMetadata: grcPolicyDocumentMetadata{
			DocumentClass: "policy",
			Status:        "approved",
		},
	}
	draftDocument := grcPolicyDocumentItem{
		ID:    "draft-policy",
		URN:   "urn:document:draft-policy",
		Title: "Draft Policy",
		grcPolicyDocumentMetadata: grcPolicyDocumentMetadata{
			DocumentClass: "policy",
			Status:        "draft",
		},
	}
	missingStatusDocument := grcPolicyDocumentItem{
		ID:    "statusless-document",
		URN:   "urn:document:statusless-document",
		Title: "Statusless document",
		grcPolicyDocumentMetadata: grcPolicyDocumentMetadata{
			DocumentClass:   "record",
			NextReviewDueAt: "2026-12-31",
		},
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
	if gap, ok := grcPolicyGapFor(gaps, "document", "secure-development", "No mapped controls"); !ok || gap.Severity != "medium" {
		t.Fatalf("document controls gap = %+v, want medium severity", gap)
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
		ID:    "secure-development",
		URN:   "urn:document:secure-development",
		Title: "Secure Development Policy",
		grcPolicyDocumentMetadata: grcPolicyDocumentMetadata{
			DocumentClass: "policy",
			Status:        "approved",
		},
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
	}, {
		ID:         "event-2",
		RecordURN:  gapID,
		RecordType: "governance.gap",
		Action:     "governance_gap.assign_owner",
		Status:     "in_progress",
		Actor:      "operator@example.com",
		Reason:     "Reassigned for follow-up",
		OccurredAt: "2026-02-03T12:00:00Z",
		Attributes: map[string]string{
			"gap_id":            gapID,
			"gap_state":         "in_progress",
			"assigned_user_ids": "new-owner@example.com",
			"due_at":            "2026-02-20",
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
	if ownerGap.GapState != "in_progress" || ownerGap.Owner != "new-owner@example.com" || ownerGap.DueAt != "2026-02-20" {
		t.Fatalf("owner gap = %+v, want reassigned in-progress gap", ownerGap)
	}
	if ownerGap.RuleID != "document.owner" || ownerGap.ActionID != "governance_gap.assign_owner" || !stringSliceContains(ownerGap.MissingFields, "owner") || ownerGap.SourceFields["policy_count"] != "0" {
		t.Fatalf("owner gap metadata = %+v, want rule, action, missing field, and source fields", ownerGap)
	}
	if len(ownerGap.Trace) != 2 || ownerGap.Trace[1].EventID != "event-2" {
		t.Fatalf("trace = %+v, want reassignment event trace", ownerGap.Trace)
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

func TestGovernanceGapAssignOwnerEventsReassignOwner(t *testing.T) {
	document := grcPolicyDocumentItem{
		ID:    "secure-development",
		URN:   "urn:document:secure-development",
		Title: "Secure Development Policy",
		grcPolicyDocumentMetadata: grcPolicyDocumentMetadata{
			DocumentClass: "policy",
			Status:        "approved",
		},
	}
	gapID := document.URN + ":gap:owner"
	events := []grcPolicyLifecycleEventItem{
		{
			ID:         "event-1",
			RecordURN:  gapID,
			RecordType: "governance.gap",
			Action:     "governance_gap.assign_owner",
			Status:     "in_progress",
			Actor:      "first@example.com",
			OccurredAt: "2026-02-02T12:00:00Z",
			Attributes: map[string]string{
				"gap_id":            gapID,
				"assigned_user_ids": "first@example.com",
			},
		},
		{
			ID:         "event-2",
			RecordURN:  gapID,
			RecordType: "governance.gap",
			Action:     "governance_gap.assign_owner",
			Status:     "in_progress",
			Actor:      "second@example.com",
			OccurredAt: "2026-02-03T12:00:00Z",
			Attributes: map[string]string{
				"gap_id":            gapID,
				"assigned_user_ids": "second@example.com",
			},
		},
	}

	gaps := grcPolicyGovernanceGapsFor([]grcPolicyDocumentItem{document}, nil, grcPolicyGovernanceRules("baseline"), events, time.Date(2026, 2, 3, 12, 0, 0, 0, time.UTC))
	ownerGap, ok := grcPolicyGapFor(gaps, "document", "secure-development", "Missing owner")
	if !ok || ownerGap.Owner != "second@example.com" || len(ownerGap.Trace) != 2 {
		t.Fatalf("owner gap = %+v, want reassigned owner with both trace events", ownerGap)
	}
}

func TestStrictGovernanceRulesRequireDocumentEvidence(t *testing.T) {
	document := grcPolicyDocumentItem{
		ID:    "secure-development",
		URN:   "urn:document:secure-development",
		Title: "Secure Development Policy",
		grcPolicyDocumentMetadata: grcPolicyDocumentMetadata{
			DocumentClass:   "policy",
			Status:          "approved",
			Owner:           "owner@example.com",
			NextReviewDueAt: "2026-12-31",
		},
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
	if strict[0].SourceFields["evidence_count"] != "0" || strict[0].SourceFields["evidence_snippet_count"] != "0" {
		t.Fatalf("strict evidence source fields = %+v, want empty evidence and snippet counts", strict[0].SourceFields)
	}

	document.EvidenceSnippets = []grcPolicyEvidenceSnippetItem{{
		ID:                "access-review",
		URN:               "urn:policy_evidence_snippet:access-review",
		DocumentID:        "secure-development",
		ManualReviewState: "ready_to_project",
	}}
	strict = grcPolicyGovernanceGapsFor([]grcPolicyDocumentItem{document}, nil, grcPolicyGovernanceRules("strict"), nil, time.Time{})
	if len(strict) != 0 {
		t.Fatalf("strict gaps with snippet evidence = %+v, want none", strict)
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
	_, ok := grcPolicyGapFor(gaps, subject, subjectID, reason)
	return ok
}

func grcPolicyGapFor(gaps []grcPolicyGovernanceGap, subject string, subjectID string, reason string) (grcPolicyGovernanceGap, bool) {
	for _, gap := range gaps {
		if gap.Subject == subject && gap.SubjectID == subjectID && gap.Reason == reason {
			return gap, true
		}
	}
	return grcPolicyGovernanceGap{}, false
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
			{ID: "later", ReviewDueAt: "2026-06-15", ReviewedAt: "2026-06-01", Cadence: "quarterly", Reviewers: []string{"later@example.com"}},
			{ID: "earlier", ReviewDueAt: "2026-01-15", ReviewedAt: "2026-01-10", Cadence: "monthly", Reviewers: []string{"earlier@example.com"}},
		},
	}

	grcPolicyFinalize(&policy, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))

	if policy.Reviews[0].ID != "earlier" {
		t.Fatalf("first review = %q, want earliest due review", policy.Reviews[0].ID)
	}
	if policy.Reviewer != "earlier@example.com" || policy.ReviewCadence != "monthly" || policy.NextReviewDueAt != "2026-01-15" {
		t.Fatalf("review metadata = %q/%q/%q, want earliest review metadata", policy.Reviewer, policy.ReviewCadence, policy.NextReviewDueAt)
	}
	if policy.LastReviewedAt != "2026-06-01" {
		t.Fatalf("last reviewed at = %q, want latest reviewed date", policy.LastReviewedAt)
	}
}

func TestPolicySnippetNeedsReviewUsesActionableStates(t *testing.T) {
	tests := []struct {
		name    string
		snippet grcPolicyEvidenceSnippetItem
		want    bool
	}{
		{
			name:    "needs review",
			snippet: grcPolicyEvidenceSnippetItem{ManualReviewState: "needs_review", ReviewState: "ready_to_project"},
			want:    true,
		},
		{
			name:    "field review",
			snippet: grcPolicyEvidenceSnippetItem{ManualReviewState: "needs_field_review"},
			want:    true,
		},
		{
			name:    "ready",
			snippet: grcPolicyEvidenceSnippetItem{ManualReviewState: "ready_to_project"},
			want:    false,
		},
		{
			name:    "reviewed",
			snippet: grcPolicyEvidenceSnippetItem{ManualReviewState: "reviewed"},
			want:    false,
		},
		{
			name:    "peer reviewed",
			snippet: grcPolicyEvidenceSnippetItem{ManualReviewState: "peer_reviewed"},
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := grcPolicySnippetNeedsReview(tt.snippet); got != tt.want {
				t.Fatalf("grcPolicySnippetNeedsReview(%+v) = %t, want %t", tt.snippet, got, tt.want)
			}
		})
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
	relation := policyLifecycleTestRelation(version, fabriccontract.RelationBelongsTo, foreignPolicy)

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
	relation := policyLifecycleTestRelation(foreignVersion, fabriccontract.RelationBelongsTo, policy)

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

func TestBuildActionEventCreatesBulkGovernanceGapEventWithoutSyntheticGapURN(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 30, 0, 0, time.UTC)
	firstGapID := "urn:document:secure-development:gap:owner"
	secondGapID := "urn:document:secure-development:gap:controls"
	event, response, err := BuildActionEvent(ActionRequest{
		Action: "governance_gap.assign_owner",
		ActionRequestScope: ActionRequestScope{
			TenantID:       "writer",
			SourceID:       "grc",
			RuntimeID:      "rt-1",
			ActorUserID:    "operator@example.com",
			IdempotencyKey: "bulk-assign-owner",
		},
		ActionRequestTarget: ActionRequestTarget{
			GapIDs: []string{firstGapID, secondGapID},
		},
		ActionRequestAssignments: ActionRequestAssignments{
			Assignees: []string{"owner@example.com"},
		},
	}, now)
	if err != nil {
		t.Fatalf("BuildActionEvent() error = %v", err)
	}
	attrs := event.GetAttributes()
	if attrs["gap_ids"] != firstGapID+","+secondGapID {
		t.Fatalf("gap_ids = %q, want both gap URNs", attrs["gap_ids"])
	}
	if attrs["gap_id"] != "" || attrs["record_urn"] != "" {
		t.Fatalf("gap_id/record_urn = %q/%q, want no synthetic gap target", attrs["gap_id"], attrs["record_urn"])
	}
	if attrs["record_id"] == "" || strings.Contains(attrs["record_id"], "urn-document") {
		t.Fatalf("record_id = %q, want bulk event id not slugified gap URNs", attrs["record_id"])
	}
	if response.Attributes["gap_ids"] != attrs["gap_ids"] {
		t.Fatalf("response attrs = %#v, want gap_ids", response.Attributes)
	}
}

func TestBuildActionEventKeepsLinkedPolicyTargetSeparate(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 30, 0, 0, time.UTC)
	event, _, err := BuildActionEvent(ActionRequest{
		Action: "governance_gap.link_policy",
		ActionRequestScope: ActionRequestScope{
			TenantID:    "writer",
			SourceID:    "grc",
			ActorUserID: "operator@example.com",
		},
		ActionRequestTarget: ActionRequestTarget{
			PolicyID:  "context-policy",
			GapID:     "urn:document:gap:policy",
			RecordURN: "urn:document:gap:policy",
		},
		ActionRequestAssignments: ActionRequestAssignments{
			Attributes: map[string]string{"target_policy_id": "linked-policy"},
		},
	}, now)
	if err != nil {
		t.Fatalf("BuildActionEvent() error = %v", err)
	}
	attrs := event.GetAttributes()
	if attrs["policy_id"] != "context-policy" || attrs["target_policy_id"] != "linked-policy" {
		t.Fatalf("policy attrs = %#v, want context policy and linked target", attrs)
	}
}

func TestBuildActionEventRejectsLinkPolicyWithoutTarget(t *testing.T) {
	_, _, err := BuildActionEvent(ActionRequest{
		Action: "governance_gap.link_policy",
		ActionRequestScope: ActionRequestScope{
			TenantID:    "writer",
			SourceID:    "grc",
			ActorUserID: "operator@example.com",
		},
		ActionRequestTarget: ActionRequestTarget{
			PolicyID:  "context-policy",
			GapID:     "urn:document:gap:policy",
			RecordURN: "urn:document:gap:policy",
		},
	}, time.Date(2026, 2, 1, 12, 30, 0, 0, time.UTC))
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("BuildActionEvent() error = %v, want invalid request", err)
	}
}

func TestBuildActionEventRejectsGapIDAndGapIDsTogether(t *testing.T) {
	_, _, err := BuildActionEvent(ActionRequest{
		Action: "governance_gap.assign_owner",
		ActionRequestScope: ActionRequestScope{
			TenantID:    "writer",
			SourceID:    "grc",
			ActorUserID: "operator@example.com",
		},
		ActionRequestTarget: ActionRequestTarget{
			GapID:  "urn:document:gap:owner",
			GapIDs: []string{"urn:document:gap:owner", "urn:document:gap:controls"},
		},
		ActionRequestAssignments: ActionRequestAssignments{
			Assignees: []string{"owner@example.com"},
		},
	}, time.Date(2026, 2, 1, 12, 30, 0, 0, time.UTC))
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("BuildActionEvent() error = %v, want invalid request", err)
	}
}

func TestBuildActionEventKeepsBulkGapIDsSeparate(t *testing.T) {
	gapIDs := []string{"urn:document:gap:owner", "urn:document:gap:controls"}
	event, _, err := BuildActionEvent(ActionRequest{
		Action: "governance_gap.assign_owner",
		ActionRequestScope: ActionRequestScope{
			TenantID:    "writer",
			SourceID:    "grc",
			ActorUserID: "operator@example.com",
		},
		ActionRequestTarget: ActionRequestTarget{
			GapIDs: gapIDs,
		},
		ActionRequestAssignments: ActionRequestAssignments{
			Assignees: []string{"owner@example.com"},
		},
	}, time.Date(2026, 2, 1, 12, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildActionEvent() error = %v", err)
	}
	attrs := event.GetAttributes()
	if attrs["gap_ids"] != strings.Join(gapIDs, ",") || attrs["gap_id"] != "" || attrs["record_urn"] != "" {
		t.Fatalf("gap attrs = %#v, want real gap_ids without single gap_id or record_urn", attrs)
	}
	if attrs["record_id"] == "" || strings.Contains(attrs["record_id"], ":gap:") {
		t.Fatalf("record_id = %q, want batch record id", attrs["record_id"])
	}
}

func TestAuditExportRowsUseGovernanceGapColumns(t *testing.T) {
	response := Response{
		Policies: []grcPolicyLifecyclePolicy{{
			ID:    "secure-development-policy",
			Title: "Secure Development Standard",
		}},
		GovernanceGaps: []grcPolicyGovernanceGap{{
			ID:             "urn:document:gap:owner",
			SubjectID:      "secure-development",
			Title:          "Secure Development Policy",
			PolicyID:       "secure-development-policy",
			GapState:       "open",
			Owner:          "AppSec",
			Action:         "Assign owner",
			LastActor:      "grc@example.com",
			StateUpdatedAt: "2026-02-01T12:00:00Z",
			DueAt:          "2026-02-07",
			MissingFields:  []string{"owner", "controls"},
			RuleID:         "document.owner",
		}},
	}

	header := AuditExportHeader()
	rows := AuditExportRows(response, ExportWindow{})
	column := map[string]int{}
	for index, name := range header {
		column[name] = index
	}
	var row []string
	for _, candidate := range rows {
		if candidate[column["record_type"]] == "governance.gap" {
			row = candidate
			break
		}
	}
	if row == nil {
		t.Fatalf("rows = %+v, want governance gap row", rows)
	}
	if len(row) != len(header) {
		t.Fatalf("row length = %d, header length = %d", len(row), len(header))
	}
	if row[column["policy_title"]] != "Secure Development Standard" || row[column["gap_subject_title"]] != "Secure Development Policy" {
		t.Fatalf("policy/gap titles = %q/%q, want separate titles", row[column["policy_title"]], row[column["gap_subject_title"]])
	}
	if row[column["controls"]] != "" || row[column["evidence"]] != "" {
		t.Fatalf("controls/evidence = %q/%q, want empty for governance gaps", row[column["controls"]], row[column["evidence"]])
	}
	if row[column["gap_missing_fields"]] != "owner; controls" || row[column["gap_rule_id"]] != "document.owner" {
		t.Fatalf("gap columns = %q/%q, want missing fields and rule id", row[column["gap_missing_fields"]], row[column["gap_rule_id"]])
	}
}

func TestAuditExportRowsIncludesUndatedGovernanceGapsInWindow(t *testing.T) {
	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC)
	response := Response{
		GovernanceGaps: []grcPolicyGovernanceGap{{
			ID:        "urn:risk:gap:policy",
			SubjectID: "privileged-access",
			Title:     "Privileged access risk",
			PolicyID:  "access-policy",
			GapState:  "open",
			Action:    "Link policy",
			RuleID:    "risk.policy",
		}},
	}

	rows := AuditExportRows(response, ExportWindow{Start: &start, End: &end})
	for _, row := range rows {
		if row[0] == "governance.gap" && row[1] == "privileged-access" {
			return
		}
	}
	t.Fatalf("rows = %+v, want undated governance gap in windowed export", rows)
}

func TestAuditExportRowsIncludesPoliciesWithActivityDatesInWindow(t *testing.T) {
	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC)
	response := Response{
		Policies: []grcPolicyLifecyclePolicy{{
			ID:    "access-policy",
			Title: "Access Policy",
			grcPolicyLifecyclePolicyMetadata: grcPolicyLifecyclePolicyMetadata{
				EffectiveAt: "2026-02-15",
			},
		}, {
			ID:    "vendor-policy",
			Title: "Vendor Policy",
			grcPolicyLifecyclePolicyMetadata: grcPolicyLifecyclePolicyMetadata{
				LastReviewedAt: "2026-02-20",
			},
		}, {
			ID:    "old-policy",
			Title: "Old Policy",
			grcPolicyLifecyclePolicyMetadata: grcPolicyLifecyclePolicyMetadata{
				EffectiveAt: "2026-01-15",
			},
		}},
	}

	rows := AuditExportRows(response, ExportWindow{Start: &start, End: &end})
	foundEffective := false
	foundReviewed := false
	for _, row := range rows {
		if row[0] == "policy" && row[1] == "access-policy" {
			foundEffective = true
		}
		if row[0] == "policy" && row[1] == "vendor-policy" {
			foundReviewed = true
		}
		if row[0] == "policy" && row[1] == "old-policy" {
			t.Fatalf("rows = %+v, did not expect out-of-window policy", rows)
		}
	}
	if !foundEffective || !foundReviewed {
		t.Fatalf("rows = %+v, want policies with effective or last-reviewed dates in window", rows)
	}
}

func TestAuditExportRowsIncludesEvidenceSnippetsInWindow(t *testing.T) {
	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC)
	response := Response{
		Policies: []grcPolicyLifecyclePolicy{{
			ID:    "access-policy",
			Title: "Access Policy",
		}},
		EvidenceSnippets: []grcPolicyEvidenceSnippetItem{{
			ID:                "snippet-ready",
			PolicyID:          "access-policy",
			PolicyCitations:   []string{"Access reviews are performed quarterly."},
			ManualReviewState: "ready_to_project",
			Attributes:        map[string]string{"observed_at": "2026-02-15T12:00:00Z"},
		}, {
			ID:                "snippet-old",
			PolicyID:          "access-policy",
			PolicyCitations:   []string{"Old access review note."},
			ManualReviewState: "ready_to_project",
			Attributes:        map[string]string{"observed_at": "2026-01-15T12:00:00Z"},
		}, {
			ID:                "snippet-undated",
			PolicyID:          "access-policy",
			PolicyCitations:   []string{"Undated citation retained for review."},
			ManualReviewState: "ready_to_project",
		}},
	}

	rows := AuditExportRows(response, ExportWindow{Start: &start, End: &end})
	foundReady := false
	foundUndated := false
	for _, row := range rows {
		if row[0] == "policy.evidence_snippet" && row[1] == "snippet-ready" {
			foundReady = true
		}
		if row[0] == "policy.evidence_snippet" && row[1] == "snippet-undated" {
			foundUndated = true
		}
		if row[0] == "policy.evidence_snippet" && row[1] == "snippet-old" {
			t.Fatalf("rows = %+v, did not expect out-of-window snippet", rows)
		}
	}
	if !foundReady || !foundUndated {
		t.Fatalf("rows = %+v, want in-window and undated policy evidence snippets", rows)
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

func TestPolicyDocumentEvidenceFieldsFlowToLifecycleAndExport(t *testing.T) {
	now := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)
	policy := policyLifecycleTestRow("urn:cerebro:writer:policy:policyops:access", "policy", "Access Policy", map[string]string{
		"policy_id":            "access-policy",
		"policy_type":          "policy",
		"policy_document_type": "access_control",
		"status":               "approved",
		"owner":                "Security",
		"approving_authority":  "Security Steering Committee",
		"review_cadence":       "annual",
		"last_reviewed_at":     "2026-06-01",
		"next_review_due_at":   "2027-06-01",
		"effective_at":         "2026-06-15",
		"exception_path":       "Submit a waiver request",
	})
	document := policyLifecycleTestRow("urn:cerebro:writer:document:policyops:access-v3", "document", "Access Policy v3", map[string]string{
		"document_id":              "access-v3",
		"document_type":            "policy",
		"document_class":           "policy",
		"policy_type":              "access_control",
		"status":                   "approved",
		"owner":                    "Security",
		"approving_authority":      "Security Steering Committee",
		"version":                  "3",
		"review_cadence":           "annual",
		"last_reviewed_at":         "2026-06-01",
		"next_review_due_at":       "2027-06-01",
		"approved_at":              "2026-06-01",
		"effective_at":             "2026-06-15",
		"acknowledgement_evidence": "attestation-campaign-1",
		"exception_path":           "Submit a waiver request",
		"source_provenance":        "manual upload",
		"source_url":               "https://grc.example/policies/access-v3",
	})
	control := policyLifecycleTestRow("urn:cerebro:writer:policy:policyops:control:CC6.1", "policy", "Logical access", map[string]string{
		"control_id":  "CC6.1",
		"policy_id":   "CC6.1",
		"policy_type": "control",
		"framework":   "SOC 2",
	})
	readySnippet := policyLifecycleTestRow("urn:cerebro:writer:policy_evidence_snippet:policyops:snippet-ready", "policy.evidence_snippet", "Access reviews", map[string]string{
		"snippet_id":          "snippet-ready",
		"policy_id":           "access-policy",
		"document_id":         "access-v3",
		"section_id":          "access-review",
		"section_title":       "Access reviews",
		"policy_citations":    "Access reviews are performed quarterly.",
		"confidence":          "0.86",
		"manual_review_state": "ready_to_project",
		"review_state":        "ready_to_project",
		"question_ids":        "q-access-1",
		"source_provenance":   "manual upload",
	})
	needsReviewSnippet := policyLifecycleTestRow("urn:cerebro:writer:policy_evidence_snippet:policyops:snippet-review", "policy.evidence_snippet", "Access automation", map[string]string{
		"snippet_id":          "snippet-review",
		"policy_id":           "access-policy",
		"document_id":         "access-v3",
		"section_id":          "access-automation",
		"section_title":       "Access automation",
		"policy_citations":    "Access requests should be reviewed before approval.",
		"confidence":          "0.62",
		"manual_review_state": "needs_review",
		"review_state":        "ready_to_project",
		"unsupported_claims":  "Access approvals are fully automated",
		"question_ids":        "q-access-2",
		"source_provenance":   "manual upload",
	})
	relations := []ports.CypherRow{
		policyLifecycleTestRelation(document, fabriccontract.RelationBelongsTo, policy),
		policyLifecycleTestRelation(document, fabriccontract.RelationAssociatedWith, control),
		policyLifecycleTestRelation(document, fabriccontract.RelationHasEvidence, readySnippet),
		policyLifecycleTestRelation(document, fabriccontract.RelationHasEvidence, needsReviewSnippet),
		policyLifecycleTestRelation(policy, fabriccontract.RelationHasEvidence, readySnippet),
		policyLifecycleTestRelation(policy, fabriccontract.RelationHasEvidence, needsReviewSnippet),
		policyLifecycleTestRelation(readySnippet, fabriccontract.RelationSupports, control),
	}

	response := grcPolicyLifecycleFromGraph([]ports.CypherRow{policy, document, control, readySnippet, needsReviewSnippet}, relations, now)
	if len(response.Documents) != 1 {
		t.Fatalf("documents len = %d, want 1", len(response.Documents))
	}
	got := response.Documents[0]
	if got.PolicyType != "access_control" || got.ApprovingAuthority != "Security Steering Committee" || got.LastReviewedAt != "2026-06-01" {
		t.Fatalf("document fields = %+v", got)
	}
	if got.AcknowledgementEvidence != "attestation-campaign-1" || got.ExceptionPath != "Submit a waiver request" || got.SourceProvenance != "manual upload" {
		t.Fatalf("document evidence fields = %+v", got)
	}
	if len(got.EvidenceSnippets) != 2 {
		t.Fatalf("document evidence snippets = %+v, want ready and needs-review snippets", got.EvidenceSnippets)
	}
	if len(response.Policies) != 1 || response.Policies[0].ApprovingAuthority != "Security Steering Committee" || response.Policies[0].EffectiveAt != "2026-06-15" {
		t.Fatalf("policy fields = %+v", response.Policies)
	}
	if len(response.Policies[0].EvidenceSnippets) != 2 || len(response.EvidenceSnippets) != 2 {
		t.Fatalf("policy/lifecycle snippets = %+v/%+v", response.Policies[0].EvidenceSnippets, response.EvidenceSnippets)
	}
	if response.Summary.EvidenceSnippets != 2 || response.Summary.SnippetsNeedingReview != 1 {
		t.Fatalf("snippet summary = %+v, want 2 snippets and 1 needing review", response.Summary.GRCPolicyLifecycleEvidenceSummary)
	}

	header := AuditExportHeader()
	rows := AuditExportRows(response, ExportWindow{})
	column := map[string]int{}
	for index, name := range header {
		column[name] = index
	}
	var documentRow []string
	for _, row := range rows {
		if row[column["record_type"]] == "document" && row[column["record_id"]] == "access-v3" {
			documentRow = row
			break
		}
	}
	if documentRow == nil {
		t.Fatalf("rows = %+v, want document export row", rows)
	}
	if len(documentRow) != len(header) {
		t.Fatalf("document row length = %d, header length = %d", len(documentRow), len(header))
	}
	if documentRow[column["policy_type"]] != "access_control" ||
		documentRow[column["approving_authority"]] != "Security Steering Committee" ||
		documentRow[column["last_reviewed_at"]] != "2026-06-01" ||
		documentRow[column["acknowledgement_evidence"]] != "attestation-campaign-1" ||
		documentRow[column["exception_path"]] != "Submit a waiver request" ||
		documentRow[column["source_provenance"]] != "manual upload" ||
		documentRow[column["source_url"]] != "https://grc.example/policies/access-v3" {
		t.Fatalf("document export row = %+v", documentRow)
	}
	var readySnippetRow []string
	var needsReviewSnippetRow []string
	for _, row := range rows {
		if row[column["record_type"]] == "policy.evidence_snippet" && row[column["record_id"]] == "snippet-ready" {
			readySnippetRow = row
		}
		if row[column["record_type"]] == "policy.evidence_snippet" && row[column["record_id"]] == "snippet-review" {
			needsReviewSnippetRow = row
		}
	}
	if readySnippetRow == nil || needsReviewSnippetRow == nil {
		t.Fatalf("rows = %+v, want ready and needs-review snippet rows", rows)
	}
	if readySnippetRow[column["policy_citations"]] != "Access reviews are performed quarterly." ||
		readySnippetRow[column["manual_review_state"]] != "ready_to_project" ||
		readySnippetRow[column["confidence"]] != "0.86" ||
		readySnippetRow[column["question_refs"]] != "q-access-1" ||
		readySnippetRow[column["controls"]] != "SOC 2 CC6.1 Logical access" {
		t.Fatalf("ready snippet row = %+v", readySnippetRow)
	}
	if needsReviewSnippetRow[column["manual_review_state"]] != "needs_review" ||
		needsReviewSnippetRow[column["unsupported_claims"]] != "Access approvals are fully automated" {
		t.Fatalf("needs-review snippet row = %+v", needsReviewSnippetRow)
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

func policyLifecycleTestRelation(left ports.CypherRow, relation string, right ports.CypherRow) ports.CypherRow {
	values := map[string]any{}
	for key, value := range left.Values {
		values["left_"+key] = value
	}
	for key, value := range right.Values {
		values["right_"+key] = value
	}
	values["relation"] = relation
	values["relation_attributes_json"] = "{}"
	return ports.CypherRow{Values: values}
}
