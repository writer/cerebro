package grcvendor

import (
	"context"
	"errors"
	"strings"
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
			vendorRow("urn:cerebro:writer:vendor:vrm:acme", "Acme", `{"vendor_id":"acme","source_system":"vrm","status":"active","lifecycle_state":"conditionally_approved","category":"analytics","inherent_risk_level":"High","next_security_review_due_date":"2026-01-10","last_security_review_completion_date":"2024-01-01","review_stale_after_days":"365","source_runtime_fresh_at":"2026-01-19","artifact_created_at":"2026-01-01","document_expiry_date":"2026-05-01","last_control_evidence_at":"2026-01-15","data_sensitivity":"Restricted","access_level":"Admin","criticality":"Tier 1","subprocessor":"true","internet_exposed":"true","customer_data":"true","dpa_attached":"false","assessment_state":"in_progress","assessment_progress":"40","open_assessment_count":"1","assessment_types":"security,privacy","external_security_rating":"D","last_material_change_at":"2026-01-18","annual_spend":"120000","spend_currency":"USD","renewal_notice_date":"2026-02-01","open_remediation_count":"3","overdue_remediation_count":"1","remediation_due_date":"2026-01-18","services_provided":"Analytics processing"}`, 2, 1, 0, 1),
			vendorRow("urn:cerebro:writer:vendor:vrm:beta", "Beta", `{"vendor_id":"beta","source_system":"vrm","status":"active","business_owner_user_id":"user-2","residual_risk_level":"Low","next_security_review_due_date":"2026-04-01"}`, 0, 0, 0, 0),
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
	if vendor.LifecycleState != LifecycleStateConditionallyApproved || vendor.DataSensitivity != "restricted" || vendor.Subprocessor != "true" {
		t.Fatalf("vendor lifecycle/risk inputs = %#v", vendor)
	}
	if vendor.EvidenceFreshnessState != FreshnessStateStale {
		t.Fatalf("evidence freshness state = %q, want stale (%#v)", vendor.EvidenceFreshnessState, vendor.EvidenceFreshness)
	}
	if vendor.RiskScore == 0 || vendor.RiskTier != "tier_1" || len(vendor.ScoreFactors) == 0 {
		t.Fatalf("risk scoring = %#v", vendor.VendorRiskScoring)
	}
	if vendor.AssessmentState != "in_progress" || vendor.AssessmentProgress != 40 || vendor.OpenAssessments != 1 {
		t.Fatalf("assessment posture = %#v", vendor.VendorAssessmentPosture)
	}
	if vendor.MonitoringState != "alert" || len(vendor.MonitoringSignals) == 0 || vendor.ExternalRating != "D" {
		t.Fatalf("monitoring posture = %#v", vendor.VendorMonitoringPosture)
	}
	if vendor.SpendAmount != "120000" || vendor.RenewalState != ReviewStateDueSoon {
		t.Fatalf("commercial posture = %#v", vendor.VendorCommercialPosture)
	}
	if vendor.ExposureLevel != "critical" || len(vendor.ExposureReasons) == 0 || vendor.PacketState != "blocked" {
		t.Fatalf("operational posture = %#v", vendor.VendorOperationalPosture)
	}
	if vendor.RemediationState != ReviewStateOverdue || vendor.OpenRemediationItems != 3 || vendor.OverdueRemediationItems != 1 {
		t.Fatalf("remediation posture = %#v", vendor.VendorOperationalPosture)
	}
	if vendor.RiskQueueRank == 0 || len(vendor.QueueReasons) == 0 || len(vendor.NextActions) == 0 || len(vendor.CloseActions) == 0 {
		t.Fatalf("vendor queue posture = %#v", vendor.VendorQueuePosture)
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
	vendor = RefreshVendorQueuePosture(vendor)
	summary := Summarize([]Vendor{vendor})
	if summary.TotalVendors != 1 || summary.HighRiskVendors != 1 || summary.OwnerMissingVendors != 1 || summary.ReviewOverdueVendors != 1 {
		t.Fatalf("summary posture = %#v", summary)
	}
	if summary.RiskQueueVendors != 1 || summary.StaleEvidenceVendors != 1 || summary.RestrictedVendors != 1 || summary.CriticalTierVendors != 1 || summary.AssessmentDueVendors != 1 || summary.MonitoringAlertVendors != 1 || summary.RenewalDueVendors != 1 {
		t.Fatalf("summary queue posture = %#v", summary)
	}
	if summary.PacketBlockedVendors != 1 || summary.HighExposureVendors != 1 || summary.RemediationDueVendors != 1 {
		t.Fatalf("summary operational posture = %#v", summary)
	}
	if summary.OpenFindings != 2 || summary.CriticalFindings != 1 || summary.EvidenceItems != 3 {
		t.Fatalf("summary finding counts = %#v", summary)
	}
}

func TestRefreshVendorQueuePostureAddsQuestionnaireBlockers(t *testing.T) {
	vendor := Vendor{
		VendorIdentity: VendorIdentity{
			URN:  "urn:cerebro:writer:vendor:core-sso",
			Name: "Core SSO",
		},
		VendorLifecycle:         VendorLifecycle{LifecycleState: LifecycleStateActive},
		VendorOwnership:         VendorOwnership{OwnerState: OwnerStateAssigned},
		VendorReviewPosture:     VendorReviewPosture{ReviewState: ReviewStateCurrent},
		VendorAssessmentPosture: VendorAssessmentPosture{AssessmentState: ReviewStateCurrent},
		VendorFreshnessPosture:  VendorFreshnessPosture{EvidenceFreshnessState: FreshnessStateCurrent},
		Attributes: map[string]string{
			"questionnaire_blocked_answers":  "2",
			"questionnaire_missing_evidence": "1",
		},
	}

	refreshed := RefreshVendorQueuePosture(vendor, time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC))

	if !hasVendorAction(refreshed.NextActions, "clear_questionnaire_blockers") {
		t.Fatalf("next actions = %#v, want questionnaire blocker action", refreshed.NextActions)
	}
	if !hasVendorQueueReason(refreshed.QueueReasons, "questionnaire blocked") {
		t.Fatalf("queue reasons = %#v, want questionnaire blocked", refreshed.QueueReasons)
	}
}

func TestQuestionnaireVendorRollupsCountsOperationalWork(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	due := now.Add(-time.Hour)
	vendorURN := "urn:cerebro:writer:vendor:core-sso"
	store := &stubQuestionnaireRunStore{records: []*ports.QuestionnaireRunRecord{
		{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "writer", RunID: "run-1"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{VendorURN: vendorURN},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{
				Status:             ports.QuestionnaireStatusNeedsInput,
				ReadyAnswerCount:   2,
				BlockedAnswerCount: 1,
				ReviewAnswerCount:  3,
				MissingEvidence:    4,
				StaleEvidence:      5,
			},
			QuestionnaireRunContent: ports.QuestionnaireRunContent{Assignments: []ports.QuestionnaireAssignment{
				{ID: "assignment-open", Status: "open"},
				{ID: "assignment-empty"},
				{ID: "assignment-closed", Status: "closed"},
			}},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{
				Attributes: map[string]string{"questionnaire_urn": "urn:cerebro:writer:security_questionnaire:questionnaire_run:run-1"},
				DueAt:      &due,
				UpdatedAt:  now,
			},
		},
		{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "writer", RunID: "run-1-old-active"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{VendorURN: vendorURN},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{
				Status:             ports.QuestionnaireStatusNeedsInput,
				ReadyAnswerCount:   20,
				BlockedAnswerCount: 20,
				ReviewAnswerCount:  20,
				MissingEvidence:    20,
				StaleEvidence:      20,
			},
			QuestionnaireRunContent: ports.QuestionnaireRunContent{Assignments: []ports.QuestionnaireAssignment{
				{ID: "assignment-duplicate-open", Status: "open"},
			}},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{
				Attributes: map[string]string{"questionnaire_urn": "urn:cerebro:writer:security_questionnaire:questionnaire_run:run-1"},
				DueAt:      &due,
				UpdatedAt:  now.Add(-time.Hour),
			},
		},
		{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "writer", RunID: "run-1-copy"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{VendorURN: vendorURN},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusApproved},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{
				Attributes: map[string]string{"questionnaire_urn": "urn:cerebro:writer:security_questionnaire:questionnaire_run:run-1"},
				DueAt:      &due,
				UpdatedAt:  now.Add(-2 * time.Hour),
			},
		},
		{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "writer", RunID: "run-2"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{VendorURN: vendorURN},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{
				Status:           ports.QuestionnaireStatusApproved,
				ReadyAnswerCount: 1,
			},
			QuestionnaireRunMetadata: ports.QuestionnaireRunMetadata{
				Attributes: map[string]string{"questionnaire_urn": "urn:cerebro:writer:security_questionnaire:questionnaire_run:run-2"},
				DueAt:      &due,
				UpdatedAt:  now,
			},
		},
		{
			QuestionnaireRunIdentity: ports.QuestionnaireRunIdentity{TenantID: "writer", RunID: "other-vendor"},
			QuestionnaireRunSource:   ports.QuestionnaireRunSource{VendorURN: "urn:cerebro:writer:vendor:other"},
			QuestionnaireRunWorkflow: ports.QuestionnaireRunWorkflow{Status: ports.QuestionnaireStatusNeedsInput, BlockedAnswerCount: 9},
		},
	}}

	rollups, err := QuestionnaireVendorRollups(context.Background(), store, "writer", []string{vendorURN, "urn:cerebro:writer:vendor:missing"}, now)
	if err != nil {
		t.Fatalf("QuestionnaireVendorRollups() error = %v", err)
	}
	rollup := rollups[vendorURN]
	if rollup.QuestionnaireCount != 2 || rollup.DueQuestionnaires != 1 || rollup.ReadyAnswers != 2 || rollup.BlockedAnswers != 1 || rollup.ReviewAnswers != 3 || rollup.MissingEvidence != 4 || rollup.StaleEvidence != 5 || rollup.OpenAssignments != 2 {
		t.Fatalf("rollup = %#v", rollup)
	}
	if len(store.rollupFilters) != 1 || !hasQuestionnaireVendorRollupFilter(store.rollupFilters[0], vendorURN) || !hasQuestionnaireVendorRollupFilter(store.rollupFilters[0], "urn:cerebro:writer:vendor:missing") {
		t.Fatalf("rollup filters = %#v, want one batch query for requested vendors", store.rollupFilters)
	}

	vendor := ApplyQuestionnaireVendorRollup(Vendor{
		VendorIdentity:          VendorIdentity{URN: vendorURN, Name: "Core SSO"},
		VendorLifecycle:         VendorLifecycle{LifecycleState: LifecycleStateActive},
		VendorOwnership:         VendorOwnership{OwnerState: OwnerStateAssigned},
		VendorReviewPosture:     VendorReviewPosture{ReviewState: ReviewStateCurrent},
		VendorAssessmentPosture: VendorAssessmentPosture{AssessmentState: ReviewStateCurrent},
		VendorFreshnessPosture:  VendorFreshnessPosture{EvidenceFreshnessState: FreshnessStateCurrent},
	}, rollup)
	if vendor.QuestionnaireCount != 2 || vendor.Attributes["questionnaire_blocked_answers"] != "1" || vendor.Attributes["questionnaire_due"] != "1" {
		t.Fatalf("vendor questionnaire attrs = %#v", vendor)
	}
	if !hasVendorAction(vendor.NextActions, "clear_questionnaire_blockers") {
		t.Fatalf("next actions = %#v, want questionnaire blocker action", vendor.NextActions)
	}
}

func TestListVendorsCanDeferLimitUntilAfterEnrichment(t *testing.T) {
	store := &stubGraphStore{
		rows: [][]ports.CypherRow{{
			vendorRow("urn:cerebro:writer:vendor:vrm:low", "Low", `{"vendor_id":"low","source_system":"vrm","status":"active","business_owner_user_id":"user-1","residual_risk_level":"Low","next_security_review_due_date":"2026-04-01"}`, 0, 0, 0, 0),
			vendorRow("urn:cerebro:writer:vendor:vrm:critical-finding", "Critical Finding", `{"vendor_id":"critical-finding","source_system":"vrm","status":"active","business_owner_user_id":"user-2","residual_risk_level":"Low","next_security_review_due_date":"2026-04-01"}`, 0, 0, 0, 0),
		}},
	}
	service := New(store)
	service.now = func() time.Time { return time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC) }

	vendors, err := service.ListVendors(context.Background(), ListVendorsRequest{
		TenantID:   "writer",
		QueueOnly:  true,
		DeferLimit: true,
		Limit:      1,
	})
	if err != nil {
		t.Fatalf("ListVendors() error = %v", err)
	}
	if len(vendors) != 2 {
		t.Fatalf("vendors len = %d, want deferred untruncated rows", len(vendors))
	}
	if store.requests[0].RowLimit != maxVendorLimit {
		t.Fatalf("row limit = %d, want queue prefetch limit %d", store.requests[0].RowLimit, maxVendorLimit)
	}
	for index := range vendors {
		if vendors[index].VendorID == "critical-finding" {
			vendors[index].CriticalFindings = 1
			vendors[index] = RefreshVendorQueuePosture(vendors[index], service.now())
		}
	}
	final := SortAndLimitVendors(FilterVendorsByQueue(vendors), 1)
	if len(final) != 1 || final[0].VendorID != "critical-finding" || final[0].RiskQueueRank < 90 {
		t.Fatalf("final vendors = %#v, want critical finding vendor first", final)
	}
}

func TestOverallFreshnessStateMissingOverridesCurrent(t *testing.T) {
	state := overallFreshnessState([]FreshnessClock{
		{ID: "source_runtime", Status: FreshnessStateCurrent},
		{ID: "artifact_age", Status: FreshnessStateMissing},
		{ID: "review_completion", Status: FreshnessStateMissing},
	})
	if state != FreshnessStateMissing {
		t.Fatalf("overallFreshnessState = %q, want missing", state)
	}
}

func TestOffboardingVendorStaysInQueue(t *testing.T) {
	vendor := RefreshVendorQueuePosture(Vendor{
		VendorIdentity: VendorIdentity{Name: "Offboarding", Status: "offboarding"},
		VendorLifecycle: VendorLifecycle{
			LifecycleState: LifecycleStateOffboarding,
		},
		VendorOwnership: VendorOwnership{OwnerState: OwnerStateAssigned},
		VendorReviewPosture: VendorReviewPosture{
			ReviewState: ReviewStateCurrent,
		},
		VendorFreshnessPosture: VendorFreshnessPosture{
			EvidenceFreshnessState: FreshnessStateCurrent,
		},
		VendorOperationalPosture: VendorOperationalPosture{
			DataDeletionState: FreshnessStateMissing,
		},
		Attributes: map[string]string{
			"data_deletion_state": "missing",
		},
	}, time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC))
	if len(vendor.QueueReasons) == 0 {
		t.Fatalf("queue reasons empty for offboarding vendor: %#v", vendor)
	}
	found := false
	for _, reason := range vendor.QueueReasons {
		if reason == "offboarding incomplete" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("queue reasons = %#v, want offboarding incomplete", vendor.QueueReasons)
	}
}

func TestNormalizeVendorLifecycleStateTreatsOffboardedAsTerminal(t *testing.T) {
	if got := normalizeVendorLifecycleState("offboarded"); got != LifecycleStateRetired {
		t.Fatalf("normalizeVendorLifecycleState(offboarded) = %q, want %q", got, LifecycleStateRetired)
	}
}

func hasVendorAction(actions []VendorAction, id string) bool {
	for _, action := range actions {
		if action.ID == id {
			return true
		}
	}
	return false
}

func hasVendorQueueReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func TestGetVendorReturnsRelationshipsAndGraph(t *testing.T) {
	urn := "urn:cerebro:writer:vendor:vrm:acme"
	store := &stubGraphStore{
		rows: [][]ports.CypherRow{
			{vendorRow(urn, "Acme", `{"vendor_id":"acme","source_system":"vrm","security_owner_user_id":"user-1","residual_risk_level":"Medium","next_security_review_due_date":"2026-02-01","last_security_review_completion_date":"2026-01-01","dpa_attached":"true","source_runtime_fresh_at":"2026-01-19","artifact_created_at":"2026-01-01","document_expiry_date":"2026-05-01","last_control_evidence_at":"2026-01-15","primary_contact":"risk@example.com"}`, 1, 1, 1, 1)},
			{
				relatedRow("urn:cerebro:writer:contract:vrm:msa", "contract", "MSA", "associated_with"),
				relatedRow("urn:cerebro:writer:security_review:vrm:review-1", "security.review", "Review", "associated_with"),
				relatedRow("urn:cerebro:writer:user:vrm:user-1", "grc.user", "user-1", "owned_by"),
				relatedRow("urn:cerebro:writer:internet_host:acme.example", "internet.host", "acme.example", "has_identifier"),
				relatedRow("urn:cerebro:writer:vendor_alias:vrm:acme-inc", "vendor.alias", "Acme Inc", "has_identifier"),
				relatedRow("urn:cerebro:writer:vendor_assessment:vrm:assessment-1", "vendor.assessment", "Assessment", "associated_with"),
				relatedRow("urn:cerebro:writer:vendor_contact:vrm:contact-1", "vendor.contact", "vendor@example.com", "has_contact"),
				relatedRow("urn:cerebro:writer:subprocessor:vrm:sub-1", "subprocessor", "Subprocessor", "uses_subprocessor"),
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
	if len(detail.Relationships.Contracts) != 1 || len(detail.Relationships.SecurityReviews) != 1 || len(detail.Relationships.Owners) != 1 || len(detail.Relationships.Hosts) != 1 || len(detail.Relationships.Aliases) != 1 || len(detail.Relationships.Assessments) != 1 || len(detail.Relationships.Contacts) != 1 || len(detail.Relationships.FourthParties) != 1 {
		t.Fatalf("relationships = %#v", detail.Relationships)
	}
	if detail.Packet.VendorURN != urn || detail.Packet.Risk.RiskLevel != "medium" || len(detail.Packet.Identifiers) != 2 || len(detail.Packet.ReviewHistory) != 2 || len(detail.Packet.Contacts) != 1 || len(detail.Packet.FourthParties) != 1 {
		t.Fatalf("packet = %#v", detail.Packet)
	}
	if detail.Packet.Operations.PacketState != "ready" || detail.Packet.Operations.ExposureLevel == "" {
		t.Fatalf("packet operations = %#v", detail.Packet.Operations)
	}
	if store.rootURN != urn || store.limit != relatedLimit {
		t.Fatalf("neighborhood request = %q/%d, want %q/%d", store.rootURN, store.limit, urn, relatedLimit)
	}
}

func TestFilterVendorsByQueueSkipsRetiredVendors(t *testing.T) {
	vendors := []Vendor{
		{
			VendorIdentity: VendorIdentity{Name: "Retired", Status: "retired"},
			VendorLifecycle: VendorLifecycle{
				LifecycleState: LifecycleStateRetired,
			},
			VendorOwnership: VendorOwnership{OwnerState: OwnerStateMissing},
			VendorReviewPosture: VendorReviewPosture{
				ReviewState: ReviewStateOverdue,
			},
		},
		{
			VendorIdentity: VendorIdentity{Name: "Active", Status: "active"},
			VendorLifecycle: VendorLifecycle{
				LifecycleState: LifecycleStateActive,
			},
			VendorOwnership: VendorOwnership{OwnerState: OwnerStateMissing},
			VendorReviewPosture: VendorReviewPosture{
				ReviewState: ReviewStateOverdue,
			},
		},
	}

	filtered := FilterVendorsByQueue(vendors)
	if len(filtered) != 1 || filtered[0].Name != "Active" {
		t.Fatalf("filtered vendors = %#v", filtered)
	}
}

func TestGetVendorAcceptsVendorID(t *testing.T) {
	urn := "urn:cerebro:writer:vendor:vrm:acme"
	store := &stubGraphStore{
		rows: [][]ports.CypherRow{
			{vendorRow(urn, "Acme", `{"vendor_id":"acme","source_system":"vrm"}`, 0, 0, 0, 0)},
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
			discoveryRow("urn:cerebro:writer:vendor_discovery:grc:shadow", "Shadow SaaS", `{"discovered_vendor_id":"shadow","normalized_name":"shadow saas","source_system":"vrm","status":"discovered","category":"analytics"}`),
			discoveryRow("urn:cerebro:writer:vendor_discovery:grc:ignored", "Ignored SaaS", `{"discovered_vendor_id":"ignored","source_system":"vrm","status":"ignored"}`),
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
		LinkedVendorURN: "urn:cerebro:writer:vendor:vrm:shadow",
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

type stubQuestionnaireRunStore struct {
	ports.StateStore
	records       []*ports.QuestionnaireRunRecord
	filters       []ports.QuestionnaireRunFilter
	rollupFilters []ports.QuestionnaireVendorRollupFilter
	err           error
}

func (s *stubQuestionnaireRunStore) UpsertQuestionnaireRun(context.Context, ports.QuestionnaireRunRecord, ports.QuestionnaireRunEventRecord) (*ports.QuestionnaireRunRecord, error) {
	return nil, s.err
}

func (s *stubQuestionnaireRunStore) GetQuestionnaireRun(context.Context, ports.QuestionnaireRunFilter) (*ports.QuestionnaireRunRecord, error) {
	return nil, s.err
}

func (s *stubQuestionnaireRunStore) ListQuestionnaireRuns(_ context.Context, filter ports.QuestionnaireRunFilter) ([]*ports.QuestionnaireRunRecord, error) {
	s.filters = append(s.filters, filter)
	if strings.TrimSpace(filter.VendorURN) == "" {
		return s.records, s.err
	}
	filtered := []*ports.QuestionnaireRunRecord{}
	for _, record := range s.records {
		if record != nil && record.VendorURN == filter.VendorURN {
			filtered = append(filtered, record)
		}
	}
	return filtered, s.err
}

func (s *stubQuestionnaireRunStore) SummarizeQuestionnaireRuns(context.Context, ports.QuestionnaireRunFilter) (ports.QuestionnaireRunSummary, error) {
	return ports.QuestionnaireRunSummary{}, s.err
}

func (s *stubQuestionnaireRunStore) ListQuestionnaireVendorRollups(_ context.Context, filter ports.QuestionnaireVendorRollupFilter) ([]ports.QuestionnaireVendorRollupRecord, error) {
	s.rollupFilters = append(s.rollupFilters, filter)
	vendorSet := map[string]struct{}{}
	for _, vendorURN := range filter.VendorURNs {
		vendorURN = strings.TrimSpace(vendorURN)
		if vendorURN != "" {
			vendorSet[vendorURN] = struct{}{}
		}
	}
	seen := map[string]struct{}{}
	current := map[string]*ports.QuestionnaireRunRecord{}
	for _, record := range s.records {
		if record == nil {
			continue
		}
		vendorURN := strings.TrimSpace(record.VendorURN)
		if _, ok := vendorSet[vendorURN]; !ok {
			continue
		}
		key := vendorURN + "\x00" + firstNonEmpty(record.Attributes["questionnaire_urn"], record.RunID)
		if existing := current[key]; existing == nil || record.UpdatedAt.After(existing.UpdatedAt) || (record.UpdatedAt.Equal(existing.UpdatedAt) && record.RunID > existing.RunID) {
			current[key] = record
		}
	}
	rollups := map[string]ports.QuestionnaireVendorRollupRecord{}
	for key, record := range current {
		vendorURN := strings.TrimSpace(record.VendorURN)
		rollup := rollups[vendorURN]
		rollup.VendorURN = vendorURN
		if _, ok := seen[key]; !ok {
			rollup.QuestionnaireCount++
			seen[key] = struct{}{}
		}
		if !testQuestionnaireTerminal(record.Status) {
			if record.DueAt != nil && !record.DueAt.After(filter.Now) {
				rollup.DueQuestionnaires++
			}
			rollup.ReadyAnswers += record.ReadyAnswerCount
			rollup.BlockedAnswers += record.BlockedAnswerCount
			rollup.ReviewAnswers += record.ReviewAnswerCount
			rollup.MissingEvidence += record.MissingEvidence
			rollup.StaleEvidence += record.StaleEvidence
			for _, assignment := range record.Assignments {
				if strings.TrimSpace(assignment.Status) == "" || assignment.Status == "open" {
					rollup.OpenAssignments++
				}
			}
		}
		rollups[vendorURN] = rollup
	}
	records := make([]ports.QuestionnaireVendorRollupRecord, 0, len(rollups))
	for _, record := range rollups {
		records = append(records, record)
	}
	return records, s.err
}

func (s *stubQuestionnaireRunStore) ListQuestionnaireRunEvents(context.Context, ports.QuestionnaireRunEventFilter) ([]*ports.QuestionnaireRunEventRecord, error) {
	return nil, s.err
}

func hasQuestionnaireVendorRollupFilter(filter ports.QuestionnaireVendorRollupFilter, vendorURN string) bool {
	for _, filteredVendorURN := range filter.VendorURNs {
		if filteredVendorURN == vendorURN {
			return true
		}
	}
	return false
}

func testQuestionnaireTerminal(status string) bool {
	switch strings.TrimSpace(status) {
	case ports.QuestionnaireStatusApproved, ports.QuestionnaireStatusRejected:
		return true
	default:
		return false
	}
}

func vendorRow(urn string, label string, attrs string, contracts int64, reviews int64, questionnaires int64, documents int64) ports.CypherRow {
	return ports.CypherRow{Values: map[string]any{
		"urn":                      urn,
		"label":                    label,
		"source_id":                "grc",
		"runtime_id":               "writer-vrm",
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
		"runtime_id":      "writer-vrm",
		"attributes_json": attrs,
	}}
}

func relatedRow(urn string, entityType string, label string, relation string) ports.CypherRow {
	return ports.CypherRow{Values: map[string]any{
		"urn":             urn,
		"entity_type":     entityType,
		"label":           label,
		"source_id":       "grc",
		"runtime_id":      "writer-vrm",
		"relation":        relation,
		"attributes_json": "{}",
	}}
}
