package reports

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/structpb"
)

type stubFindingStore struct {
	findings []*ports.FindingRecord
	request  ports.ListFindingsRequest
}

func (s *stubFindingStore) Ping(context.Context) error { return nil }

func (s *stubFindingStore) UpsertFinding(context.Context, *ports.FindingRecord) (*ports.FindingRecord, error) {
	return nil, nil
}

func (s *stubFindingStore) GetFinding(_ context.Context, id string) (*ports.FindingRecord, error) {
	for _, finding := range s.findings {
		if finding != nil && finding.ID == id {
			return cloneFinding(finding), nil
		}
	}
	return nil, ports.ErrFindingNotFound
}

func (s *stubFindingStore) ListFindings(_ context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	s.request = request
	findings := make([]*ports.FindingRecord, 0, len(s.findings))
	for _, finding := range s.findings {
		if finding == nil {
			continue
		}
		if request.TenantID != "" && strings.TrimSpace(finding.TenantID) != strings.TrimSpace(request.TenantID) {
			continue
		}
		if request.RuntimeID != "" && strings.TrimSpace(finding.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
			continue
		}
		if len(request.RuntimeIDs) != 0 && !stringInSlice(request.RuntimeIDs, strings.TrimSpace(finding.RuntimeID)) {
			continue
		}
		findings = append(findings, cloneFinding(finding))
	}
	return findings, nil
}

func stringInSlice(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func (s *stubFindingStore) UpdateFindingStatus(_ context.Context, request ports.FindingStatusUpdate) (*ports.FindingRecord, error) {
	for _, finding := range s.findings {
		if finding == nil || finding.ID != request.FindingID {
			continue
		}
		cloned := cloneFinding(finding)
		cloned.Status = request.Status
		cloned.StatusReason = request.Reason
		cloned.StatusUpdatedAt = request.UpdatedAt
		return cloned, nil
	}
	return nil, ports.ErrFindingNotFound
}

func (s *stubFindingStore) UpdateFindingAssignee(_ context.Context, request ports.FindingAssigneeUpdate) (*ports.FindingRecord, error) {
	for _, finding := range s.findings {
		if finding == nil || finding.ID != request.FindingID {
			continue
		}
		cloned := cloneFinding(finding)
		cloned.Assignee = request.Assignee
		return cloned, nil
	}
	return nil, ports.ErrFindingNotFound
}

func (s *stubFindingStore) UpdateFindingDueDate(_ context.Context, request ports.FindingDueDateUpdate) (*ports.FindingRecord, error) {
	for _, finding := range s.findings {
		if finding == nil || finding.ID != request.FindingID {
			continue
		}
		cloned := cloneFinding(finding)
		cloned.DueAt = request.DueAt
		return cloned, nil
	}
	return nil, ports.ErrFindingNotFound
}

func (s *stubFindingStore) AddFindingNote(_ context.Context, request ports.FindingNoteCreate) (*ports.FindingRecord, error) {
	for _, finding := range s.findings {
		if finding == nil || finding.ID != request.FindingID {
			continue
		}
		cloned := cloneFinding(finding)
		cloned.Notes = append(cloned.Notes, request.Note)
		return cloned, nil
	}
	return nil, ports.ErrFindingNotFound
}

func (s *stubFindingStore) LinkFindingTicket(_ context.Context, request ports.FindingTicketLink) (*ports.FindingRecord, error) {
	for _, finding := range s.findings {
		if finding == nil || finding.ID != request.FindingID {
			continue
		}
		cloned := cloneFinding(finding)
		cloned.Tickets = append(cloned.Tickets, request.Ticket)
		return cloned, nil
	}
	return nil, ports.ErrFindingNotFound
}

func (s *stubFindingStore) LinkFindingExternalRef(_ context.Context, request ports.FindingExternalRefLink) (*ports.FindingRecord, error) {
	for _, finding := range s.findings {
		if finding == nil || finding.ID != request.FindingID {
			continue
		}
		cloned := cloneFinding(finding)
		cloned.ExternalRefs = append(cloned.ExternalRefs, request.ExternalRef)
		return cloned, nil
	}
	return nil, ports.ErrFindingNotFound
}

type stubGraphStore struct {
	rootURN       string
	limit         int
	calls         []string
	neighborhoods map[string]*ports.EntityNeighborhood
}

func (s *stubGraphStore) Ping(context.Context) error { return nil }

func (s *stubGraphStore) GetEntityNeighborhood(_ context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	s.rootURN = rootURN
	s.limit = limit
	s.calls = append(s.calls, rootURN)
	neighborhood, ok := s.neighborhoods[rootURN]
	if !ok {
		return nil, ports.ErrGraphEntityNotFound
	}
	return cloneNeighborhood(neighborhood), nil
}

func (s *stubGraphStore) ExecuteReadCypher(_ context.Context, _ ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	return nil, nil
}

type stubBatchGraphStore struct {
	*stubGraphStore
	batchCalls [][]string
	batchLimit int
}

func (s *stubBatchGraphStore) GetEntityNeighborhoods(_ context.Context, rootURNs []string, limit int) (map[string]*ports.EntityNeighborhood, error) {
	roots := append([]string(nil), rootURNs...)
	s.batchCalls = append(s.batchCalls, roots)
	s.batchLimit = limit
	neighborhoods := make(map[string]*ports.EntityNeighborhood, len(roots))
	for _, rootURN := range roots {
		neighborhood, ok := s.neighborhoods[rootURN]
		if !ok {
			continue
		}
		neighborhoods[rootURN] = cloneNeighborhood(neighborhood)
	}
	return neighborhoods, nil
}

type stubReportStore struct {
	run *cerebrov1.ReportRun
}

func (s *stubReportStore) Ping(context.Context) error { return nil }

func (s *stubReportStore) PutReportRun(_ context.Context, run *cerebrov1.ReportRun) error {
	s.run = cloneReportRun(run)
	return nil
}

func (s *stubReportStore) GetReportRun(_ context.Context, id string) (*cerebrov1.ReportRun, error) {
	if s.run == nil || s.run.GetId() != id {
		return nil, ports.ErrReportRunNotFound
	}
	return cloneReportRun(s.run), nil
}

func TestRunFindingSummaryReportPersistsCompletedRun(t *testing.T) {
	overdueDueAt := time.Now().UTC().Add(-2 * time.Hour)
	scheduledDueAt := time.Now().UTC().Add(24 * time.Hour)
	findingStore := &stubFindingStore{
		findings: []*ports.FindingRecord{
			{
				ID:        "finding-1",
				TenantID:  "writer",
				RuntimeID: "writer-okta-audit",
				RuleID:    "identity-okta-policy-rule-lifecycle-tampering",
				PolicyID:  "pol-1",
				CheckID:   "identity-okta-policy-rule-lifecycle-tampering-30d",
				CheckName: "Okta Policy Rule Lifecycle Tampering (30 days)",
				ControlRefs: []ports.FindingControlRef{
					{FrameworkName: "SOC 2", ControlID: "CC6.2"},
					{FrameworkName: "SOC 2", ControlID: "CC6.2"},
					{FrameworkName: "ISO 27001:2022", ControlID: "A.8.9"},
				},
				FindingWorkflow: ports.FindingWorkflow{
					Notes: []ports.FindingNote{
						{ID: "note-1", Body: "Escalate to identity engineering.", CreatedAt: time.Now().UTC().Add(-time.Hour)},
						{ID: "note-2", Body: "Awaiting owner confirmation.", CreatedAt: time.Now().UTC()},
					},
					Tickets: []ports.FindingTicket{
						{URL: "https://jira.writer.com/browse/ENG-123", Name: "ENG-123", ExternalID: "ENG-123", LinkedAt: time.Now().UTC().Add(-30 * time.Minute)},
					},
					DueAt: overdueDueAt,
				},
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				FindingRisk: ports.FindingRisk{
					RiskScore:       80,
					LikelihoodScore: 85,
					ImpactScore:     75,
					RiskReasons:     []string{"active", "external_exposure"},
					RiskFactors: []ports.FindingRiskFactor{
						{
							FactorID:             "external_exposure",
							Category:             "likelihood",
							Weight:               35,
							SeverityContribution: "high",
							EvidenceRefs:         []string{"attribute:internet_exposed"},
							ObservedAt:           time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
							SuppressionScope:     "factor:external_exposure",
						},
					},
					RiskModelVersion: "likelihood-impact-v2",
				},
				Attributes: map[string]string{
					"primary_resource_urn": "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				},
			},
			{
				ID:        "finding-2",
				TenantID:  "writer",
				RuntimeID: "writer-okta-audit",
				RuleID:    "identity-okta-policy-rule-lifecycle-tampering",
				PolicyID:  "pol-1",
				CheckID:   "identity-okta-policy-rule-lifecycle-tampering-30d",
				CheckName: "Okta Policy Rule Lifecycle Tampering (30 days)",
				ControlRefs: []ports.FindingControlRef{
					{FrameworkName: "SOC 2", ControlID: "CC6.2"},
					{FrameworkName: "ISO 27001:2022", ControlID: "A.8.9"},
				},
				FindingWorkflow: ports.FindingWorkflow{
					DueAt: scheduledDueAt,
				},
				Severity:     "HIGH",
				Status:       "resolved",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				FindingRisk: ports.FindingRisk{
					RiskFactors: []ports.FindingRiskFactor{
						{
							FactorID:             "external_exposure",
							Category:             "likelihood",
							Weight:               10,
							SeverityContribution: "high",
						},
					},
				},
				Attributes: map[string]string{
					"primary_resource_urn": "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				},
			},
		},
	}
	graphStore := &stubGraphStore{
		neighborhoods: map[string]*ports.EntityNeighborhood{
			"urn:cerebro:writer:okta_resource:policyrule:pol-1": {
				Root: &ports.NeighborhoodNode{
					URN:        "urn:cerebro:writer:okta_resource:policyrule:pol-1",
					EntityType: "okta.resource",
					Label:      "Require MFA",
				},
				Neighbors: []*ports.NeighborhoodNode{
					{
						URN:        "urn:cerebro:writer:okta_user:00u2",
						EntityType: "okta.user",
						Label:      "admin@writer.com",
					},
				},
				Relations: []*ports.NeighborhoodRelation{
					{
						FromURN:  "urn:cerebro:writer:okta_user:00u2",
						Relation: "acted_on",
						ToURN:    "urn:cerebro:writer:okta_resource:policyrule:pol-1",
					},
				},
			},
		},
	}
	reportStore := &stubReportStore{}
	service := New(findingStore, graphStore, reportStore)

	response, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: findingSummaryReportID,
		Parameters: map[string]string{
			reportParameterTenantID:   "writer",
			reportParameterRuntimeIDs: "writer-okta-audit",
			reportParameterGraphLimit: "2",
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if response.GetReport().GetId() != findingSummaryReportID {
		t.Fatalf("Run().Report.ID = %q, want %q", response.GetReport().GetId(), findingSummaryReportID)
	}
	if response.GetRun().GetReportId() != findingSummaryReportID {
		t.Fatalf("Run().Run.ReportId = %q, want %q", response.GetRun().GetReportId(), findingSummaryReportID)
	}
	if response.GetRun().GetStatus() != findingSummaryReportStatus {
		t.Fatalf("Run().Run.Status = %q, want %q", response.GetRun().GetStatus(), findingSummaryReportStatus)
	}
	if findingStore.request.TenantID != "writer" {
		t.Fatalf("ListFindings().TenantID = %q, want writer", findingStore.request.TenantID)
	}
	if findingStore.request.RuntimeID != "writer-okta-audit" {
		t.Fatalf("ListFindings().RuntimeID = %q, want writer-okta-audit", findingStore.request.RuntimeID)
	}
	result := response.GetRun().GetResult().AsMap()
	if got := result[reportParameterTenantID]; got != "writer" {
		t.Fatalf("Run().Run.Result[tenant_id] = %#v, want writer", got)
	}
	if got := result["total_findings"]; got != float64(2) {
		t.Fatalf("Run().Run.Result[total_findings] = %#v, want 2", got)
	}
	severityCounts, ok := result["severity_counts"].([]any)
	if !ok || len(severityCounts) != 1 {
		t.Fatalf("Run().Run.Result[severity_counts] = %#v, want 1 entry", result["severity_counts"])
	}
	dueStatusCounts, ok := result["due_status_counts"].([]any)
	if !ok || len(dueStatusCounts) != 2 {
		t.Fatalf("Run().Run.Result[due_status_counts] = %#v, want 2 entries", result["due_status_counts"])
	}
	seenDueStatuses := map[string]bool{}
	for _, rawEntry := range dueStatusCounts {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			t.Fatalf("due status count entry = %#v, want object", rawEntry)
		}
		status, ok := entry["due_status"].(string)
		if !ok || status == "" {
			t.Fatalf("due status bucket = %#v, want non-empty string", entry["due_status"])
		}
		seenDueStatuses[status] = true
		if got := entry["count"]; got != float64(1) {
			t.Fatalf("due status count = %#v, want 1", got)
		}
	}
	if !seenDueStatuses["overdue"] || !seenDueStatuses["scheduled"] {
		t.Fatalf("due status buckets = %#v, want overdue and scheduled", seenDueStatuses)
	}
	if got := result["note_count"]; got != float64(2) {
		t.Fatalf("Run().Run.Result[note_count] = %#v, want 2", got)
	}
	if got := result["noted_finding_count"]; got != float64(1) {
		t.Fatalf("Run().Run.Result[noted_finding_count] = %#v, want 1", got)
	}
	if got := result["ticket_count"]; got != float64(1) {
		t.Fatalf("Run().Run.Result[ticket_count] = %#v, want 1", got)
	}
	if got := result["ticketed_finding_count"]; got != float64(1) {
		t.Fatalf("Run().Run.Result[ticketed_finding_count] = %#v, want 1", got)
	}
	policyCounts, ok := result["policy_counts"].([]any)
	if !ok || len(policyCounts) != 1 {
		t.Fatalf("Run().Run.Result[policy_counts] = %#v, want 1 entry", result["policy_counts"])
	}
	checkCounts, ok := result["check_counts"].([]any)
	if !ok || len(checkCounts) != 1 {
		t.Fatalf("Run().Run.Result[check_counts] = %#v, want 1 entry", result["check_counts"])
	}
	checkEntry, ok := checkCounts[0].(map[string]any)
	if !ok {
		t.Fatalf("check count entry = %#v, want object", checkCounts[0])
	}
	if got := checkEntry["check_id"]; got != "identity-okta-policy-rule-lifecycle-tampering-30d" {
		t.Fatalf("check count check_id = %#v, want identity-okta-policy-rule-lifecycle-tampering-30d", got)
	}
	if got := checkEntry["check_name"]; got != "Okta Policy Rule Lifecycle Tampering (30 days)" {
		t.Fatalf("check count check_name = %#v, want check name", got)
	}
	if got := checkEntry["count"]; got != float64(2) {
		t.Fatalf("check count count = %#v, want 2", got)
	}
	controlCounts, ok := result["control_counts"].([]any)
	if !ok || len(controlCounts) != 2 {
		t.Fatalf("Run().Run.Result[control_counts] = %#v, want 2 entries", result["control_counts"])
	}
	for _, rawEntry := range controlCounts {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			t.Fatalf("control count entry = %#v, want object", rawEntry)
		}
		if got := entry["framework_name"]; got == "" {
			t.Fatalf("control count framework_name = %#v, want non-empty", got)
		}
		if got := entry["control_id"]; got == "" {
			t.Fatalf("control count control_id = %#v, want non-empty", got)
		}
		if got := entry["count"]; got != float64(2) {
			t.Fatalf("control count = %#v, want 2", got)
		}
	}
	resourceCounts, ok := result["resource_counts"].([]any)
	if !ok || len(resourceCounts) != 1 {
		t.Fatalf("Run().Run.Result[resource_counts] = %#v, want 1 entry", result["resource_counts"])
	}
	topRiskFindings, ok := result["top_risk_findings"].([]any)
	if !ok || len(topRiskFindings) != 1 {
		t.Fatalf("Run().Run.Result[top_risk_findings] = %#v, want 1 entry", result["top_risk_findings"])
	}
	topRiskFinding, ok := topRiskFindings[0].(map[string]any)
	if !ok {
		t.Fatalf("top risk finding = %#v, want object", topRiskFindings[0])
	}
	riskReasons, ok := topRiskFinding["risk_reasons"].([]any)
	if !ok || len(riskReasons) != 2 {
		t.Fatalf("top risk reasons = %#v, want serialized reasons", topRiskFinding["risk_reasons"])
	}
	riskFactors, ok := topRiskFinding["risk_factors"].([]any)
	if !ok || len(riskFactors) != 1 {
		t.Fatalf("top risk factors = %#v, want one serialized factor", topRiskFinding["risk_factors"])
	}
	riskFactorCounts, ok := result["risk_factor_counts"].([]any)
	if !ok || len(riskFactorCounts) != 1 {
		t.Fatalf("Run().Run.Result[risk_factor_counts] = %#v, want 1 entry", result["risk_factor_counts"])
	}
	riskFactorCount, ok := riskFactorCounts[0].(map[string]any)
	if !ok {
		t.Fatalf("risk factor count entry = %#v, want object", riskFactorCounts[0])
	}
	if got := riskFactorCount["factor_id"]; got != "external_exposure" {
		t.Fatalf("risk factor count factor_id = %#v, want external_exposure", got)
	}
	if got := riskFactorCount["count"]; got != float64(2) {
		t.Fatalf("risk factor count = %#v, want 2", got)
	}
	if got := riskFactorCount["weight_total"]; got != float64(45) {
		t.Fatalf("risk factor weight_total = %#v, want 45", got)
	}
	exposureAnalysis, ok := result["exposure_analysis"].(map[string]any)
	if !ok {
		t.Fatalf("Run().Run.Result[exposure_analysis] = %#v, want object", result["exposure_analysis"])
	}
	if _, ok := exposureAnalysis["compound_risks"].(map[string]any); !ok {
		t.Fatalf("exposure_analysis.compound_risks = %#v, want object", exposureAnalysis["compound_risks"])
	}
	if _, ok := exposureAnalysis["correlations"].([]any); !ok {
		t.Fatalf("exposure_analysis.correlations = %#v, want array", exposureAnalysis["correlations"])
	}
	graphEvidence, ok := result["graph_evidence"].([]any)
	if !ok || len(graphEvidence) != 1 {
		t.Fatalf("Run().Run.Result[graph_evidence] = %#v, want 1 entry", result["graph_evidence"])
	}
	graphEvidenceEntry, ok := graphEvidence[0].(map[string]any)
	if !ok {
		t.Fatalf("graph evidence entry = %#v, want object", graphEvidence[0])
	}
	if got := graphEvidenceEntry["status"]; got != graphEvidenceEntryStatusIncluded {
		t.Fatalf("graph evidence status = %#v, want %q", got, graphEvidenceEntryStatusIncluded)
	}
	if graphStore.rootURN != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("GetEntityNeighborhood().rootURN = %q, want policy rule urn", graphStore.rootURN)
	}
	if graphStore.limit != 2 {
		t.Fatalf("GetEntityNeighborhood().limit = %d, want 2", graphStore.limit)
	}
	if reportStore.run == nil {
		t.Fatal("PutReportRun() not called")
	}
	if got := reportStore.run.GetParameters()[reportParameterResourceLimit]; got != "3" {
		t.Fatalf("stored resource_limit = %q, want default 3", got)
	}
	if got := reportStore.run.GetParameters()[reportParameterGraphLimit]; got != "2" {
		t.Fatalf("stored graph_limit = %q, want 2", got)
	}
}

func TestRunFindingSummaryReportBatchesGraphEvidenceNeighborhoods(t *testing.T) {
	resourceOne := "urn:cerebro:writer:test_resource:one"
	resourceTwo := "urn:cerebro:writer:test_resource:two"
	findingStore := &stubFindingStore{
		findings: []*ports.FindingRecord{
			{
				ID:           "finding-1",
				TenantID:     "writer",
				RuntimeID:    "writer-runtime",
				RuleID:       "test-rule",
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{resourceOne},
				Attributes: map[string]string{
					"primary_resource_urn": resourceOne,
				},
			},
			{
				ID:           "finding-2",
				TenantID:     "writer",
				RuntimeID:    "writer-runtime",
				RuleID:       "test-rule",
				Severity:     "MEDIUM",
				Status:       "open",
				ResourceURNs: []string{resourceTwo},
				Attributes: map[string]string{
					"primary_resource_urn": resourceTwo,
				},
			},
		},
	}
	graphStore := &stubBatchGraphStore{
		stubGraphStore: &stubGraphStore{neighborhoods: map[string]*ports.EntityNeighborhood{
			resourceOne: testNeighborhood(resourceOne),
			resourceTwo: testNeighborhood(resourceTwo),
		}},
	}
	service := New(findingStore, graphStore, &stubReportStore{})

	response, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: findingSummaryReportID,
		Parameters: map[string]string{
			reportParameterTenantID:      "writer",
			reportParameterRuntimeIDs:    "writer-runtime",
			reportParameterGraphLimit:    "4",
			reportParameterResourceLimit: "2",
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	graphEvidence, ok := response.GetRun().GetResult().AsMap()["graph_evidence"].([]any)
	if !ok || len(graphEvidence) != 2 {
		t.Fatalf("graph_evidence = %#v, want 2 entries", response.GetRun().GetResult().AsMap()["graph_evidence"])
	}
	if len(graphStore.batchCalls) != 1 {
		t.Fatalf("GetEntityNeighborhoods() calls = %#v, want one batch", graphStore.batchCalls)
	}
	if got := graphStore.batchCalls[0]; len(got) != 2 || got[0] != resourceOne || got[1] != resourceTwo {
		t.Fatalf("GetEntityNeighborhoods().roots = %#v, want [%q %q]", got, resourceOne, resourceTwo)
	}
	if graphStore.batchLimit != 4 {
		t.Fatalf("GetEntityNeighborhoods().limit = %d, want 4", graphStore.batchLimit)
	}
	if len(graphStore.calls) != 0 {
		t.Fatalf("GetEntityNeighborhood() calls = %#v, want no individual lookups", graphStore.calls)
	}
}

func TestGraphEvidenceUsesBatchPartialResultsForMissingRoots(t *testing.T) {
	present := "urn:cerebro:writer:test_resource:present"
	missing := "urn:cerebro:writer:test_resource:missing"
	graphStore := &stubBatchGraphStore{
		stubGraphStore: &stubGraphStore{neighborhoods: map[string]*ports.EntityNeighborhood{
			present: testNeighborhood(present),
		}},
	}
	service := New(nil, graphStore, nil)

	evidence, neighborhoods, err := service.graphEvidence(context.Background(), map[string]int{
		present: 2,
		missing: 1,
	}, 2, 4)
	if err != nil {
		t.Fatalf("graphEvidence() error = %v", err)
	}
	if len(neighborhoods) != 1 || neighborhoods[present] == nil {
		t.Fatalf("graphEvidence() neighborhoods = %#v, want only present root", neighborhoods)
	}
	if len(evidence) != 2 {
		t.Fatalf("graphEvidence() evidence = %#v, want 2 entries", evidence)
	}
	included, ok := evidence[0].(map[string]any)
	if !ok || included["resource_urn"] != present || included["status"] != graphEvidenceEntryStatusIncluded {
		t.Fatalf("graphEvidence()[0] = %#v, want included present root", evidence[0])
	}
	notFound, ok := evidence[1].(map[string]any)
	if !ok || notFound["resource_urn"] != missing || notFound["status"] != graphEvidenceEntryStatusNotFound {
		t.Fatalf("graphEvidence()[1] = %#v, want missing root", evidence[1])
	}
	if len(graphStore.batchCalls) != 1 {
		t.Fatalf("GetEntityNeighborhoods() calls = %#v, want one batch", graphStore.batchCalls)
	}
	if got := graphStore.batchCalls[0]; len(got) != 2 || got[0] != present || got[1] != missing {
		t.Fatalf("GetEntityNeighborhoods().roots = %#v, want [%q %q]", got, present, missing)
	}
	if len(graphStore.calls) != 0 {
		t.Fatalf("GetEntityNeighborhood() calls = %#v, want no individual lookups", graphStore.calls)
	}
}

func TestRunFindingSummaryReportDoesNotPublishMultiRuntimeListAsRuntimeID(t *testing.T) {
	findingStore := &stubFindingStore{findings: []*ports.FindingRecord{
		{ID: "finding-1", TenantID: "example", RuntimeID: "example-github-audit", RuleID: "github-rule", Severity: "HIGH", Status: "OPEN"},
		{ID: "finding-2", TenantID: "example", RuntimeID: "example-okta-audit", RuleID: "okta-rule", Severity: "MEDIUM", Status: "OPEN"},
	}}
	service := New(findingStore, nil, &stubReportStore{})

	response, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: findingSummaryReportID,
		Parameters: map[string]string{
			reportParameterTenantID:      "example",
			reportParameterRuntimeIDs:    "example-github-audit,example-okta-audit",
			reportParameterGraphLimit:    "1",
			reportParameterResourceLimit: "1",
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if findingStore.request.RuntimeID != "" {
		t.Fatalf("ListFindings().RuntimeID = %q, want empty for multi-runtime request", findingStore.request.RuntimeID)
	}
	if got := findingStore.request.RuntimeIDs; len(got) != 2 || got[0] != "example-github-audit" || got[1] != "example-okta-audit" {
		t.Fatalf("ListFindings().RuntimeIDs = %#v, want both runtimes", got)
	}
	result := response.GetRun().GetResult().AsMap()
	runtimeIDs, ok := result[reportParameterRuntimeIDs].([]any)
	if !ok || len(runtimeIDs) != 2 || runtimeIDs[0] != "example-github-audit" || runtimeIDs[1] != "example-okta-audit" {
		t.Fatalf("Run().Run.Result[runtime_ids] = %#v, want both runtime ids", result[reportParameterRuntimeIDs])
	}
}

func TestRunRiskDeltaReportSimulatesPublicExposureRemoval(t *testing.T) {
	findingStore := &stubFindingStore{
		findings: []*ports.FindingRecord{
			{
				ID:           "cloud-public-prod-secrets",
				TenantID:     "writer",
				RuntimeID:    "writer-aws",
				RuleID:       "cloud-public-resource-exposure",
				Title:        "Cloud Public Resource Exposure",
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:aws_secret_store:prod-secrets"},
				Attributes: map[string]string{
					"action":               "public_network_ingress",
					"crown_jewel":          "true",
					"internet_exposed":     "true",
					"rule_source_id":       "cloud",
					"primary_resource_urn": "urn:cerebro:writer:aws_secret_store:prod-secrets",
				},
			},
		},
	}
	graphStore := &stubGraphStore{
		neighborhoods: map[string]*ports.EntityNeighborhood{
			"urn:cerebro:writer:aws_secret_store:prod-secrets": {
				Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
				Neighbors: []*ports.NeighborhoodNode{
					{URN: "urn:cerebro:writer:aws_public_principal:public_internet", EntityType: "aws.public_principal", Label: "public internet"},
					{URN: "urn:cerebro:writer:finding:cloud-public-prod-secrets", EntityType: "finding", Label: "cloud-public-prod-secrets"},
				},
				Relations: []*ports.NeighborhoodRelation{
					{FromURN: "urn:cerebro:writer:aws_public_principal:public_internet", Relation: "can_reach", ToURN: "urn:cerebro:writer:aws_secret_store:prod-secrets"},
					{FromURN: "urn:cerebro:writer:aws_secret_store:prod-secrets", Relation: "has_finding", ToURN: "urn:cerebro:writer:finding:cloud-public-prod-secrets"},
				},
			},
		},
	}
	service := New(findingStore, graphStore, &stubReportStore{})

	response, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: riskDeltaReportID,
		Parameters: map[string]string{
			reportParameterTenantID:     "writer",
			reportParameterRuntimeIDs:   "writer-aws",
			reportParameterScenarioType: findinganalysis.RiskDeltaScenarioRemovePublicExposure,
			reportParameterTargetURN:    "urn:cerebro:writer:aws_secret_store:prod-secrets",
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	result := response.GetRun().GetResult().AsMap()
	if got := result[reportParameterScenarioType]; got != findinganalysis.RiskDeltaScenarioRemovePublicExposure {
		t.Fatalf("scenario_type = %#v, want remove_public_exposure", got)
	}
	if got := result["graph_evidence_status"]; got != graphEvidenceStatusIncluded {
		t.Fatalf("graph_evidence_status = %#v, want included", got)
	}
	if got := result["graph_neighborhood_count"]; got != float64(1) {
		t.Fatalf("graph_neighborhood_count = %#v, want 1", got)
	}
	if got := result["risk_score_reduction"]; got.(float64) <= 0 {
		t.Fatalf("risk_score_reduction = %#v, want positive", got)
	}
	if got := result["attack_path_score_reduction"]; got.(float64) <= 0 {
		t.Fatalf("attack_path_score_reduction = %#v, want positive", got)
	}
	riskDelta, ok := result["risk_delta"].(map[string]any)
	if !ok {
		t.Fatalf("risk_delta = %#v, want object", result["risk_delta"])
	}
	affected, ok := riskDelta["affected_findings"].([]any)
	if !ok || len(affected) != 1 {
		t.Fatalf("risk_delta.affected_findings = %#v, want one affected finding", riskDelta["affected_findings"])
	}
	removedPaths, ok := riskDelta["removed_attack_paths"].([]any)
	if !ok || len(removedPaths) == 0 {
		t.Fatalf("risk_delta.removed_attack_paths = %#v, want removed public path", riskDelta["removed_attack_paths"])
	}
}

func TestRiskDeltaGraphNeighborhoodsBatchesRoots(t *testing.T) {
	target := "urn:cerebro:writer:test_resource:target"
	related := "urn:cerebro:writer:test_resource:related"
	graphStore := &stubBatchGraphStore{
		stubGraphStore: &stubGraphStore{neighborhoods: map[string]*ports.EntityNeighborhood{
			target:  testNeighborhood(target),
			related: testNeighborhood(related),
		}},
	}
	service := New(nil, graphStore, nil)

	neighborhoods, err := service.riskDeltaGraphNeighborhoods(context.Background(), target, []*ports.FindingRecord{
		{Attributes: map[string]string{"primary_resource_urn": related}},
	}, 2, 6)
	if err != nil {
		t.Fatalf("riskDeltaGraphNeighborhoods() error = %v", err)
	}
	if len(neighborhoods) != 2 {
		t.Fatalf("riskDeltaGraphNeighborhoods() = %#v, want 2 neighborhoods", neighborhoods)
	}
	if len(graphStore.batchCalls) != 1 {
		t.Fatalf("GetEntityNeighborhoods() calls = %#v, want one batch", graphStore.batchCalls)
	}
	if got := graphStore.batchCalls[0]; len(got) != 2 || got[0] != target || got[1] != related {
		t.Fatalf("GetEntityNeighborhoods().roots = %#v, want [%q %q]", got, target, related)
	}
	if graphStore.batchLimit != 6 {
		t.Fatalf("GetEntityNeighborhoods().limit = %d, want 6", graphStore.batchLimit)
	}
	if len(graphStore.calls) != 0 {
		t.Fatalf("GetEntityNeighborhood() calls = %#v, want no individual lookups", graphStore.calls)
	}
}

func TestRunRiskDeltaReportRejectsCrossTenantTargetURN(t *testing.T) {
	graphStore := &stubGraphStore{
		neighborhoods: map[string]*ports.EntityNeighborhood{
			"urn:cerebro:other:aws_secret_store:prod-secrets": {
				Root: &ports.NeighborhoodNode{URN: "urn:cerebro:other:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
			},
		},
	}
	service := New(&stubFindingStore{}, graphStore, &stubReportStore{})

	_, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: riskDeltaReportID,
		Parameters: map[string]string{
			reportParameterTenantID:     "writer",
			reportParameterRuntimeIDs:   "writer-aws",
			reportParameterScenarioType: findinganalysis.RiskDeltaScenarioRemovePublicExposure,
			reportParameterTargetURN:    "urn:cerebro:other:aws_secret_store:prod-secrets",
		},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Run() error = %v, want %v", err, ErrInvalidRequest)
	}
	if graphStore.rootURN != "" {
		t.Fatalf("GetEntityNeighborhood rootURN = %q, want no cross-tenant graph read", graphStore.rootURN)
	}
}

func TestRiskActionPlanGraphNeighborhoodsBatchesUniqueLimitedRoots(t *testing.T) {
	first := "urn:cerebro:writer:test_resource:first"
	second := "urn:cerebro:writer:test_resource:second"
	third := "urn:cerebro:writer:test_resource:third"
	graphStore := &stubBatchGraphStore{
		stubGraphStore: &stubGraphStore{neighborhoods: map[string]*ports.EntityNeighborhood{
			first:  testNeighborhood(first),
			second: testNeighborhood(second),
			third:  testNeighborhood(third),
		}},
	}
	service := New(nil, graphStore, nil)

	neighborhoods, err := service.riskActionPlanGraphNeighborhoods(context.Background(), []string{first, "", first, second, third}, 2, 5)
	if err != nil {
		t.Fatalf("riskActionPlanGraphNeighborhoods() error = %v", err)
	}
	if len(neighborhoods) != 2 {
		t.Fatalf("riskActionPlanGraphNeighborhoods() = %#v, want 2 neighborhoods", neighborhoods)
	}
	if len(graphStore.batchCalls) != 1 {
		t.Fatalf("GetEntityNeighborhoods() calls = %#v, want one batch", graphStore.batchCalls)
	}
	if got := graphStore.batchCalls[0]; len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("GetEntityNeighborhoods().roots = %#v, want [%q %q]", got, first, second)
	}
	if graphStore.batchLimit != 5 {
		t.Fatalf("GetEntityNeighborhoods().limit = %d, want 5", graphStore.batchLimit)
	}
	if len(graphStore.calls) != 0 {
		t.Fatalf("GetEntityNeighborhood() calls = %#v, want no individual lookups", graphStore.calls)
	}
}

func TestRunRiskActionPlanReportRanksSimulatedRemediations(t *testing.T) {
	findingStore := &stubFindingStore{
		findings: []*ports.FindingRecord{
			{
				ID:           "cloud-public-prod-secrets",
				TenantID:     "writer",
				RuntimeID:    "writer-aws",
				RuleID:       "cloud-public-resource-exposure",
				Title:        "Cloud Public Resource Exposure",
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:aws_secret_store:prod-secrets"},
				FindingWorkflow: ports.FindingWorkflow{
					Assignee: "cloud-platform",
				},
				FindingRisk: ports.FindingRisk{
					RiskScore:       90,
					ConfidenceScore: 92,
					RiskReasons:     []string{"external_exposure", "crown_jewel"},
					RiskFactors: []ports.FindingRiskFactor{
						{FactorID: "external_exposure", Category: "likelihood", Weight: 35, SeverityContribution: "high", EvidenceRefs: []string{"attribute:internet_exposed"}},
						{FactorID: "crown_jewel", Category: "impact", Weight: 35, SeverityContribution: "high", EvidenceRefs: []string{"attribute:crown_jewel"}},
					},
				},
				Attributes: map[string]string{
					"action":               "public_network_ingress",
					"crown_jewel":          "true",
					"internet_exposed":     "true",
					"primary_resource_urn": "urn:cerebro:writer:aws_secret_store:prod-secrets",
					"resource_name":        "prod-secrets",
				},
			},
			{
				ID:           "repo-kev-package",
				TenantID:     "writer",
				RuntimeID:    "writer-github",
				RuleID:       "vulnerability-known-exploited",
				Title:        "Known exploited dependency",
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:github_repository:payments-api"},
				FindingRisk: ports.FindingRisk{
					RiskScore:       78,
					ConfidenceScore: 88,
					RiskReasons:     []string{"known_exploited", "cvss_high"},
					RiskFactors: []ports.FindingRiskFactor{
						{FactorID: "known_exploited", Category: "likelihood", Weight: 35, SeverityContribution: "high", EvidenceRefs: []string{"attribute:is_kev"}},
					},
				},
				Attributes: map[string]string{
					"cvss_score":           "8.7",
					"is_kev":               "true",
					"package":              "example-lib",
					"primary_resource_urn": "urn:cerebro:writer:github_repository:payments-api",
				},
			},
		},
	}
	graphStore := &stubGraphStore{
		neighborhoods: map[string]*ports.EntityNeighborhood{
			"urn:cerebro:writer:aws_secret_store:prod-secrets": {
				Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
				Neighbors: []*ports.NeighborhoodNode{
					{URN: "urn:cerebro:writer:aws_public_principal:public_internet", EntityType: "aws.public_principal", Label: "public internet"},
					{URN: "urn:cerebro:writer:finding:cloud-public-prod-secrets", EntityType: "finding", Label: "cloud-public-prod-secrets"},
				},
				Relations: []*ports.NeighborhoodRelation{
					{FromURN: "urn:cerebro:writer:aws_public_principal:public_internet", Relation: "can_reach", ToURN: "urn:cerebro:writer:aws_secret_store:prod-secrets"},
					{FromURN: "urn:cerebro:writer:aws_secret_store:prod-secrets", Relation: "has_finding", ToURN: "urn:cerebro:writer:finding:cloud-public-prod-secrets"},
				},
			},
			"urn:cerebro:writer:github_repository:payments-api": {
				Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:github_repository:payments-api", EntityType: "github.repository", Label: "payments-api"},
			},
		},
	}
	service := New(findingStore, graphStore, &stubReportStore{})

	response, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: riskActionPlanReportID,
		Parameters: map[string]string{
			reportParameterTenantID:       "writer",
			reportParameterRuntimeIDs:     "writer-aws, writer-github",
			reportParameterCandidateLimit: "2",
			reportParameterResourceLimit:  "2",
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if findingStore.request.RuntimeID != "" {
		t.Fatalf("ListFindings().RuntimeID = %q, want empty for multi-runtime request", findingStore.request.RuntimeID)
	}
	if got := findingStore.request.RuntimeIDs; len(got) != 2 || got[0] != "writer-aws" || got[1] != "writer-github" {
		t.Fatalf("ListFindings().RuntimeIDs = %#v, want both runtimes", got)
	}
	result := response.GetRun().GetResult().AsMap()
	if got := result["graph_evidence_status"]; got != graphEvidenceStatusIncluded {
		t.Fatalf("graph_evidence_status = %#v, want included", got)
	}
	if got := result["graph_neighborhood_count"]; got != float64(2) {
		t.Fatalf("graph_neighborhood_count = %#v, want 2", got)
	}
	candidates, ok := result["action_candidates"].([]any)
	if !ok || len(candidates) != 2 {
		t.Fatalf("action_candidates = %#v, want 2 entries", result["action_candidates"])
	}
	topCandidate, ok := candidates[0].(map[string]any)
	if !ok {
		t.Fatalf("top candidate = %#v, want object", candidates[0])
	}
	if got := topCandidate["scenario_type"]; got != findinganalysis.RiskDeltaScenarioRemovePublicExposure {
		t.Fatalf("top scenario_type = %#v, want remove_public_exposure", got)
	}
	if got := topCandidate["target_urn"]; got != "urn:cerebro:writer:aws_secret_store:prod-secrets" {
		t.Fatalf("top target_urn = %#v, want prod secrets", got)
	}
	if got := topCandidate["owner"]; got != "cloud-platform" {
		t.Fatalf("top owner = %#v, want cloud-platform", got)
	}
	if got := topCandidate["expected_risk_score_reduction"]; got.(float64) <= 0 {
		t.Fatalf("expected risk reduction = %#v, want positive", got)
	}
	if got := topCandidate["expected_attack_path_score_reduction"]; got.(float64) <= 0 {
		t.Fatalf("expected attack path reduction = %#v, want positive", got)
	}
	riskDelta, ok := topCandidate["risk_delta"].(map[string]any)
	if !ok {
		t.Fatalf("risk_delta = %#v, want object", topCandidate["risk_delta"])
	}
	removedPaths, ok := riskDelta["removed_attack_paths"].([]any)
	if !ok || len(removedPaths) == 0 {
		t.Fatalf("risk_delta.removed_attack_paths = %#v, want removed public path", riskDelta["removed_attack_paths"])
	}
	if got := response.GetRun().GetParameters()[reportParameterCandidateLimit]; got != "2" {
		t.Fatalf("stored candidate_limit = %q, want 2", got)
	}
}

func TestRunRiskActionPlanReportWithoutGraphStoreUsesFindingSignals(t *testing.T) {
	findingStore := &stubFindingStore{
		findings: []*ports.FindingRecord{
			{
				ID:           "repo-kev-package",
				TenantID:     "writer",
				RuntimeID:    "writer-github",
				RuleID:       "vulnerability-known-exploited",
				Title:        "Known exploited dependency",
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:github_repository:payments-api"},
				Attributes: map[string]string{
					"cvss_score":           "9.1",
					"is_kev":               "true",
					"primary_resource_urn": "urn:cerebro:writer:github_repository:payments-api",
				},
			},
		},
	}
	service := New(findingStore, nil, &stubReportStore{})

	response, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: riskActionPlanReportID,
		Parameters: map[string]string{
			reportParameterTenantID:   "writer",
			reportParameterRuntimeIDs: "writer-github",
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	result := response.GetRun().GetResult().AsMap()
	if got := result["graph_evidence_status"]; got != graphEvidenceStatusUnconfigured {
		t.Fatalf("graph_evidence_status = %#v, want unconfigured", got)
	}
	candidates, ok := result["action_candidates"].([]any)
	if !ok || len(candidates) != 1 {
		t.Fatalf("action_candidates = %#v, want one entry", result["action_candidates"])
	}
	candidate := candidates[0].(map[string]any)
	if got := candidate["scenario_type"]; got != findinganalysis.RiskDeltaScenarioPatchVulnerability {
		t.Fatalf("scenario_type = %#v, want patch_vulnerability", got)
	}
	if got := candidate["expected_risk_score_reduction"]; got.(float64) <= 0 {
		t.Fatalf("expected risk reduction = %#v, want positive", got)
	}
}

func TestRunRiskActionPlanReportIncludesUnscoredCandidatesAndDiff(t *testing.T) {
	previousResult, err := structpb.NewStruct(map[string]any{
		"action_candidates": []any{
			map[string]any{
				"id":                            "assign-owner-urn-cerebro-writer-service-payments",
				"title":                         "Assign owner for payments",
				"priority_score":                1,
				"expected_risk_score_reduction": 0,
				"simulation_status":             "unsupported",
			},
			map[string]any{
				"id":             "removed-candidate",
				"title":          "Removed candidate",
				"priority_score": 10,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewStruct(previousResult) error = %v", err)
	}
	reportStore := &stubReportStore{run: &cerebrov1.ReportRun{
		Id:         "previous-plan",
		ReportId:   riskActionPlanReportID,
		Parameters: map[string]string{reportParameterTenantID: "writer"},
		Result:     previousResult,
	}}
	findingStore := &stubFindingStore{
		findings: []*ports.FindingRecord{
			{
				ID:           "ownerless-control-gap",
				TenantID:     "writer",
				RuntimeID:    "writer-grc",
				RuleID:       "control-owner-missing",
				Title:        "High risk control gap",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:service:payments"},
				FindingRisk: ports.FindingRisk{
					RiskScore:       82,
					ConfidenceScore: 42,
					RiskReasons:     []string{"crown_jewel"},
				},
				Attributes: map[string]string{
					"primary_resource_urn": "urn:cerebro:writer:service:payments",
					"resource_name":        "payments",
				},
				LastObservedAt: time.Now().UTC().Add(-45 * 24 * time.Hour),
			},
		},
	}
	service := New(findingStore, nil, reportStore)

	response, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: riskActionPlanReportID,
		Parameters: map[string]string{
			reportParameterTenantID:            "writer",
			reportParameterRuntimeIDs:          "writer-grc",
			reportParameterIncludeUnscored:     "true",
			reportParameterPreviousReportRunID: "previous-plan",
			reportParameterCandidateLimit:      "5",
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	result := response.GetRun().GetResult().AsMap()
	if result[reportParameterIncludeUnscored] != true {
		t.Fatalf("include_unscored = %#v, want true", result[reportParameterIncludeUnscored])
	}
	candidates, ok := result["action_candidates"].([]any)
	if !ok || len(candidates) != 2 {
		t.Fatalf("action_candidates = %#v, want two unscored candidates", result["action_candidates"])
	}
	types := map[string]bool{}
	for _, raw := range candidates {
		candidate := raw.(map[string]any)
		if candidate["simulation_status"] != "unsupported" {
			t.Fatalf("candidate = %#v, want unsupported status", candidate)
		}
		types[candidate["action_type"].(string)] = true
	}
	if !types["assign_owner"] || !types["refresh_evidence"] {
		t.Fatalf("candidate types = %#v, want assign_owner and refresh_evidence", types)
	}
	planDiff, ok := result["plan_diff"].(map[string]any)
	if !ok {
		t.Fatalf("plan_diff = %#v, want object", result["plan_diff"])
	}
	if len(planDiff["added"].([]any)) != 1 || len(planDiff["changed"].([]any)) != 1 || len(planDiff["removed"].([]any)) != 1 {
		t.Fatalf("plan_diff = %#v, want one added, changed, and removed candidate", planDiff)
	}
	plan := result["plan"].(map[string]any)
	if plan["model_version"] != "risk-action-plan-v2" || plan["plan_diff"] == nil {
		t.Fatalf("plan = %#v, want typed plan with diff", plan)
	}
}

func TestRunRiskActionPlanReportRejectsCrossTenantPreviousRun(t *testing.T) {
	previousResult, err := structpb.NewStruct(map[string]any{
		"action_candidates": []any{
			map[string]any{
				"id":                "remove-public-exposure-urn-cerebro-other-service-billing",
				"title":             "Remove public exposure from other tenant billing",
				"target_urn":        "urn:cerebro:other:service:billing",
				"priority_score":    100,
				"simulation_status": "simulated",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewStruct(previousResult) error = %v", err)
	}
	reportStore := &stubReportStore{run: &cerebrov1.ReportRun{
		Id:         "previous-plan",
		ReportId:   riskActionPlanReportID,
		Parameters: map[string]string{reportParameterTenantID: "other"},
		Result:     previousResult,
	}}
	findingStore := &stubFindingStore{
		findings: []*ports.FindingRecord{
			{
				ID:           "ownerless-control-gap",
				TenantID:     "writer",
				RuntimeID:    "writer-grc",
				RuleID:       "control-owner-missing",
				Title:        "High risk control gap",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:service:payments"},
				FindingRisk: ports.FindingRisk{
					RiskScore:       82,
					ConfidenceScore: 42,
					RiskReasons:     []string{"crown_jewel"},
				},
				Attributes: map[string]string{
					"primary_resource_urn": "urn:cerebro:writer:service:payments",
					"resource_name":        "payments",
				},
				LastObservedAt: time.Now().UTC().Add(-45 * 24 * time.Hour),
			},
		},
	}
	service := New(findingStore, nil, reportStore)

	_, err = service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: riskActionPlanReportID,
		Parameters: map[string]string{
			reportParameterTenantID:            "writer",
			reportParameterRuntimeIDs:          "writer-grc",
			reportParameterIncludeUnscored:     "true",
			reportParameterPreviousReportRunID: "previous-plan",
		},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Run() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetReportRunRequiresAvailableStore(t *testing.T) {
	service := New(nil, nil, nil)
	if _, err := service.Get(context.Background(), &cerebrov1.GetReportRunRequest{Id: "report-run-1"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("Get() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestRunReportValidationErrorsAreInvalidRequest(t *testing.T) {
	service := New(&stubFindingStore{}, nil, &stubReportStore{})
	if _, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Run() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestListReportDefinitionsIncludesFindingSummary(t *testing.T) {
	response := New(nil, nil, nil).List()
	if len(response.GetReports()) != 3 {
		t.Fatalf("len(List().Reports) = %d, want 3", len(response.GetReports()))
	}
	reportsByID := map[string]*cerebrov1.ReportDefinition{}
	for _, report := range response.GetReports() {
		reportsByID[report.GetId()] = report
	}
	if reportsByID[findingSummaryReportID] == nil {
		t.Fatalf("List().Reports = %#v, want finding summary definition", response.GetReports())
	}
	if reportsByID[riskDeltaReportID] == nil {
		t.Fatalf("List().Reports = %#v, want risk delta definition", response.GetReports())
	}
	if reportsByID[riskActionPlanReportID] == nil {
		t.Fatalf("List().Reports = %#v, want risk action plan definition", response.GetReports())
	}
	parameters := reportParametersByID(reportsByID[findingSummaryReportID].GetParameters())
	if !parameters[reportParameterRuntimeIDs].GetRequired() {
		t.Fatalf("runtime_ids parameter Required = false, want true")
	}
	riskDeltaParameters := reportParametersByID(reportsByID[riskDeltaReportID].GetParameters())
	if !riskDeltaParameters[reportParameterScenarioType].GetRequired() || !riskDeltaParameters[reportParameterTargetURN].GetRequired() {
		t.Fatalf("risk delta parameters = %#v, want scenario_type and target_urn required", riskDeltaParameters)
	}
	riskActionPlanParameters := reportParametersByID(reportsByID[riskActionPlanReportID].GetParameters())
	if !riskActionPlanParameters[reportParameterRuntimeIDs].GetRequired() || riskActionPlanParameters[reportParameterCandidateLimit].GetRequired() {
		t.Fatalf("risk action plan parameters = %#v, want runtime_ids required and candidate_limit optional", riskActionPlanParameters)
	}
}

func reportParametersByID(parameters []*cerebrov1.ReportParameter) map[string]*cerebrov1.ReportParameter {
	byID := make(map[string]*cerebrov1.ReportParameter, len(parameters))
	for _, parameter := range parameters {
		byID[parameter.GetId()] = parameter
	}
	return byID
}

func TestReportRunIDIncludesEntropy(t *testing.T) {
	generatedAt := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	first, err := reportRunID(findingSummaryReportID, generatedAt)
	if err != nil {
		t.Fatalf("reportRunID(first) error = %v", err)
	}
	second, err := reportRunID(findingSummaryReportID, generatedAt)
	if err != nil {
		t.Fatalf("reportRunID(second) error = %v", err)
	}
	if first == second {
		t.Fatalf("reportRunID() returned duplicate id %q", first)
	}
}

func TestRunFindingSummaryReportWithoutGraphStoreMarksEvidenceUnconfigured(t *testing.T) {
	findingStore := &stubFindingStore{
		findings: []*ports.FindingRecord{
			{
				ID:        "finding-1",
				TenantID:  "writer",
				RuntimeID: "writer-okta-audit",
				RuleID:    "identity-okta-policy-rule-lifecycle-tampering",
				Severity:  "HIGH",
				Status:    "open",
				ResourceURNs: []string{
					"urn:cerebro:writer:okta_resource:policyrule:pol-1",
				},
			},
		},
	}
	service := New(findingStore, nil, &stubReportStore{})

	response, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: findingSummaryReportID,
		Parameters: map[string]string{
			reportParameterTenantID:   "writer",
			reportParameterRuntimeIDs: "writer-okta-audit",
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := response.GetRun().GetResult().AsMap()["graph_evidence_status"]; got != graphEvidenceStatusUnconfigured {
		t.Fatalf("graph_evidence_status = %#v, want %q", got, graphEvidenceStatusUnconfigured)
	}
	exposureAnalysis, ok := response.GetRun().GetResult().AsMap()["exposure_analysis"].(map[string]any)
	if !ok {
		t.Fatalf("exposure_analysis = %#v, want object", response.GetRun().GetResult().AsMap()["exposure_analysis"])
	}
	if attackPaths, ok := exposureAnalysis["attack_paths"].([]any); ok && len(attackPaths) != 0 {
		t.Fatalf("attack_paths = %#v, want empty when graph evidence is unconfigured", attackPaths)
	}
}

func TestRunFindingSummaryReportSupportsRuntimeIDs(t *testing.T) {
	findingStore := &stubFindingStore{
		findings: []*ports.FindingRecord{
			{
				ID:        "okta-finding",
				TenantID:  "example",
				RuntimeID: "example-okta-audit",
				RuleID:    "identity-okta-policy-rule-lifecycle-tampering",
				Severity:  "HIGH",
				Status:    "open",
			},
			{
				ID:        "github-finding",
				TenantID:  "example",
				RuntimeID: "example-github-audit",
				RuleID:    "github-secret-scanning-alert-created",
				Severity:  "HIGH",
				Status:    "open",
			},
			{
				ID:        "other-finding",
				TenantID:  "example",
				RuntimeID: "example-aws",
				RuleID:    "cloud-public-resource-exposure",
				Severity:  "HIGH",
				Status:    "open",
			},
		},
	}
	service := New(findingStore, nil, &stubReportStore{})

	response, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: findingSummaryReportID,
		Parameters: map[string]string{
			reportParameterTenantID:   "example",
			reportParameterRuntimeIDs: "example-github-audit, example-okta-audit",
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if findingStore.request.RuntimeID != "" {
		t.Fatalf("ListFindings().RuntimeID = %q, want empty for multi-runtime", findingStore.request.RuntimeID)
	}
	if got := findingStore.request.RuntimeIDs; len(got) != 2 {
		t.Fatalf("ListFindings().RuntimeIDs = %#v, want 2", got)
	}
	result := response.GetRun().GetResult().AsMap()
	if got := result["total_findings"]; got != float64(2) {
		t.Fatalf("total_findings = %#v, want 2", got)
	}
	runtimeCounts, ok := result["runtime_counts"].([]any)
	if !ok || len(runtimeCounts) != 2 {
		t.Fatalf("runtime_counts = %#v, want 2 entries", result["runtime_counts"])
	}
	sourceCounts, ok := result["source_counts"].([]any)
	if !ok || len(sourceCounts) != 2 {
		t.Fatalf("source_counts = %#v, want 2 entries", result["source_counts"])
	}
}

func TestTopRiskFindingEntriesKeepsSeverityTieBreakBeforeLimit(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	findings := []*ports.FindingRecord{}
	for i := 0; i < 11; i++ {
		findings = append(findings, &ports.FindingRecord{
			ID:             fmt.Sprintf("low-%02d", i),
			Title:          "Low risk tie",
			Severity:       "LOW",
			LastObservedAt: now.Add(time.Duration(i) * time.Minute),
			FindingRisk: ports.FindingRisk{
				RiskScore: 70,
			},
		})
	}
	findings = append(findings, &ports.FindingRecord{
		ID:             "critical-old",
		Title:          "Critical risk tie",
		Severity:       "CRITICAL",
		LastObservedAt: now.Add(-time.Hour),
		FindingRisk: ports.FindingRisk{
			RiskScore: 70,
		},
	})
	entries := topRiskFindingEntries(findings, 10)
	foundCritical := false
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("top risk entry = %#v, want object", raw)
		}
		if entry["finding_id"] == "critical-old" {
			foundCritical = true
			break
		}
	}
	if !foundCritical {
		t.Fatalf("topRiskFindingEntries() = %#v, want critical tie included before newer lows", entries)
	}
}

func cloneFinding(finding *ports.FindingRecord) *ports.FindingRecord {
	if finding == nil {
		return nil
	}
	return &ports.FindingRecord{
		ID:                finding.ID,
		Fingerprint:       finding.Fingerprint,
		TenantID:          finding.TenantID,
		RuntimeID:         finding.RuntimeID,
		RuleID:            finding.RuleID,
		Title:             finding.Title,
		Severity:          finding.Severity,
		Status:            finding.Status,
		Summary:           finding.Summary,
		ResourceURNs:      append([]string(nil), finding.ResourceURNs...),
		EventIDs:          append([]string(nil), finding.EventIDs...),
		ObservedPolicyIDs: append([]string(nil), finding.ObservedPolicyIDs...),
		PolicyID:          finding.PolicyID,
		PolicyName:        finding.PolicyName,
		CheckID:           finding.CheckID,
		CheckName:         finding.CheckName,
		ControlRefs:       append([]ports.FindingControlRef(nil), finding.ControlRefs...),
		FindingWorkflow: ports.FindingWorkflow{
			Notes:           append([]ports.FindingNote(nil), finding.Notes...),
			Tickets:         append([]ports.FindingTicket(nil), finding.Tickets...),
			ExternalRefs:    append([]ports.FindingExternalRef(nil), finding.ExternalRefs...),
			Assignee:        finding.Assignee,
			DueAt:           finding.DueAt,
			StatusReason:    finding.StatusReason,
			StatusUpdatedAt: finding.StatusUpdatedAt,
		},
		FindingRisk: ports.FindingRisk{
			RiskScore:        finding.RiskScore,
			LikelihoodScore:  finding.LikelihoodScore,
			ImpactScore:      finding.ImpactScore,
			ConfidenceScore:  finding.ConfidenceScore,
			LikelihoodLevel:  finding.LikelihoodLevel,
			ImpactLevel:      finding.ImpactLevel,
			RiskReasons:      append([]string(nil), finding.RiskReasons...),
			RiskFactors:      append([]ports.FindingRiskFactor(nil), finding.RiskFactors...),
			RiskModelVersion: finding.RiskModelVersion,
		},
		Attributes:      cloneAttributes(finding.Attributes),
		FirstObservedAt: finding.FirstObservedAt,
		LastObservedAt:  finding.LastObservedAt,
	}
}

func cloneReportRun(run *cerebrov1.ReportRun) *cerebrov1.ReportRun {
	if run == nil {
		return nil
	}
	cloned := &cerebrov1.ReportRun{
		Id:          run.GetId(),
		ReportId:    run.GetReportId(),
		Parameters:  cloneAttributes(run.GetParameters()),
		Status:      run.GetStatus(),
		GeneratedAt: run.GetGeneratedAt(),
	}
	if run.GetResult() != nil {
		cloned.Result = run.GetResult()
	}
	return cloned
}

func cloneNeighborhood(neighborhood *ports.EntityNeighborhood) *ports.EntityNeighborhood {
	if neighborhood == nil {
		return nil
	}
	cloned := &ports.EntityNeighborhood{
		Root:      cloneNeighborhoodNode(neighborhood.Root),
		Neighbors: make([]*ports.NeighborhoodNode, 0, len(neighborhood.Neighbors)),
		Relations: make([]*ports.NeighborhoodRelation, 0, len(neighborhood.Relations)),
	}
	for _, neighbor := range neighborhood.Neighbors {
		cloned.Neighbors = append(cloned.Neighbors, cloneNeighborhoodNode(neighbor))
	}
	for _, relation := range neighborhood.Relations {
		cloned.Relations = append(cloned.Relations, cloneNeighborhoodRelation(relation))
	}
	return cloned
}

func testNeighborhood(rootURN string) *ports.EntityNeighborhood {
	return &ports.EntityNeighborhood{
		Root: &ports.NeighborhoodNode{
			URN:        rootURN,
			EntityType: "test.resource",
			Label:      rootURN,
		},
		Neighbors: []*ports.NeighborhoodNode{},
		Relations: []*ports.NeighborhoodRelation{},
	}
}

func cloneNeighborhoodNode(node *ports.NeighborhoodNode) *ports.NeighborhoodNode {
	if node == nil {
		return nil
	}
	return &ports.NeighborhoodNode{
		URN:        node.URN,
		EntityType: node.EntityType,
		Label:      node.Label,
	}
}

func cloneNeighborhoodRelation(relation *ports.NeighborhoodRelation) *ports.NeighborhoodRelation {
	if relation == nil {
		return nil
	}
	return &ports.NeighborhoodRelation{
		FromURN:    relation.FromURN,
		Relation:   relation.Relation,
		ToURN:      relation.ToURN,
		Attributes: cloneAttributes(relation.Attributes),
	}
}

func cloneAttributes(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func TestNormalizeParametersDropsSensitiveKeys(t *testing.T) {
	for _, key := range []string{
		"token",
		"GitHub_Token",
		"PASSWORD",
		"client_secret",
		"api-key",
		"private_key",
		"x-api-key",
		"authorization",
	} {
		got := normalizeParameters(map[string]string{
			"tenant_id": "writer",
			key:         "shh",
		})
		if _, ok := got[key]; ok {
			t.Fatalf("normalizeParameters() retained sensitive key %q", key)
		}
		if got["tenant_id"] != "writer" {
			t.Fatalf("normalizeParameters() dropped non-sensitive key when filtering %q", key)
		}
	}
}
