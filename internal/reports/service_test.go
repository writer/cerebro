package reports

import (
	"context"
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
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
		findings = append(findings, cloneFinding(finding))
	}
	return findings, nil
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

type stubGraphStore struct {
	rootURN       string
	limit         int
	neighborhoods map[string]*ports.EntityNeighborhood
}

func (s *stubGraphStore) Ping(context.Context) error { return nil }

func (s *stubGraphStore) GetEntityNeighborhood(_ context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	s.rootURN = rootURN
	s.limit = limit
	neighborhood, ok := s.neighborhoods[rootURN]
	if !ok {
		return nil, ports.ErrGraphEntityNotFound
	}
	return cloneNeighborhood(neighborhood), nil
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
	findingStore := &stubFindingStore{
		findings: []*ports.FindingRecord{
			{
				ID:        "finding-1",
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
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				Attributes: map[string]string{
					"primary_resource_urn": "urn:cerebro:writer:okta_resource:policyrule:pol-1",
				},
			},
			{
				ID:        "finding-2",
				RuntimeID: "writer-okta-audit",
				RuleID:    "identity-okta-policy-rule-lifecycle-tampering",
				PolicyID:  "pol-1",
				CheckID:   "identity-okta-policy-rule-lifecycle-tampering-30d",
				CheckName: "Okta Policy Rule Lifecycle Tampering (30 days)",
				ControlRefs: []ports.FindingControlRef{
					{FrameworkName: "SOC 2", ControlID: "CC6.2"},
					{FrameworkName: "ISO 27001:2022", ControlID: "A.8.9"},
				},
				Severity:     "HIGH",
				Status:       "resolved",
				ResourceURNs: []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
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
			reportParameterRuntimeID:  "writer-okta-audit",
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
	if findingStore.request.RuntimeID != "writer-okta-audit" {
		t.Fatalf("ListFindings().RuntimeID = %q, want writer-okta-audit", findingStore.request.RuntimeID)
	}
	result := response.GetRun().GetResult().AsMap()
	if got := result[reportParameterRuntimeID]; got != "writer-okta-audit" {
		t.Fatalf("Run().Run.Result[runtime_id] = %#v, want writer-okta-audit", got)
	}
	if got := result["total_findings"]; got != float64(2) {
		t.Fatalf("Run().Run.Result[total_findings] = %#v, want 2", got)
	}
	severityCounts, ok := result["severity_counts"].([]any)
	if !ok || len(severityCounts) != 1 {
		t.Fatalf("Run().Run.Result[severity_counts] = %#v, want 1 entry", result["severity_counts"])
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
}

func TestGetReportRunRequiresAvailableStore(t *testing.T) {
	service := New(nil, nil, nil)
	if _, err := service.Get(context.Background(), &cerebrov1.GetReportRunRequest{Id: "report-run-1"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("Get() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestListReportDefinitionsIncludesFindingSummary(t *testing.T) {
	response := New(nil, nil, nil).List()
	if len(response.GetReports()) != 1 {
		t.Fatalf("len(List().Reports) = %d, want 1", len(response.GetReports()))
	}
	if response.GetReports()[0].GetId() != findingSummaryReportID {
		t.Fatalf("List().Reports[0].ID = %q, want %q", response.GetReports()[0].GetId(), findingSummaryReportID)
	}
}

func TestRunFindingSummaryReportWithoutGraphStoreMarksEvidenceUnconfigured(t *testing.T) {
	findingStore := &stubFindingStore{
		findings: []*ports.FindingRecord{
			{
				ID:        "finding-1",
				RuntimeID: "writer-okta-audit",
				RuleID:    "identity-okta-policy-rule-lifecycle-tampering",
				Severity:  "HIGH",
				Status:    "open",
			},
		},
	}
	service := New(findingStore, nil, &stubReportStore{})

	response, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: findingSummaryReportID,
		Parameters: map[string]string{
			reportParameterRuntimeID: "writer-okta-audit",
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := response.GetRun().GetResult().AsMap()["graph_evidence_status"]; got != graphEvidenceStatusUnconfigured {
		t.Fatalf("graph_evidence_status = %#v, want %q", got, graphEvidenceStatusUnconfigured)
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
		Attributes:        cloneAttributes(finding.Attributes),
		Assignee:          finding.Assignee,
		StatusReason:      finding.StatusReason,
		StatusUpdatedAt:   finding.StatusUpdatedAt,
		FirstObservedAt:   finding.FirstObservedAt,
		LastObservedAt:    finding.LastObservedAt,
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
		FromURN:  relation.FromURN,
		Relation: relation.Relation,
		ToURN:    relation.ToURN,
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
