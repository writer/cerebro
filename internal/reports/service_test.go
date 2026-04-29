package reports

import (
	"context"
	"errors"
	"testing"
	"time"

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

func (s *stubFindingStore) ListFindings(_ context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	s.request = request
	findings := make([]*ports.FindingRecord, 0, len(s.findings))
	for _, finding := range s.findings {
		findings = append(findings, cloneFinding(finding))
	}
	return findings, nil
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
				TenantID:  "writer",
				RuntimeID: "writer-okta-audit",
				RuleID:    "identity-okta-policy-rule-lifecycle-tampering",
				Severity:  "HIGH",
				Status:    "open",
			},
			{
				ID:        "finding-2",
				TenantID:  "writer",
				RuntimeID: "writer-okta-audit",
				RuleID:    "identity-okta-policy-rule-lifecycle-tampering",
				Severity:  "HIGH",
				Status:    "resolved",
			},
		},
	}
	reportStore := &stubReportStore{}
	service := New(findingStore, reportStore)

	response, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: findingSummaryReportID,
		Parameters: map[string]string{
			reportParameterTenantID:  "writer",
			reportParameterRuntimeID: "writer-okta-audit",
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
	if reportStore.run == nil {
		t.Fatal("PutReportRun() not called")
	}
}

func TestGetReportRunRequiresAvailableStore(t *testing.T) {
	service := New(nil, nil)
	if _, err := service.Get(context.Background(), &cerebrov1.GetReportRunRequest{Id: "report-run-1"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("Get() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestRunFindingSummaryReportWrapsValidationErrors(t *testing.T) {
	service := New(&stubFindingStore{}, &stubReportStore{})
	_, err := service.Run(context.Background(), &cerebrov1.RunReportRequest{
		ReportId: findingSummaryReportID,
		Parameters: map[string]string{
			reportParameterTenantID: "writer",
		},
	})
	if !errors.Is(err, ErrInvalidReportRequest) {
		t.Fatalf("Run() error = %v, want %v", err, ErrInvalidReportRequest)
	}
}

func TestListReportDefinitionsIncludesFindingSummary(t *testing.T) {
	response := New(nil, nil).List()
	if len(response.GetReports()) != 1 {
		t.Fatalf("len(List().Reports) = %d, want 1", len(response.GetReports()))
	}
	if response.GetReports()[0].GetId() != findingSummaryReportID {
		t.Fatalf("List().Reports[0].ID = %q, want %q", response.GetReports()[0].GetId(), findingSummaryReportID)
	}
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

func cloneFinding(finding *ports.FindingRecord) *ports.FindingRecord {
	if finding == nil {
		return nil
	}
	return &ports.FindingRecord{
		ID:              finding.ID,
		Fingerprint:     finding.Fingerprint,
		TenantID:        finding.TenantID,
		RuntimeID:       finding.RuntimeID,
		RuleID:          finding.RuleID,
		Title:           finding.Title,
		Severity:        finding.Severity,
		Status:          finding.Status,
		Summary:         finding.Summary,
		ResourceURNs:    append([]string(nil), finding.ResourceURNs...),
		EventIDs:        append([]string(nil), finding.EventIDs...),
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
