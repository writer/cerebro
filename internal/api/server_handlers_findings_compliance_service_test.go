package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/policy"
)

type stubFindingsComplianceService struct {
	store      findings.FindingStore
	scanResult *scanFindingsResponse
	report     compliance.ComplianceReport
}

func (s stubFindingsComplianceService) FindingsStore(context.Context) findings.FindingStore {
	return s.store
}

func (s stubFindingsComplianceService) ScanFindings(context.Context, []string, int) (*scanFindingsResponse, error) {
	if s.scanResult == nil {
		return &scanFindingsResponse{}, nil
	}
	return s.scanResult, nil
}

func (s stubFindingsComplianceService) Reporter(ctx context.Context) *findings.ComplianceReporter {
	return findings.NewComplianceReporter(s.FindingsStore(ctx), nil)
}

func (s stubFindingsComplianceService) EvaluateFramework(context.Context, *compliance.Framework, compliance.EvaluationOptions) compliance.ComplianceReport {
	return s.report
}

func (s stubFindingsComplianceService) Warn(string, ...any) {}

func newFindingsComplianceServiceTestServer(t *testing.T, service findingsComplianceService) *Server {
	t.Helper()
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
	})
	s.findingsCompliance = service
	s.app.Findings = nil
	s.app.Warehouse = nil
	s.app.Scanner = nil
	s.app.Policy = nil
	s.app.SecurityGraph = nil
	t.Cleanup(func() {
		s.Close()
	})
	return s
}

func TestFindingsHandlersUseServiceInterface(t *testing.T) {
	store := findings.NewStore()
	store.Upsert(context.Background(), policy.Finding{
		ID:         "finding-1",
		PolicyID:   "policy.bucket.public",
		PolicyName: "Public bucket",
		Severity:   "high",
		Resource: map[string]any{
			"id":   "bucket-1",
			"type": "bucket",
		},
	})

	s := newFindingsComplianceServiceTestServer(t, stubFindingsComplianceService{store: store})

	w := do(t, s, http.MethodGet, "/api/v1/findings/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if count, ok := body["count"].(float64); !ok || count != 1 {
		t.Fatalf("expected count 1 from service-backed findings store, got %#v", body["count"])
	}
}

func TestServerFindingsComplianceServiceFallsBackToEmptyStore(t *testing.T) {
	svc := newFindingsComplianceService(&serverDependencies{})
	store := svc.FindingsStore(context.Background())
	if store == nil {
		t.Fatal("expected non-nil fallback findings store")
	}
	if count := store.Count(findings.FindingFilter{}); count != 0 {
		t.Fatalf("expected empty fallback findings store, got count=%d", count)
	}
}

func TestFindingsHandlersGracefullyHandleMissingFindingsStore(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
	})
	s.app.Findings = nil
	t.Cleanup(func() {
		s.Close()
	})

	w := do(t, s, http.MethodGet, "/api/v1/findings/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if count, ok := body["count"].(float64); !ok || count != 0 {
		t.Fatalf("expected empty findings payload, got %#v", body["count"])
	}
}

func TestScanFindingsUsesServiceInterface(t *testing.T) {
	s := newFindingsComplianceServiceTestServer(t, stubFindingsComplianceService{
		store: findings.NewStore(),
		scanResult: &scanFindingsResponse{
			Scanned:    3,
			Violations: 1,
			Duration:   "12ms",
			Findings: []policy.Finding{{
				ID:         "finding-2",
				PolicyID:   "policy.iam.admin",
				PolicyName: "Admin role",
				Severity:   "critical",
				Resource: map[string]any{
					"id":   "role-1",
					"type": "role",
				},
			}},
			Tables: []scanFindingsTableResult{{
				Table:      "aws_iam_roles",
				Scanned:    3,
				Violations: 1,
				Duration:   "12ms",
			}},
		},
	})

	w := do(t, s, http.MethodPost, "/api/v1/findings/scan", map[string]any{
		"tables": []string{"aws_iam_roles"},
		"limit":  25,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if scanned, ok := body["scanned"].(float64); !ok || scanned != 3 {
		t.Fatalf("expected scanned=3 from service-backed scan, got %#v", body["scanned"])
	}
	if violations, ok := body["violations"].(float64); !ok || violations != 1 {
		t.Fatalf("expected violations=1 from service-backed scan, got %#v", body["violations"])
	}
}

func TestFindingsComplianceReportsUseServiceInterface(t *testing.T) {
	store := findings.NewStore()
	store.Upsert(context.Background(), policy.Finding{
		ID:         "finding-3",
		PolicyID:   "policy.bucket.encryption",
		PolicyName: "Bucket encryption",
		Severity:   "medium",
		Resource: map[string]any{
			"id":   "bucket-2",
			"type": "bucket",
		},
	})

	s := newFindingsComplianceServiceTestServer(t, stubFindingsComplianceService{store: store})

	w := do(t, s, http.MethodGet, "/api/v1/reports/executive-summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if total, ok := body["total_findings"].(float64); !ok || total != 1 {
		t.Fatalf("expected executive summary payload from service-backed reporter, got %#v", body)
	}
}

func TestFindingsComplianceReportsGracefullyHandleMissingFindingsStore(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
	})
	s.app.Findings = nil
	t.Cleanup(func() {
		s.Close()
	})

	w := do(t, s, http.MethodGet, "/api/v1/reports/executive-summary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if total, ok := body["total_findings"].(float64); !ok || total != 0 {
		t.Fatalf("expected empty executive summary payload, got %#v", body)
	}
}

func TestComplianceHandlersUseServiceInterface(t *testing.T) {
	now := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	s := newFindingsComplianceServiceTestServer(t, stubFindingsComplianceService{
		store: findings.NewStore(),
		report: compliance.ComplianceReport{
			GeneratedAt: now.Format(time.RFC3339),
			Summary: compliance.ComplianceSummary{
				TotalControls:   1,
				PassingControls: 0,
				FailingControls: 1,
			},
			Controls: []compliance.ControlStatus{{
				ControlID: "2.1.1",
				Title:     "Ensure S3 buckets are encrypted",
				Status:    compliance.ControlStateFailing,
				FailCount: 2,
			}},
		},
	})

	w := do(t, s, http.MethodGet, "/api/v1/compliance/frameworks/cis-aws-1.5/status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if got := body["framework_id"]; got != "cis-aws-1.5" {
		t.Fatalf("unexpected framework id: %#v", got)
	}
	if total, ok := body["total_findings"].(float64); !ok || total != 2 {
		t.Fatalf("expected total_findings=2 from service-backed compliance report, got %#v", body["total_findings"])
	}
}

func TestOpenFindingsByPolicyNilStore(t *testing.T) {
	if got := openFindingsByPolicy(nil); len(got) != 0 {
		t.Fatalf("expected empty findings-by-policy map for nil store, got %#v", got)
	}
}
