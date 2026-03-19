package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/executions"
	"github.com/evalops/cerebro/internal/executionstore"
)

type stubPlatformExecutionService struct {
	summaries []executions.Summary
	err       error
	lastOpts  executions.ListOptions
}

func (s *stubPlatformExecutionService) ListExecutions(_ context.Context, opts executions.ListOptions) ([]executions.Summary, error) {
	s.lastOpts = opts
	if s.err != nil {
		return nil, s.err
	}
	return append([]executions.Summary(nil), s.summaries...), nil
}

func TestPlatformExecutionHandlersUseServiceInterface(t *testing.T) {
	svc := &stubPlatformExecutionService{
		summaries: []executions.Summary{{
			Namespace:   executionstore.NamespacePlatformReportRun,
			RunID:       "report_run:test",
			Kind:        "quality",
			Status:      "succeeded",
			SubmittedAt: time.Date(2026, 3, 19, 12, 0, 0, 0, time.UTC),
			UpdatedAt:   time.Date(2026, 3, 19, 12, 1, 0, 0, time.UTC),
			DisplayName: "report:quality",
		}},
	}
	server := NewServerWithDependencies(serverDependencies{Config: &app.Config{}})
	t.Cleanup(func() { server.Close() })

	server.platformExecutions = svc
	server.app.Config = nil
	server.app.ExecutionStore = nil

	resp := do(t, server, http.MethodGet, "/api/v1/platform/executions?namespace=report_run,workload_scan&status=running&exclude_status=failed&report_id=quality&limit=25&offset=5&order=submitted", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	if got := svc.lastOpts; len(got.Namespaces) != 2 || got.Namespaces[0] != "report_run" || got.Namespaces[1] != "workload_scan" {
		t.Fatalf("expected namespace filter to flow through service, got %#v", got.Namespaces)
	}
	if got := svc.lastOpts.Statuses; len(got) != 1 || got[0] != "running" {
		t.Fatalf("expected status filter to flow through service, got %#v", got)
	}
	if got := svc.lastOpts.ExcludeStatuses; len(got) != 1 || got[0] != "failed" {
		t.Fatalf("expected exclude_status filter to flow through service, got %#v", got)
	}
	if svc.lastOpts.ReportID != "quality" || svc.lastOpts.Limit != 25 || svc.lastOpts.Offset != 5 || !svc.lastOpts.OrderBySubmittedAt {
		t.Fatalf("unexpected list options: %#v", svc.lastOpts)
	}

	body := decodeJSON(t, resp)
	if got := int(body["count"].(float64)); got != 1 {
		t.Fatalf("expected one execution from service stub, got %#v", body)
	}
}

func TestPlatformExecutionServiceListExecutionsReportsAvailabilityErrors(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		svc := newPlatformExecutionService(nil)
		_, err := svc.ListExecutions(t.Context(), executions.ListOptions{})
		if !errors.Is(err, errPlatformExecutionStoreNotConfigured) {
			t.Fatalf("expected not configured error, got %v", err)
		}
	})

	t.Run("unavailable", func(t *testing.T) {
		svc := newPlatformExecutionService(&serverDependencies{
			Config: &app.Config{ExecutionStoreFile: t.TempDir()},
		})
		_, err := svc.ListExecutions(t.Context(), executions.ListOptions{})
		if !errors.Is(err, errPlatformExecutionStoreUnavailable) {
			t.Fatalf("expected unavailable error, got %v", err)
		}
	})
}
