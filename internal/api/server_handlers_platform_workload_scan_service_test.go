package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/workloadscan"
)

type stubPlatformWorkloadScanService struct {
	targets   []workloadscan.TargetPriority
	err       error
	lastOpts  workloadscan.PrioritizationOptions
	invokedAt time.Time
}

func (s *stubPlatformWorkloadScanService) PrioritizeTargets(_ context.Context, opts workloadscan.PrioritizationOptions) ([]workloadscan.TargetPriority, error) {
	s.lastOpts = opts
	if opts.Now != nil {
		s.invokedAt = opts.Now()
	}
	if s.err != nil {
		return nil, s.err
	}
	return append([]workloadscan.TargetPriority(nil), s.targets...), nil
}

func TestPlatformWorkloadScanTargetsHandlerUsesServiceInterface(t *testing.T) {
	server := NewServerWithDependencies(serverDependencies{Config: &app.Config{}})
	t.Cleanup(func() { server.Close() })

	svc := &stubPlatformWorkloadScanService{
		targets: []workloadscan.TargetPriority{{
			NodeID:      "vm:1",
			DisplayName: "i-123",
			Provider:    workloadscan.ProviderAWS,
			Target: workloadscan.VMTarget{
				Provider:   workloadscan.ProviderAWS,
				Region:     "us-east-1",
				InstanceID: "i-123",
			},
			Assessment: workloadscan.PriorityAssessment{
				Score:    90,
				Priority: workloadscan.ScanPriorityCritical,
				Eligible: true,
			},
		}},
	}
	server.platformWorkloadScan = svc
	server.app.SecurityGraph = nil
	server.app.ExecutionStore = nil
	server.app.Config = nil

	resp := do(t, server, http.MethodGet, "/api/v1/platform/workload-scan/targets?include_deferred=true&provider=aws,gcp&limit=25", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	if got := svc.lastOpts.Limit; got != 25 {
		t.Fatalf("expected limit 25, got %d", got)
	}
	if !svc.lastOpts.IncludeDeferred {
		t.Fatal("expected include_deferred to flow through service")
	}
	if got := svc.lastOpts.Providers; len(got) != 2 || got[0] != workloadscan.ProviderAWS || got[1] != workloadscan.ProviderGCP {
		t.Fatalf("unexpected providers: %#v", got)
	}
	if svc.invokedAt.IsZero() {
		t.Fatal("expected service to receive a Now clock")
	}

	body := decodeJSON(t, resp)
	if got := int(body["count"].(float64)); got != 1 {
		t.Fatalf("expected one target from service stub, got %#v", body)
	}
}

func TestPlatformWorkloadScanServiceReportsAvailabilityErrors(t *testing.T) {
	t.Run("graph unavailable", func(t *testing.T) {
		svc := newPlatformWorkloadScanService(&serverDependencies{})
		_, err := svc.PrioritizeTargets(t.Context(), workloadscan.PrioritizationOptions{})
		if !errors.Is(err, graph.ErrStoreUnavailable) {
			t.Fatalf("expected graph store unavailable, got %v", err)
		}
	})

	t.Run("state unavailable", func(t *testing.T) {
		svc := newPlatformWorkloadScanService(&serverDependencies{
			Config:        &app.Config{WorkloadScanStateFile: t.TempDir()},
			SecurityGraph: graph.New(),
		})
		_, err := svc.PrioritizeTargets(t.Context(), workloadscan.PrioritizationOptions{})
		if !errors.Is(err, errPlatformWorkloadScanStateUnavailable) {
			t.Fatalf("expected workload scan state unavailable, got %v", err)
		}
	})
}
