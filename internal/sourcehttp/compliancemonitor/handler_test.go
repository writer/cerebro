package compliancemonitorhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliancemonitor"
	"github.com/writer/cerebro/internal/ports"
)

func TestComplianceMonitorHTTPJourney(t *testing.T) {
	t.Parallel()
	store := &monitorHTTPStore{monitors: map[string]*ports.ComplianceMonitor{}}
	service, err := compliancemonitor.New(store, monitorHTTPLog{})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(service, func(_ context.Context, tenantID string) (string, error) { return tenantID, nil }, func(context.Context) string { return "operator-1" }, nil, 0)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /grc/compliance-monitors", handler.Create)
	mux.HandleFunc("GET /grc/compliance-monitors", handler.List)
	mux.HandleFunc("GET /grc/compliance-monitors/{monitorID}", handler.Get)
	mux.HandleFunc("PUT /grc/compliance-monitors/{monitorID}", handler.Update)
	server := httptest.NewServer(mux)
	defer server.Close()

	nextRun := time.Date(2026, 7, 15, 13, 0, 0, 0, time.UTC)
	input := monitorInput{
		TenantID: "tenant-1", ProgramID: "program-1", PlanRevisionID: "plan-revision-1",
		TriggerKind: ports.ComplianceTriggerTime, IntervalSeconds: 3600, ExpectedCoverage: "complete",
		MaximumEvidenceAgeSecond: 86400, GracePeriodSeconds: 300, Enabled: true, NextRunAt: nextRun,
	}
	var created monitorResponse
	doMonitorJSON(t, server.Client(), http.MethodPost, server.URL+"/grc/compliance-monitors", input, http.StatusCreated, &created)
	if created.Monitor.ID == "" || created.Monitor.Version != 1 || created.Monitor.PlanRevisionID != "plan-revision-1" {
		t.Fatalf("created monitor = %#v", created.Monitor)
	}

	input.TriggerKind = ports.ComplianceTriggerChange
	input.IntervalSeconds = 0
	input.NextRunAt = time.Time{}
	input.DebounceSeconds = 120
	var updated monitorResponse
	doMonitorJSON(t, server.Client(), http.MethodPut, server.URL+"/grc/compliance-monitors/"+created.Monitor.ID, updateMonitorRequest{ExpectedVersion: 1, Monitor: input}, http.StatusOK, &updated)
	if updated.Monitor.Version != 2 || updated.Monitor.TriggerKind != ports.ComplianceTriggerChange || updated.Monitor.DebounceSeconds != 120 {
		t.Fatalf("updated monitor = %#v", updated.Monitor)
	}

	var got monitorResponse
	doMonitorJSON(t, server.Client(), http.MethodGet, server.URL+"/grc/compliance-monitors/"+created.Monitor.ID+"?tenant_id=tenant-1", nil, http.StatusOK, &got)
	if got.Monitor.Version != 2 {
		t.Fatalf("get monitor = %#v", got.Monitor)
	}
	var listed monitorListResponse
	doMonitorJSON(t, server.Client(), http.MethodGet, server.URL+"/grc/compliance-monitors?tenant_id=tenant-1&limit=100", nil, http.StatusOK, &listed)
	if len(listed.Monitors) != 1 || listed.Monitors[0].ID != created.Monitor.ID {
		t.Fatalf("listed monitors = %#v", listed.Monitors)
	}
}

func doMonitorJSON(t *testing.T, client *http.Client, method, url string, input any, wantStatus int, output any) {
	t.Helper()
	var body bytes.Buffer
	if input != nil {
		if err := json.NewEncoder(&body).Encode(input); err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequestWithContext(context.Background(), method, url, &body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != wantStatus {
		var problem bytes.Buffer
		_, _ = problem.ReadFrom(response.Body)
		t.Fatalf("status = %d, want %d: %s", response.StatusCode, wantStatus, problem.String())
	}
	if output != nil {
		if err := json.NewDecoder(response.Body).Decode(output); err != nil {
			t.Fatal(err)
		}
	}
}

type monitorHTTPLog struct{}

func (monitorHTTPLog) Ping(context.Context) error                             { return nil }
func (monitorHTTPLog) Append(context.Context, *cerebrov1.EventEnvelope) error { return nil }

type monitorHTTPStore struct {
	ports.ComplianceMonitorStore
	monitors map[string]*ports.ComplianceMonitor
}

func monitorHTTPKey(tenantID, id string) string { return tenantID + "\x00" + id }

func (s *monitorHTTPStore) ProjectComplianceMonitor(_ context.Context, monitor *ports.ComplianceMonitor, expectedVersion uint64) (*ports.ComplianceMonitor, error) {
	key := monitorHTTPKey(monitor.TenantID, monitor.ID)
	current := s.monitors[key]
	if (current == nil && expectedVersion != 0) || (current != nil && current.Version != expectedVersion) {
		return nil, ports.ErrComplianceMonitorConflict
	}
	copy := *monitor
	copy.CreatedAt = time.Now().UTC()
	copy.UpdatedAt = copy.CreatedAt
	if current != nil {
		copy.CreatedAt = current.CreatedAt
	}
	s.monitors[key] = &copy
	return &copy, nil
}

func (s *monitorHTTPStore) GetComplianceMonitor(_ context.Context, tenantID, id string) (*ports.ComplianceMonitor, error) {
	monitor := s.monitors[monitorHTTPKey(tenantID, id)]
	if monitor == nil {
		return nil, ports.ErrComplianceMonitorNotFound
	}
	copy := *monitor
	return &copy, nil
}

func (s *monitorHTTPStore) ListComplianceMonitors(_ context.Context, filter ports.ComplianceMonitorFilter) ([]*ports.ComplianceMonitor, error) {
	result := make([]*ports.ComplianceMonitor, 0)
	for _, monitor := range s.monitors {
		if monitor.TenantID == filter.TenantID && monitor.ID > filter.AfterID {
			copy := *monitor
			result = append(result, &copy)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if len(result) > int(filter.Limit) {
		result = result[:filter.Limit]
	}
	return result, nil
}
