package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestThreatIntelEndpoints_Return503WhenServiceMissing(t *testing.T) {
	a := newTestApp(t)
	a.ThreatIntel = nil
	s := NewServer(a)

	cases := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/v1/threatintel/feeds"},
		{method: http.MethodGet, path: "/api/v1/threatintel/stats"},
		{method: http.MethodGet, path: "/api/v1/threatintel/lookup/ip/1.1.1.1"},
		{method: http.MethodGet, path: "/api/v1/threatintel/lookup/domain/example.com"},
		{method: http.MethodGet, path: "/api/v1/threatintel/lookup/cve/CVE-2025-0001"},
		{method: http.MethodPost, path: "/api/v1/threatintel/feeds/cisa-kev/sync"},
	}

	for _, tc := range cases {
		w := do(t, s, tc.method, tc.path, nil)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s: expected 503, got %d", tc.method, tc.path, w.Code)
		}
	}
}

func TestScanCoverage_Return503WithoutSnowflake(t *testing.T) {
	a := newTestApp(t)
	a.Snowflake = nil
	s := NewServer(a)

	w := do(t, s, http.MethodGet, "/api/v1/scan/coverage", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestSchedulerRun_ReturnsServiceUnavailableWhenSchedulerStopped(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodPost, "/api/v1/scheduler/jobs/not-a-job/run", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when scheduler is not running, got %d", w.Code)
	}
}

func TestProviderTest_ReturnsNotFoundForUnknownProvider(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodPost, "/api/v1/providers/not-a-provider/test", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestSchedulerJobControlEndpoints_RunEnableDisableAndConflict(t *testing.T) {
	a := newTestApp(t)
	block := make(chan struct{})
	a.Scheduler.AddJob("blocking", time.Hour, func(context.Context) error {
		<-block
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		close(block)
	})
	go a.Scheduler.Start(ctx)
	time.Sleep(10 * time.Millisecond)

	s := NewServer(a)

	run := do(t, s, http.MethodPost, "/api/v1/scheduler/jobs/blocking/run", nil)
	if run.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for run endpoint, got %d", run.Code)
	}

	conflict := do(t, s, http.MethodPost, "/api/v1/scheduler/jobs/blocking/run", nil)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate run endpoint, got %d", conflict.Code)
	}

	enable := do(t, s, http.MethodPost, "/api/v1/scheduler/jobs/blocking/enable", nil)
	if enable.Code != http.StatusOK {
		t.Fatalf("expected 200 for enable endpoint, got %d", enable.Code)
	}

	disable := do(t, s, http.MethodPost, "/api/v1/scheduler/jobs/blocking/disable", nil)
	if disable.Code != http.StatusOK {
		t.Fatalf("expected 200 for disable endpoint, got %d", disable.Code)
	}
}

func TestSchedulerRun_ReturnsNotFoundWhenSchedulerRunningAndJobMissing(t *testing.T) {
	a := newTestApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go a.Scheduler.Start(ctx)
	time.Sleep(10 * time.Millisecond)

	s := NewServer(a)
	w := do(t, s, http.MethodPost, "/api/v1/scheduler/jobs/not-a-job/run", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing job with running scheduler, got %d", w.Code)
	}
}

func TestTelemetryIngest_ReturnsBadRequestForInvalidJSON(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/telemetry/ingest", strings.NewReader("{"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestThreatIntelSyncFeed_ReturnsBadRequestForUnknownFeed(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodPost, "/api/v1/threatintel/feeds/unknown-feed/sync", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
