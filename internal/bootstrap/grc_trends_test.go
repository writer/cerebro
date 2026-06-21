package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestGRCBuildTrendPointsReconstructsRunningBacklog(t *testing.T) {
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	trends := &ports.GRCFindingTrends{
		OpenAtStart: 10,
		Points: []ports.GRCFindingTrendPoint{
			{BucketStart: base, Opened: 3, OpenedCritical: 1, OpenedHigh: 1, Closed: 1},
			{BucketStart: base.AddDate(0, 0, 1), Opened: 0, Closed: 4},
			{BucketStart: base.AddDate(0, 0, 2), Opened: 2, Closed: 0},
		},
	}

	points := grcBuildTrendPoints(trends)
	if len(points) != 3 {
		t.Fatalf("points = %d, want 3", len(points))
	}
	if points[0].Date != "2026-03-01" {
		t.Fatalf("points[0].Date = %q, want 2026-03-01", points[0].Date)
	}
	for i, want := range []int{12, 8, 10} { // 10+3-1; 12+0-4; 8+2-0
		if points[i].OpenTotal != want {
			t.Fatalf("points[%d].OpenTotal = %d, want %d", i, points[i].OpenTotal, want)
		}
	}
}

func TestGRCBuildTrendPointsClampsBacklogAtZero(t *testing.T) {
	trends := &ports.GRCFindingTrends{
		OpenAtStart: 1,
		Points: []ports.GRCFindingTrendPoint{
			{BucketStart: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), Closed: 5},
		},
	}
	if got := grcBuildTrendPoints(trends)[0].OpenTotal; got != 0 {
		t.Fatalf("OpenTotal = %d, want 0 (clamped)", got)
	}
}

func TestGRCBuildTrendPointsNilReturnsEmptySlice(t *testing.T) {
	points := grcBuildTrendPoints(nil)
	if points == nil || len(points) != 0 {
		t.Fatalf("points = %#v, want empty non-nil slice", points)
	}
}

func TestGRCTrendsParamsFromRequestDefaults(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/grc/trends", nil)
	interval, days, err := grcTrendsParamsFromRequest(r)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if interval != "day" || days != grcTrendsDefaultDays {
		t.Fatalf("interval=%q days=%d, want day/%d", interval, days, grcTrendsDefaultDays)
	}
}

func TestGRCTrendsParamsFromRequestClampsDays(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/grc/trends?days=100000&interval=week", nil)
	interval, days, err := grcTrendsParamsFromRequest(r)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if interval != "week" || days != grcTrendsMaxDays {
		t.Fatalf("interval=%q days=%d, want week/%d", interval, days, grcTrendsMaxDays)
	}
}

func TestGRCTrendsParamsFromRequestRejectsInterval(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/grc/trends?interval=hour", nil)
	if _, _, err := grcTrendsParamsFromRequest(r); err == nil {
		t.Fatalf("expected error for unsupported interval")
	}
}

type stubGRCTrendsStore struct {
	*stubRuntimeStore
	calls int
	last  ports.GRCFindingTrendsRequest
}

func (s *stubGRCTrendsStore) SummarizeGRCFindingTrends(_ context.Context, request ports.GRCFindingTrendsRequest) (ports.GRCFindingTrends, error) {
	s.calls++
	s.last = request
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	return ports.GRCFindingTrends{
		OpenAtStart: 5,
		Points: []ports.GRCFindingTrendPoint{
			{BucketStart: base, Opened: 2, OpenedCritical: 1, Closed: 0},
			{BucketStart: base.AddDate(0, 0, 1), Opened: 0, Closed: 3},
		},
	}, nil
}

func TestHandleGRCTrendsReturnsSeries(t *testing.T) {
	store := &stubGRCTrendsStore{stubRuntimeStore: &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta": {Id: "writer-okta", SourceId: "okta", TenantId: "writer"},
		},
	}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/trends?tenant_id=writer&days=30")
	if err != nil {
		t.Fatalf("GET /grc/trends error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/trends status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload grcTrendsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /grc/trends: %v", err)
	}
	if payload.Interval != "day" {
		t.Fatalf("interval = %q, want day", payload.Interval)
	}
	if len(payload.Points) != 2 {
		t.Fatalf("points = %d, want 2", len(payload.Points))
	}
	if payload.Points[0].OpenTotal != 7 || payload.Points[1].OpenTotal != 4 { // 5+2-0; 7+0-3
		t.Fatalf("open totals = %d,%d want 7,4", payload.Points[0].OpenTotal, payload.Points[1].OpenTotal)
	}
	if payload.Points[0].OpenedCritical != 1 {
		t.Fatalf("opened_critical = %d, want 1", payload.Points[0].OpenedCritical)
	}
	if store.calls != 1 {
		t.Fatalf("trends store calls = %d, want 1", store.calls)
	}
	if store.last.Interval != "day" {
		t.Fatalf("store interval = %q, want day", store.last.Interval)
	}
}
