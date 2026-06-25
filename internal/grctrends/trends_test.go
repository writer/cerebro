package grctrends

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestBuildSummaryAggregatesFlowBacklogAndSLA(t *testing.T) {
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	trends := &ports.GRCFindingTrends{
		OpenAtStart: 10,
		Points: []ports.GRCFindingTrendPoint{
			{
				BucketStart:                base,
				Opened:                     5,
				OpenedCritical:             2,
				OpenedHigh:                 1,
				Closed:                     1,
				ClosedDurationSecondsTotal: float64((2 * time.Hour).Seconds()),
				ClosedDurationCount:        1,
			},
			{
				BucketStart:                base.AddDate(0, 0, 1),
				Opened:                     1,
				Closed:                     4,
				ClosedCritical:             1,
				ClosedHigh:                 2,
				ClosedSLABreached:          2,
				ClosedDurationSecondsTotal: float64((8 * time.Hour).Seconds()),
				ClosedDurationCount:        4,
			},
		},
	}

	summary := BuildSummary(trends)
	if summary.TotalOpened != 6 || summary.TotalClosed != 5 || summary.Net != 1 {
		t.Fatalf("flow summary = opened %d closed %d net %d, want 6/5/1", summary.TotalOpened, summary.TotalClosed, summary.Net)
	}
	if summary.CurrentOpen != 11 || summary.PeakOpen != 14 {
		t.Fatalf("backlog summary = current %d peak %d, want 11/14", summary.CurrentOpen, summary.PeakOpen)
	}
	if summary.OpenedCritical != 2 || summary.OpenedHigh != 1 || summary.ClosedCritical != 1 || summary.ClosedHigh != 2 {
		t.Fatalf("severity summary = %#v, want opened critical/high 2/1 closed critical/high 1/2", summary)
	}
	if summary.ClosedSLABreached != 2 || summary.ClosedSLABreachedRate != 0.4 {
		t.Fatalf("sla summary = %d rate %v, want 2/0.4", summary.ClosedSLABreached, summary.ClosedSLABreachedRate)
	}
	if summary.AvgTimeToCloseSeconds != float64((10*time.Hour).Seconds())/5 {
		t.Fatalf("avg close seconds = %v, want %v", summary.AvgTimeToCloseSeconds, float64((10*time.Hour).Seconds())/5)
	}
}

func TestMergeAggregatesTenantsDeterministically(t *testing.T) {
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	provider := &recordingTrendProvider{
		responses: map[string]ports.GRCFindingTrends{
			"alpha": {
				OpenAtStart: 3,
				Points: []ports.GRCFindingTrendPoint{
					{BucketStart: base, Opened: 1, Closed: 1, ClosedDurationSecondsTotal: float64(time.Hour.Seconds()), ClosedDurationCount: 1},
					{BucketStart: base.AddDate(0, 0, 1), Opened: 2, OpenedHigh: 1},
				},
				AgingBuckets: []ports.GRCAgingBucket{{ID: "0-7", Label: "0-7 days", MinDays: 0, MaxDays: 7, Count: 2}},
			},
			"beta": {
				OpenAtStart: 5,
				Points: []ports.GRCFindingTrendPoint{
					{BucketStart: base, Opened: 4, OpenedCritical: 1, Closed: 2, ClosedHigh: 1, ClosedSLABreached: 1, ClosedDurationSecondsTotal: float64((3 * time.Hour).Seconds()), ClosedDurationCount: 2},
				},
				AgingBuckets: []ports.GRCAgingBucket{{ID: "0-7", Label: "0-7 days", MinDays: 0, MaxDays: 7, Count: 4}},
			},
		},
	}
	runtimes := []*cerebrov1.SourceRuntime{
		{Id: "beta-2", TenantId: "beta"},
		nil,
		{Id: "alpha-2", TenantId: "alpha"},
		{Id: "alpha-1", TenantId: "alpha"},
		{Id: "beta-1", TenantId: "beta"},
		{Id: "", TenantId: "ignored"},
	}

	merged, err := Merge(context.Background(), provider, runtimes, base, base.AddDate(0, 0, 7), "day", Filter{Severity: "HIGH", Framework: "SOC 2"})
	if err != nil {
		t.Fatalf("Merge error = %v", err)
	}
	if merged.OpenAtStart != 8 {
		t.Fatalf("OpenAtStart = %d, want 8", merged.OpenAtStart)
	}
	if len(merged.Points) != 2 {
		t.Fatalf("points = %d, want 2", len(merged.Points))
	}
	first := merged.Points[0]
	if !first.BucketStart.Equal(base) || first.Opened != 5 || first.OpenedCritical != 1 || first.Closed != 3 || first.ClosedHigh != 1 || first.ClosedSLABreached != 1 {
		t.Fatalf("first merged point = %#v, want base opened/closed aggregate", first)
	}
	if first.ClosedDurationSecondsTotal != float64((4*time.Hour).Seconds()) || first.ClosedDurationCount != 3 {
		t.Fatalf("first duration aggregate = %v/%d, want 4h/3", first.ClosedDurationSecondsTotal, first.ClosedDurationCount)
	}
	if !merged.Points[1].BucketStart.Equal(base.AddDate(0, 0, 1)) || merged.Points[1].OpenedHigh != 1 {
		t.Fatalf("second merged point = %#v, want next-day alpha high open", merged.Points[1])
	}
	if len(merged.AgingBuckets) != 1 || merged.AgingBuckets[0].Count != 6 {
		t.Fatalf("aging buckets = %#v, want one count=6", merged.AgingBuckets)
	}
	provider.assertRuntimeIDs(t, map[string][]string{
		"alpha": {"alpha-1", "alpha-2"},
		"beta":  {"beta-1", "beta-2"},
	})
}

type recordingTrendProvider struct {
	mu        sync.Mutex
	responses map[string]ports.GRCFindingTrends
	requests  []ports.GRCFindingTrendsRequest
}

func (p *recordingTrendProvider) SummarizeGRCFindingTrends(_ context.Context, request ports.GRCFindingTrendsRequest) (ports.GRCFindingTrends, error) {
	p.mu.Lock()
	p.requests = append(p.requests, request)
	p.mu.Unlock()
	return p.responses[request.FindingRequest.TenantID], nil
}

func (p *recordingTrendProvider) assertRuntimeIDs(t *testing.T, want map[string][]string) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	got := map[string][]string{}
	for _, request := range p.requests {
		got[request.FindingRequest.TenantID] = request.FindingRequest.RuntimeIDs
		if request.FindingRequest.Severity != "HIGH" || request.FindingRequest.Framework != "SOC 2" {
			t.Fatalf("filter = severity %q framework %q, want HIGH/SOC 2", request.FindingRequest.Severity, request.FindingRequest.Framework)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime IDs = %#v, want %#v", got, want)
	}
}
