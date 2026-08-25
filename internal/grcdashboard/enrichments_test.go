package grcdashboard

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
)

func TestParseEnrichments(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		value   string
		want    Enrichments
		wantErr bool
	}{
		{name: "default", want: EnrichmentsInline},
		{name: "inline", value: " INLINE ", want: EnrichmentsInline},
		{name: "deferred", value: "deferred", want: EnrichmentsDeferred},
		{name: "invalid", value: "eventually", want: EnrichmentsInline, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseEnrichments(url.Values{"enrichments": []string{tc.value}})
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseEnrichments() error = %v, wantErr %t", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("ParseEnrichments() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestScheduleEnrichmentsDeferredSkipsWork(t *testing.T) {
	t.Parallel()
	group, ctx := errgroup.WithContext(context.Background())
	result := ScheduleEnrichments(group, ctx, EnrichmentsDeferred, EnrichmentWork[string, string]{
		RuntimeHealth: func(context.Context) ([]string, error) {
			t.Fatal("deferred runtime health ran")
			return nil, nil
		},
		Coverage: func(context.Context) ([]string, error) {
			t.Fatal("deferred coverage ran")
			return nil, nil
		},
	})
	if err := group.Wait(); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if len(result.SourceSummaries) != 0 || len(result.Coverage) != 0 || result.RuntimeHealthErr != nil {
		t.Fatalf("deferred result = %+v, want empty", result)
	}
}

func TestScheduleEnrichmentsKeepsRuntimeHealthFailureNonFatal(t *testing.T) {
	t.Parallel()
	runtimeErr := errors.New("runtime health unavailable")
	group, ctx := errgroup.WithContext(context.Background())
	result := ScheduleEnrichments(group, ctx, EnrichmentsInline, EnrichmentWork[string, string]{
		RuntimeHealthTimeout: time.Second,
		RuntimeHealth: func(context.Context) ([]string, error) {
			return []string{"partial"}, runtimeErr
		},
		Coverage: func(context.Context) ([]string, error) {
			return []string{"coverage"}, nil
		},
	})
	if err := group.Wait(); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if !errors.Is(result.RuntimeHealthErr, runtimeErr) {
		t.Fatalf("runtime health error = %v, want %v", result.RuntimeHealthErr, runtimeErr)
	}
	if len(result.SourceSummaries) != 0 {
		t.Fatalf("source summaries = %v, want cleared after error", result.SourceSummaries)
	}
	if len(result.Coverage) != 1 || result.Coverage[0] != "coverage" {
		t.Fatalf("coverage = %v, want successful result", result.Coverage)
	}
}

func TestScheduleEnrichmentsReturnsCoverageFailure(t *testing.T) {
	t.Parallel()
	coverageErr := errors.New("coverage unavailable")
	group, ctx := errgroup.WithContext(context.Background())
	ScheduleEnrichments(group, ctx, EnrichmentsInline, EnrichmentWork[string, string]{
		RuntimeHealthTimeout: time.Second,
		RuntimeHealth:        func(context.Context) ([]string, error) { return nil, nil },
		Coverage:             func(context.Context) ([]string, error) { return nil, coverageErr },
	})
	if err := group.Wait(); !errors.Is(err, coverageErr) {
		t.Fatalf("Wait() error = %v, want %v", err, coverageErr)
	}
}

func TestPreviewLimitFor(t *testing.T) {
	t.Parallel()
	for input, want := range map[uint32]uint32{0: PreviewLimit, 1: 1, PreviewLimit: PreviewLimit, PreviewLimit + 1: PreviewLimit} {
		if got := PreviewLimitFor(input); got != want {
			t.Fatalf("PreviewLimitFor(%d) = %d, want %d", input, got, want)
		}
	}
}
