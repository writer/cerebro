package sourceruntime

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type processingBenchmarkSource struct {
	pages         int
	eventsPerPage int
}

func (s processingBenchmarkSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "processing_benchmark"}
}

func (processingBenchmarkSource) Check(context.Context, sourcecdk.Config) error { return nil }

func (processingBenchmarkSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s processingBenchmarkSource) Read(_ context.Context, _ sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	page := 0
	if cursor.GetOpaque() != "" {
		parsed, err := strconv.Atoi(cursor.GetOpaque())
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		page = parsed
	}
	events := make([]*cerebrov1.EventEnvelope, 0, s.eventsPerPage)
	for index := 0; index < s.eventsPerPage; index++ {
		events = append(events, runtimeTestEvent(
			fmt.Sprintf("page-%04d-event-%04d", page, index),
			"processing_benchmark",
			"processing_benchmark.event",
		))
	}
	pull := sourcecdk.Pull{Events: events}
	if page+1 < s.pages {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strconv.Itoa(page + 1)}
	}
	return pull, nil
}

type processingBenchmarkAppendLog struct{}

func (processingBenchmarkAppendLog) Ping(context.Context) error { return nil }
func (processingBenchmarkAppendLog) Append(context.Context, *cerebrov1.EventEnvelope) error {
	return nil
}
func (processingBenchmarkAppendLog) AppendBatch(context.Context, []*cerebrov1.EventEnvelope) error {
	return nil
}

type processingBenchmarkProjector struct{}

func (processingBenchmarkProjector) Project(context.Context, *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	return ports.ProjectionResult{EntitiesProjected: 1}, nil
}

func BenchmarkSyncProcessingPipeline(b *testing.B) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = devNull.Close() })
	originalStderr := os.Stderr
	os.Stderr = devNull
	b.Cleanup(func() { os.Stderr = originalStderr })

	for _, workload := range []struct {
		pages         int
		eventsPerPage int
	}{
		{pages: 1, eventsPerPage: 100},
		{pages: 10, eventsPerPage: 100},
		{pages: 2, eventsPerPage: 1_000},
	} {
		name := fmt.Sprintf("pages_%d/events_per_page_%d", workload.pages, workload.eventsPerPage)
		b.Run(name, func(b *testing.B) {
			source := processingBenchmarkSource{pages: workload.pages, eventsPerPage: workload.eventsPerPage}
			registry, registryErr := sourcecdk.NewRegistry(source)
			if registryErr != nil {
				b.Fatal(registryErr)
			}
			store := &runtimeStore{}
			service := New(registry, store, processingBenchmarkAppendLog{}, processingBenchmarkProjector{})
			totalEvents := workload.pages * workload.eventsPerPage
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				store.runtimes = map[string]*cerebrov1.SourceRuntime{
					"processing-benchmark": {Id: "processing-benchmark", SourceId: "processing_benchmark", TenantId: "benchmark"},
				}
				response, syncErr := service.Sync(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{
					Id: "processing-benchmark", PageLimit: uint32(workload.pages),
				})
				if syncErr != nil {
					b.Fatal(syncErr)
				}
				if int(response.GetEventsAppended()) != totalEvents {
					b.Fatalf("events appended = %d, want %d", response.GetEventsAppended(), totalEvents)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*totalEvents), "ns/event")
		})
	}
}
