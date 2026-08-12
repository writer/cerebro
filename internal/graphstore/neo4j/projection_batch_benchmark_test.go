package neo4j

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

const projectionBatchBenchmarkRows = 5_000

var projectionBatchBenchmarkChunkCount atomic.Int64

func TestProjectionBatchBenchmarkCorpus(t *testing.T) {
	entities := projectionBatchBenchmarkEntities(projectionBatchBenchmarkRows)
	prepared, err := prepareProjectedEntities(entities)
	if err != nil {
		t.Fatal(err)
	}
	for _, batchSize := range []int{100, 500, 1_000} {
		got := len(chunkSlice(prepared, batchSize))
		want := (projectionBatchBenchmarkRows + batchSize - 1) / batchSize
		if got != want {
			t.Fatalf("batch size %d produced %d chunks, want %d", batchSize, got, want)
		}
	}
}

// BenchmarkProjectionBatchPreparation supplies a reproducible tuning grid for
// the two production controls that determine projection write pressure. It
// measures validation, coalescing, stable ordering, chunk planning, and write
// slot contention without adding network variance from a particular Neo4j host.
func BenchmarkProjectionBatchPreparation(b *testing.B) {
	entities := projectionBatchBenchmarkEntities(projectionBatchBenchmarkRows)
	for _, batchSize := range []int{100, 500, 1_000} {
		for _, concurrency := range []int{1, 2, 4, 8} {
			name := fmt.Sprintf("rows_%d/batch_%d/concurrency_%d", len(entities), batchSize, concurrency)
			b.Run(name, func(b *testing.B) {
				store := &Store{
					projectionBatchSize:        batchSize,
					projectionWriteConcurrency: concurrency,
					writeSlots:                 make(chan struct{}, concurrency),
				}
				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						release, err := store.acquireWriteSlot(context.Background())
						if err != nil {
							b.Fatal(err)
						}
						prepared, err := prepareProjectedEntities(entities)
						if err != nil {
							release()
							b.Fatal(err)
						}
						projectionBatchBenchmarkChunkCount.Store(int64(len(chunkSlice(prepared, store.projectionBatchSizeOrDefault()))))
						release()
					}
				})
				b.StopTimer()
				b.ReportMetric(float64((len(entities)+batchSize-1)/batchSize), "batches/op")
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(entities)), "ns/row")
			})
		}
	}
}

func projectionBatchBenchmarkEntities(count int) []*ports.ProjectedEntity {
	entities := make([]*ports.ProjectedEntity, 0, count)
	for index := 0; index < count; index++ {
		entities = append(entities, &ports.ProjectedEntity{
			URN:        fmt.Sprintf("urn:cerebro:benchmark:asset:%08d", index),
			TenantID:   "benchmark",
			SourceID:   "benchmark",
			RuntimeID:  "benchmark-runtime",
			EntityType: "benchmark.asset",
			Label:      fmt.Sprintf("asset-%08d", index),
			Attributes: map[string]string{"index": fmt.Sprintf("%d", index), "state": "active"},
		})
	}
	return entities
}
