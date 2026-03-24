package graph_test

import (
	"context"
	"fmt"
	"testing"

	graphpkg "github.com/writer/cerebro/internal/graph"
)

var benchmarkSink graphpkg.BenchmarkRunResult

func BenchmarkGraphBackendWorkloads(b *testing.B) {
	tiers := []int{1000, 10000, 100000}
	builders := []struct {
		name  string
		build func(*testing.B, int) benchmarkFixture
	}{
		{
			name: "security-estate",
			build: func(tb *testing.B, size int) benchmarkFixture {
				tb.Helper()
				return buildSecurityBenchmarkFixture(tb, size)
			},
		},
		{
			name: "world-model",
			build: func(tb *testing.B, size int) benchmarkFixture {
				tb.Helper()
				return buildWorldModelBenchmarkFixture(tb, size)
			},
		},
	}

	ctx := context.Background()
	for _, builder := range builders {
		builder := builder
		for _, tier := range tiers {
			tier := tier
			b.Run(fmt.Sprintf("%s/%d", builder.name, tier), func(b *testing.B) {
				fixture := builder.build(b, tier)
				cases := benchmarkCasesForFixture(fixture, 1)
				for _, c := range cases {
					c := c
					b.Run(fmt.Sprintf("%s/%s", c.Backend, c.Workload), func(b *testing.B) {
						run := c.Run
						b.ReportMetric(float64(c.NodeCount), "nodes")
						b.ReportMetric(float64(c.EdgeCount), "edges")
						b.ResetTimer()
						for i := 0; i < b.N; i++ {
							result, err := run(ctx)
							if err != nil {
								b.Fatalf("benchmark run error: %v", err)
							}
							benchmarkSink = result
						}
						b.StopTimer()
						b.ReportMetric(float64(benchmarkSink.ResultSize), "result_size")
					})
				}
			})
		}
	}
}
