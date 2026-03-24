package graph

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"
)

// BenchmarkRunResult captures one benchmark invocation result.
type BenchmarkRunResult struct {
	ResultSize int            `json:"result_size"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// BenchmarkRun executes one workload against a prepared backend.
type BenchmarkRun func(context.Context) (BenchmarkRunResult, error)

// BenchmarkCase defines one workload/backend/fixture benchmark configuration.
type BenchmarkCase struct {
	Backend    string       `json:"backend"`
	Fixture    string       `json:"fixture"`
	Workload   string       `json:"workload"`
	NodeCount  int          `json:"node_count"`
	EdgeCount  int          `json:"edge_count"`
	BatchSize  int          `json:"batch_size"`
	Iterations int          `json:"iterations"`
	Run        BenchmarkRun `json:"-"`
}

// BenchmarkMeasurement captures the recorded benchmark samples and rollups.
type BenchmarkMeasurement struct {
	Backend       string         `json:"backend"`
	Fixture       string         `json:"fixture"`
	Workload      string         `json:"workload"`
	NodeCount     int            `json:"node_count"`
	EdgeCount     int            `json:"edge_count"`
	BatchSize     int            `json:"batch_size"`
	Iterations    int            `json:"iterations"`
	SamplesMS     []float64      `json:"samples_ms,omitempty"`
	MinLatencyMS  float64        `json:"min_latency_ms"`
	MaxLatencyMS  float64        `json:"max_latency_ms"`
	AvgLatencyMS  float64        `json:"avg_latency_ms"`
	P50LatencyMS  float64        `json:"p50_latency_ms"`
	P95LatencyMS  float64        `json:"p95_latency_ms"`
	ResultSizeMin int            `json:"result_size_min"`
	ResultSizeMax int            `json:"result_size_max"`
	ResultSizeAvg float64        `json:"result_size_avg"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// BenchmarkReport is a machine-readable benchmark suite report.
type BenchmarkReport struct {
	GeneratedAt  time.Time              `json:"generated_at"`
	Measurements []BenchmarkMeasurement `json:"measurements,omitempty"`
}

// RunBenchmarkSuite executes the provided benchmark cases and records latency
// distributions plus result-size summaries for regression tracking.
func RunBenchmarkSuite(ctx context.Context, cases []BenchmarkCase) (*BenchmarkReport, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return nil, err
	}
	report := &BenchmarkReport{
		GeneratedAt:  time.Now().UTC(),
		Measurements: make([]BenchmarkMeasurement, 0, len(cases)),
	}
	for _, c := range cases {
		measurement, err := runBenchmarkCase(ctx, c)
		if err != nil {
			return nil, err
		}
		report.Measurements = append(report.Measurements, measurement)
	}
	return report, nil
}

// NewBlastRadiusBenchmarkRun builds one benchmark workload for bounded blast radius traversal.
func NewBlastRadiusBenchmarkRun(store GraphStore, principalID string, maxDepth int) BenchmarkRun {
	return func(ctx context.Context) (BenchmarkRunResult, error) {
		result, err := store.BlastRadius(ctx, principalID, maxDepth)
		if err != nil {
			return BenchmarkRunResult{}, err
		}
		if result == nil {
			return BenchmarkRunResult{}, nil
		}
		return BenchmarkRunResult{
			ResultSize: result.TotalCount,
			Metadata: map[string]any{
				"principal_id": principalID,
				"max_depth":    maxDepth,
			},
		}, nil
	}
}

// NewReverseAccessBenchmarkRun builds one benchmark workload for reverse access traversal.
func NewReverseAccessBenchmarkRun(store GraphStore, resourceID string, maxDepth int) BenchmarkRun {
	return func(ctx context.Context) (BenchmarkRunResult, error) {
		result, err := store.ReverseAccess(ctx, resourceID, maxDepth)
		if err != nil {
			return BenchmarkRunResult{}, err
		}
		if result == nil {
			return BenchmarkRunResult{}, nil
		}
		return BenchmarkRunResult{
			ResultSize: result.TotalCount,
			Metadata: map[string]any{
				"resource_id": resourceID,
				"max_depth":   maxDepth,
			},
		}, nil
	}
}

// NewEffectiveAccessBenchmarkRun builds one benchmark workload for effective access evaluation.
func NewEffectiveAccessBenchmarkRun(store GraphStore, principalID, resourceID string, maxDepth int) BenchmarkRun {
	return func(ctx context.Context) (BenchmarkRunResult, error) {
		result, err := store.EffectiveAccess(ctx, principalID, resourceID, maxDepth)
		if err != nil {
			return BenchmarkRunResult{}, err
		}
		size := 0
		if result != nil {
			size = len(result.AllowedBy)
			if result.Allowed {
				size++
			}
		}
		return BenchmarkRunResult{
			ResultSize: size,
			Metadata: map[string]any{
				"principal_id": principalID,
				"resource_id":  resourceID,
				"max_depth":    maxDepth,
			},
		}, nil
	}
}

// NewExtractSubgraphBenchmarkRun builds one benchmark workload for bounded subgraph extraction.
func NewExtractSubgraphBenchmarkRun(store GraphStore, rootID string, opts ExtractSubgraphOptions) BenchmarkRun {
	return func(ctx context.Context) (BenchmarkRunResult, error) {
		result, err := store.ExtractSubgraph(ctx, rootID, opts)
		if err != nil {
			return BenchmarkRunResult{}, err
		}
		size := 0
		if result != nil {
			size = result.NodeCount()
		}
		return BenchmarkRunResult{
			ResultSize: size,
			Metadata: map[string]any{
				"root_id":   rootID,
				"max_depth": opts.MaxDepth,
				"direction": int(opts.Direction),
			},
		}, nil
	}
}

// NewClaimTimelineBenchmarkRun builds one snapshot-backed benchmark workload for claim timeline queries.
func NewClaimTimelineBenchmarkRun(store GraphStore, claimID string, opts ClaimTimelineOptions) BenchmarkRun {
	return func(ctx context.Context) (BenchmarkRunResult, error) {
		snapshot, err := store.Snapshot(ctx)
		if err != nil {
			return BenchmarkRunResult{}, err
		}
		timeline, ok := GetClaimTimeline(GraphViewFromSnapshot(snapshot), claimID, opts)
		if !ok {
			return BenchmarkRunResult{
				Metadata: map[string]any{"claim_id": claimID, "found": false},
			}, nil
		}
		return BenchmarkRunResult{
			ResultSize: len(timeline.Entries),
			Metadata: map[string]any{
				"claim_id": claimID,
				"found":    true,
			},
		}, nil
	}
}

// NewSnapshotReportBenchmarkRun builds one snapshot-backed benchmark workload for report probes.
func NewSnapshotReportBenchmarkRun(store GraphStore, probe StoreReportProbe) BenchmarkRun {
	return func(ctx context.Context) (BenchmarkRunResult, error) {
		snapshot, err := store.Snapshot(ctx)
		if err != nil {
			return BenchmarkRunResult{}, err
		}
		value, err := probe.Build(GraphViewFromSnapshot(snapshot))
		if err != nil {
			return BenchmarkRunResult{}, err
		}
		normalized, err := normalizeReportParityValue(value)
		if err != nil {
			return BenchmarkRunResult{}, err
		}
		return BenchmarkRunResult{
			ResultSize: benchmarkValueSize(normalized),
			Metadata: map[string]any{
				"probe": firstNonEmpty(probe.Name, "report"),
			},
		}, nil
	}
}

func runBenchmarkCase(ctx context.Context, c BenchmarkCase) (BenchmarkMeasurement, error) {
	if c.Iterations <= 0 {
		return BenchmarkMeasurement{}, fmt.Errorf("benchmark iterations must be positive for %s/%s/%s", c.Backend, c.Fixture, c.Workload)
	}
	if c.Run == nil {
		return BenchmarkMeasurement{}, fmt.Errorf("benchmark run function is required for %s/%s/%s", c.Backend, c.Fixture, c.Workload)
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 1
	}

	measurement := BenchmarkMeasurement{
		Backend:    c.Backend,
		Fixture:    c.Fixture,
		Workload:   c.Workload,
		NodeCount:  c.NodeCount,
		EdgeCount:  c.EdgeCount,
		BatchSize:  c.BatchSize,
		Iterations: c.Iterations,
		SamplesMS:  make([]float64, 0, c.Iterations),
	}

	resultSizes := make([]int, 0, c.Iterations)
	for i := 0; i < c.Iterations; i++ {
		start := time.Now()
		result, err := c.Run(ctx)
		if err != nil {
			return BenchmarkMeasurement{}, fmt.Errorf("benchmark %s/%s/%s iteration %d: %w", c.Backend, c.Fixture, c.Workload, i+1, err)
		}
		measurement.SamplesMS = append(measurement.SamplesMS, durationMillis(time.Since(start)))
		resultSizes = append(resultSizes, max(0, result.ResultSize))
		if len(result.Metadata) > 0 {
			measurement.Metadata = cloneAnyMap(result.Metadata)
		}
	}

	latencySamples := append([]float64(nil), measurement.SamplesMS...)
	sort.Float64s(latencySamples)
	measurement.MinLatencyMS = latencySamples[0]
	measurement.MaxLatencyMS = latencySamples[len(latencySamples)-1]
	measurement.AvgLatencyMS = floatAverage(latencySamples)
	measurement.P50LatencyMS = benchmarkPercentileFloat(latencySamples, 0.50)
	measurement.P95LatencyMS = benchmarkPercentileFloat(latencySamples, 0.95)
	measurement.ResultSizeMin, measurement.ResultSizeMax, measurement.ResultSizeAvg = summarizeIntSamples(resultSizes)
	return measurement, nil
}

func summarizeIntSamples(samples []int) (minValue, maxValue int, average float64) {
	if len(samples) == 0 {
		return 0, 0, 0
	}
	minValue = samples[0]
	maxValue = samples[0]
	total := 0
	for _, sample := range samples {
		if sample < minValue {
			minValue = sample
		}
		if sample > maxValue {
			maxValue = sample
		}
		total += sample
	}
	return minValue, maxValue, float64(total) / float64(len(samples))
}

func floatAverage(samples []float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	total := 0.0
	for _, sample := range samples {
		total += sample
	}
	return total / float64(len(samples))
}

func benchmarkPercentileFloat(sorted []float64, percentile float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if percentile <= 0 {
		return sorted[0]
	}
	if percentile >= 1 {
		return sorted[len(sorted)-1]
	}
	index := int(math.Ceil(percentile*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func benchmarkValueSize(value any) int {
	switch typed := value.(type) {
	case nil:
		return 0
	case map[string]any:
		return len(typed)
	case []any:
		return len(typed)
	case []string:
		return len(typed)
	case []int:
		return len(typed)
	default:
		return 1
	}
}
