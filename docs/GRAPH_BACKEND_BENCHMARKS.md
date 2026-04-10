# Graph Backend Benchmarks

This suite benchmarks the graph query families that matter for the durable-backend migration:

- bounded traversal
- claim conflict reports
- claim timelines
- evaluation temporal analysis
- playbook effectiveness reports

It exercises the same backend code paths used by the product:

- in-memory reference graph
- Neptune graph store via the benchmark memory-backed openCypher executor

## What Gets Recorded

`RunBenchmarkSuite` in [store_benchmark.go](../internal/graph/store_benchmark.go) emits a machine-readable JSON-serializable report with:

- backend
- fixture family
- workload name
- node and edge counts
- batch size
- iteration count
- raw latency samples in milliseconds
- min / max / avg / p50 / p95 latency rollups
- min / max / avg result size
- workload metadata

The JSON payload is suitable for CI artifact upload and regression comparison.

## Benchmark Matrix

The benchmark entry point is [store_benchmark_bench_test.go](../internal/graph/store_benchmark_bench_test.go).

It covers:

- fixture families:
  - `security-estate`
  - `world-model`
- graph sizes:
  - `1K`
  - `10K`
  - `100K`
- backends:
  - `memory`
  - `neptune`

## Local Run

Run the full benchmark matrix:

```bash
GOTMPDIR=./.tmp/go-tmp \
TMPDIR=./.tmp/tmp \
GOCACHE=./.tmp/go-cache \
go test ./internal/graph -run '^$' -bench BenchmarkGraphBackendWorkloads -benchmem
```

Run a shorter smoke pass:

```bash
GOTMPDIR=./.tmp/go-tmp \
TMPDIR=./.tmp/tmp \
GOCACHE=./.tmp/go-cache \
go test ./internal/graph -run 'TestRunBenchmarkSuiteSupportsBackendAndFixtureMatrix|TestBenchmarkRunsHandleEmptyAndCyclicGraphs|TestBenchmarkRunsHandleHighFanoutGraph' -count=1
```

## Hosted / Real-Service Caveats

The in-repo benchmark matrix uses memory-backed Neptune adapters so developers can compare Cerebro backend code paths without requiring hosted infrastructure.

That means:

- relative backend overhead inside Cerebro is meaningful
- correctness and regression tracking are meaningful
- absolute service latency is not representative of real Neptune deployments

For hosted measurements:

- replace the benchmark stores with live Neptune-backed `GraphStore` instances
- keep the same fixture families and workload names so regression comparisons stay aligned
- treat emulator or local fake timings as functional baselines, not production latency targets

## Regression Comparison

The recommended workflow is:

1. Run `RunBenchmarkSuite` for the cases you care about.
2. Marshal the returned `BenchmarkReport` to JSON.
3. Upload that JSON as a CI artifact.
4. Compare new reports against the previous baseline on:
   - p50 latency
   - p95 latency
   - result-size drift
   - fixture node/edge counts
