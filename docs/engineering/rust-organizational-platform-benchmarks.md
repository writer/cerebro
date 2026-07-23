# Rust Organizational Platform Benchmarks

## Scope

This receipt compares one operation that the Go and Rust paths can perform with
the same input and output cardinality: projecting Box content-asset records.
Every decoded provider object produces one graph entity and no relationship.

The corpus contains 100, 1,000, and 5,000 deterministic records. Both
implementations verify the record count and provider IDs before timing begins.
Catalog loading and corpus construction are outside the timed section.

Two Go boundaries are reported:

- `pre-flattened` starts after the Go source runtime has converted provider
  fields into event attributes;
- `raw record` starts from the same decoded provider-object shape received by
  the Rust mapper and includes Go catalog field extraction.

The `raw record` boundary is the direct implementation comparison. The
pre-flattened number shows the cost after work has already been moved into an
earlier Go stage; it is not end-to-end source throughput.

## Method

- Host: Apple M4 Pro, macOS 26.5.2, arm64
- Rust: rustc 1.93.1, optimized benchmark profile
- Go: go1.26.5, `GOMAXPROCS=1`, `-cpu=1`
- Samples: five per workload
- Sample time: 500 ms
- Reported latency: median nanoseconds per input record
- Rust timed work: catalog field extraction, deterministic entity identity,
  typed-property validation, delta construction, and delta digest
- Rust admission timed work: all Rust projection work plus atomic in-memory
  graph validation and commit
- Go raw-record timed work: catalog field extraction, event construction, and
  source projection
- Go pre-flattened admission timed work: source projection plus insertion into
  the Go scratch graph

Run the same suite with:

```sh
make rust-organizational-platform-benchmark
```

Raw outputs are written to:

- `tmp/organizational-platform-go-benchmark.txt`
- `tmp/organizational-platform-rust-benchmark.txt`

## Median results

| Records | Go pre-flattened projection | Go raw-record projection | Rust projection | Rust projection + admission |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 892 ns/record | 3,485 ns/record | 2,594 ns/record | 2,658 ns/record |
| 1,000 | 888 ns/record | 3,221 ns/record | 2,578 ns/record | 2,829 ns/record |
| 5,000 | 890 ns/record | 3,216 ns/record | 2,699 ns/record | 3,051 ns/record |

Against the equivalent raw-record boundary, Rust projection is:

- 25.6% faster at 100 records;
- 20.0% faster at 1,000 records;
- 16.1% faster at 5,000 records.

At 1,000 records, the median Rust path projects about 387,900 records per
second. Projection plus atomic graph admission processes about 353,500 records
per second.

The Go raw-record path allocates about 2.7 KB and 51 objects per record. The
Rust benchmark does not yet install an allocation-counting allocator, so this
receipt does not claim a per-record Rust allocation result.

## Whole-process memory

A separate 100 ms single-sample run measured peak resident set size with
`/usr/bin/time -l`:

| Process | Peak resident set |
| --- | ---: |
| Go raw-record benchmark | 156.2 MiB |
| Rust benchmark | 27.1 MiB |

The Rust process used 82.6% less peak resident memory in this run. This is a
whole-process measurement: it includes each language runtime, linked
dependencies, catalog initialization, corpus storage, and the benchmark
harness. It is not a per-record heap measurement.

## Optimization found by the benchmark

The first Rust run cloned each accepted entity in the delta builder and cloned
it again when the graph engine consumed the delta. Moving already-validated
owned values across both boundaries removed those copies without changing the
public write boundary or atomic validation.

At 1,000 records:

- projection improved from 3,094 to 2,578 ns/record, a 16.7% reduction;
- projection plus admission improved from 3,743 to 2,829 ns/record, a 24.4%
  reduction.

## What this does not prove

This receipt does not measure provider network time, PostgreSQL transaction
latency, Neo4j batch projection, HTTP request concurrency, or multi-tenant
contention. Those require service-level benchmarks against disposable stores.
The in-process result establishes that the stronger Rust admission boundary is
not slower than the equivalent Go raw-record projection path for this corpus.
