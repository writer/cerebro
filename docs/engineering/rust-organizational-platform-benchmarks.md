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
- Rust refresh timed work: all Rust projection work plus atomic replacement of
  the same entities in an already populated tenant graph
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

| Records | Go pre-flattened projection | Go raw-record projection | Rust projection | Rust projection + admission | Rust populated refresh |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 943 ns/record | 3,103 ns/record | 1,907 ns/record | 2,049 ns/record | 2,079 ns/record |
| 1,000 | 890 ns/record | 3,100 ns/record | 2,015 ns/record | 2,118 ns/record | 2,186 ns/record |
| 5,000 | 878 ns/record | 3,125 ns/record | 2,026 ns/record | 2,221 ns/record | 2,404 ns/record |

Against the equivalent raw-record boundary, Rust projection is:

- 38.5% faster at 100 records;
- 35.0% faster at 1,000 records;
- 35.2% faster at 5,000 records.

At 1,000 records, the median Rust path projects about 496,300 records per
second. Projection plus atomic graph admission processes about 472,100 records
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

## Durable store and graph reads

A second suite runs the Rust write boundary against disposable PostgreSQL 16
and Neo4j 5 instances. It measures the transaction that commits current state
and its outbox record, Neo4j projection, pending-outbox recovery, bounded path
queries, and concurrent tenant writes.

Run it with explicit disposable-store coordinates:

```sh
CEREBRO_TEST_POSTGRES_DSN='...' \
CEREBRO_TEST_NEO4J_URI='...' \
CEREBRO_TEST_NEO4J_USERNAME='...' \
CEREBRO_TEST_NEO4J_PASSWORD='...' \
make rust-organizational-store-benchmark
```

The July 23 AWS run used one isolated `m7g.xlarge` instance with PostgreSQL 16
and Neo4j 5 bound to its loopback interface. The host used an encrypted 50 GiB
gp3 volume, accepted no inbound traffic, and was reached through AWS Systems
Manager. Both revisions ran as optimized builds on the same host against the
same warm database containers. The before revision and the optimized revision
each ran three times; the table reports the median:

| Operation | Workload | Before | After | Change |
| --- | ---: | ---: | ---: | ---: |
| PostgreSQL commit + Neo4j projection | 100 entities | 157.2 ms | 74.9 ms | 2.10x |
| PostgreSQL commit + Neo4j projection | 1,000 entities | 1,137.3 ms | 176.1 ms | 6.46x |
| Eight concurrent tenant commits | 8 x 100 entities | 284.3 ms | 151.5 ms | 1.88x |

At 1,000 entities, the durable path increased from about 879 to 5,677 records
per second. The optimized median splits into 68.4 ms for the PostgreSQL commit
and 111.8 ms for Neo4j projection. PostgreSQL uses `jsonb_to_recordset` in
bounded 1,000-row chunks for entities, assertions, and observations. Identity
claim resolution and retraction repair remain explicit operations because
their conflict and replacement semantics are stronger than a generic bulk
upsert.

The Neo4j projector now sends tenant and graph revision once per query instead
of repeating them in every row. Tenant identity remains a mandatory Cypher
parameter for entity, assertion, and retraction writes.

The path corpus has one valid path at every requested depth, so this measures
bounded lookup overhead rather than path explosion. The concurrent result uses
separate PostgreSQL connections and a shared Neo4j projector. The live-store
test verified idempotent replay, pending-outbox recovery, a three-edge
provider-account to repository path through a canonical person and group, and
that a conflicting bulk identity write changes neither PostgreSQL current state
nor the projected Neo4j entity.

## Optimization found by the benchmark

The first Rust run cloned each accepted entity in the delta builder and cloned
it again when the graph engine consumed the delta. Moving already-validated
owned values across both boundaries removed those copies without changing the
public write boundary or atomic validation.

At 1,000 records:

- projection improved from 3,094 to 2,578 ns/record, a 16.7% reduction;
- projection plus admission improved from 3,743 to 2,829 ns/record, a 24.4%
  reduction.

## July 23 follow-up

The mapper now compiles family lookup, projection field paths, mapper identity,
and provider kinds once when a source mapper is created. Before and after runs
used the same five-sample, 300 ms workload:

| Workload | Before | After | Reduction |
| --- | ---: | ---: | ---: |
| Rust projection, 1,000 records | 2,501 ns/record | 2,247 ns/record | 10.2% |
| Rust projection, 5,000 records | 2,674 ns/record | 2,290 ns/record | 14.4% |
| Rust projection + admission, 1,000 records | 2,751 ns/record | 2,529 ns/record | 8.1% |

In the paired follow-up run, the equivalent Go raw-record projection measured
3,079 ns/record at 1,000 records. Rust measured 2,247 ns/record, 27.0% lower.

Bounded product reads also moved from Go-primary shadowing to Rust authority.
The Rust API now resolves a one-hop root, its edges, and the graph revision in
one Neo4j query. The before and after release builds used the same local
disposable stores and request shape:

| HTTP workload | Before | After | Change |
| --- | ---: | ---: | ---: |
| One root, concurrency 1 | 6.347 ms/request | 1.712 ms/request | 73.0% lower latency |
| One root, concurrency 16 | 1,085.7 requests/s | 3,939.5 requests/s | 3.63x throughput |

The batch route accepts one tenant and at most 100 roots. In the durable store
suite, seven sequential one-hop reads took 27.251 ms per set. One seven-root
query took 2.588 ms per set, a 90.5% reduction and 10.5x throughput increase.
The batch result was checked for all seven roots and their bounded edges on
every iteration.

## July 23 admission hot-path follow-up

The next pass removed four costs without moving any validation boundary:

- entity-only records no longer construct unused assertion provenance;
- delta assembly uses hash indexes for duplicate enforcement and sorts once
  before the deterministic digest;
- deterministic IDs encode only the 16 digest bytes used by the ID instead of
  allocating a full 32-byte digest string and slicing it;
- entity-only refreshes preflight conflicts and commit directly instead of
  cloning the tenant's full graph.

The before and after runs used the same five-sample, 500 ms workload:

| Workload | Before | After | Reduction |
| --- | ---: | ---: | ---: |
| Rust projection, 1,000 records | 2,263 ns/record | 2,015 ns/record | 11.0% |
| Rust projection, 5,000 records | 2,335 ns/record | 2,026 ns/record | 13.2% |
| Rust projection + admission, 1,000 records | 2,503 ns/record | 2,118 ns/record | 15.4% |
| Rust projection + admission, 5,000 records | 2,661 ns/record | 2,221 ns/record | 16.5% |

The populated-refresh benchmark was added before changing graph admission. At
5,000 records, removing the full-graph clone reduced its median from 3,016 to
2,404 ns/record, a 20.3% reduction. The atomicity test also requires a rejected
identity delta to leave both the graph revision and entity count unchanged.

## What this does not prove

This receipt does not measure provider network time, production-sized graph
fan-out, HTTP request concurrency, or a production database topology. The AWS
stores were empty, disposable, and co-located on one host, so the result is not
a production capacity claim. The in-process result establishes that the
stronger Rust admission boundary is not slower than the equivalent Go
raw-record projection path for this corpus. The durable suite establishes that
committed writes survive a projection interruption and that bounded multi-hop
reads work against the actual databases.
