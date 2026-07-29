# Security Lifecycle Query Benchmark

This benchmark uses generated metadata-only lifecycle projections. It contains
no customer, provider, or environment data.

Run:

```sh
cargo bench -p cerebro-security-lifecycle --bench lifecycle_query
```

Host for the recorded run: Apple M4 Pro, macOS 26.5.2, Rust 1.93.1. Each value
is the mean of 10 release-mode iterations and includes cloning the projected
input passed to the query authority.

| Lifecycle rows | Main before | This change | Latency | Allocations | Allocated bytes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 500 | 2.107 ms | 1.249 ms | -40.7% | 30,342 -> 24,494 (-19.3%) | 2.13 MB -> 1.38 MB (-35.0%) |
| 10,000 | 33.587 ms | 25.747 ms | -23.3% | 605,758 -> 461,494 (-23.8%) | 45.68 MB -> 27.37 MB (-40.1%) |
| 100,000 | 352.389 ms | 275.536 ms | -21.8% | 6,057,174 -> 4,601,494 (-24.0%) | 414.93 MB -> 251.43 MB (-39.4%) |

The improvement comes from filtering and evaluating first, sorting only stable
subject identity, and materializing finding/action records only for the
returned page. Aggregate counts are accumulated in the same pass.

## Scale conclusion

Increasing the generic graph scan is not a scale solution. A synthetic scan of
10,000 generic resources to select lifecycle-bearing rows took 0.336 ms before
policy evaluation, decoding, sorting, and graph I/O. Those omitted costs still
grow with the tenant resource population.

The benchmark also builds a process-local `BTreeMap` by stable subject URN,
caches its unfiltered counts, and reads a 100-row keyset page from 100,000
lifecycle rows. The page read took 495 ns and one 800-byte allocation. Index
construction, durable replay, filtered count intersections, and graph I/O are
excluded, so this is an architecture comparison rather than a production
latency claim.

## Durable Neo4j projection

The lifecycle-specific Neo4j projection is rebuilt from the existing generic
organizational projection. It labels only validated lifecycle-bearing resource
nodes, flattens the metadata needed for indexes and policy counts, and keeps
the canonical subject URN as the keyset identity. Grouped aggregates and the
bounded page query run in one tenant-scoped transaction. The reader checks the
graph revision and lifecycle projection watermark before and after those
queries. A missing, stale, or wrong-version watermark uses the existing
truthful 500-resource fallback instead of returning an exact-looking empty
population.

Run the storage-backed benchmark against a disposable Neo4j instance:

```sh
CEREBRO_TEST_NEO4J_URI=127.0.0.1:7687 \
CEREBRO_TEST_NEO4J_USERNAME=neo4j \
CEREBRO_TEST_NEO4J_PASSWORD=... \
cargo test -p cerebro-organizational-store \
  --test lifecycle_benchmark --release -- --ignored --nocapture
```

Recorded on the same Apple M4 Pro host with Neo4j 5 Community in an isolated
four-CPU, 6 GiB VM. The 100,000-entity atomic projection required a 3 GiB Neo4j
transaction-memory budget; the default 1 GiB budget rejected that construction
without committing it.

| Operation | 10,000 lifecycle entities | 100,000 lifecycle entities |
| --- | ---: | ---: |
| Build validated projection input | 29.67 ms | 294.40 ms |
| Project metadata and graph revision | 1,081.69 ms | 5,223.32 ms |
| Readiness-gated rebuild/backfill | 437.41 ms | 5,484.63 ms |
| Idempotent projection replay | 312.56 ms | 3,080.94 ms |
| Filtered grouped aggregates + 100-row keyset page | 31.73 ms | 237.85 ms |

Read latency is the mean of 20 release-mode iterations after one warmup. The
filter selects credentials in two observed states, one of 20 owners, and an
expiry cutoff. The query does not materialize generic resources or transfer
the filtered population to the Rust process. Aggregate work still grows with
the matching lifecycle population; the index removes growth with unrelated
generic graph resources.

The earlier full Rust scan at 100,000 lifecycle rows took 275.54 ms after the
in-memory optimization and allocated 251.43 MB. That figure excludes the
generic graph read and transfer. The durable indexed read took 237.85 ms
including Neo4j grouped counts and the page transfer, 13.7% below that
scan-only baseline. At 10,000 rows the durable read is 23.2% slower than the
25.75 ms scan-only baseline, but the scan figure still excludes generic graph
I/O and transfer. Rebuild refreshes exact observation provenance properties in
1,000-row keyset batches; the finding resolver separately binds those
properties to the exact current `affects` assertion.
The 100,000-row rebuild cost is an explicit offline backfill tradeoff, not a
request-path cost.
