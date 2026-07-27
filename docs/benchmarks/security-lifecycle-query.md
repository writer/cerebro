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

The production read remains capped at 500 graph resources and reports
`coverage.complete=false` when that bound is reached. Direct subject lookup
uses the graph's indexed external key. Claiming 100,000-subject readiness
requires a rebuildable lifecycle-specific graph projection with indexed stable
identity, grouped filtered counts, and keyset page reads. That projection must
remain derived from the existing durable state and must not add a fourth
store.
