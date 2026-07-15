# Rust Security Path Kernel Carve

## Decision

Cerebro will move deterministic security-path decisions into a pure Rust kernel. The
kernel will build canonical snapshots, compare observations, verify that paths are
absent, and rank candidate relationship cuts. It will not collect provider data,
query Neo4j, acquire leases, or persist workflow state.

The same Rust crate will support two execution shapes:

- an embedded, no-import Wasm guest called by the existing Go compatibility plane;
- a native library linked into the Rust control kernel when mission orchestration
  consumes security-path results.

Go continues to own source-runtime collection and graph orchestration during this
carve. Rust owns the decision produced from the collected proof and receipts.

## Customer Outcome

An operator receives one deterministic answer for each material access route:

- newly observed;
- no longer observed;
- proof changed while the route still exists;
- unchanged; or
- indeterminate because collection or provenance is incomplete.

The result identifies the owner, contributing source runtimes, proof edges, and the
smallest observed relationship cuts. A path is not recorded as absent unless fresh
receipts cover every runtime that contributed its reference proof.

## Ownership Boundary

The Rust security-path kernel owns:

- canonical path, proof, provenance, ownership, and receipt normalization;
- stable route, proof, snapshot, delta, and verification digests;
- completeness and indeterminate-reason evaluation;
- added, removed, proof-changed, and unchanged classification;
- observed-absence verification against fresh runtime receipts;
- deterministic candidate-cut ranking;
- schema and ABI version compatibility.

The Go compatibility plane owns:

- source-runtime and provider calls;
- runtime leases and refresh order;
- Neo4j reads, reconciliation, and assertion migration;
- checkpoint and graph-run lookup;
- translating graph query results into kernel inputs;
- persistence, HTTP, MCP, job, and telemetry adapters.

The graph remains a rebuildable projection. The Rust module does not become a graph
store or a workflow store.

## Initial API

The pure crate exposes typed functions without hidden I/O or wall-clock access:

```rust
pub fn build_snapshot(input: SnapshotInput) -> Result<Snapshot, KernelError>;
pub fn compare(before: Option<&Snapshot>, after: &Snapshot) -> Result<Delta, KernelError>;
pub fn verify_observed_absent(
    reference: &Snapshot,
    after: &Snapshot,
    requested_path_ids: &[String],
) -> Result<Verification, KernelError>;
pub fn rank_candidate_cuts(paths: &[SecurityPath]) -> Vec<CandidateEdgeCut>;
```

Inputs carry explicit observation times, tenant identifiers, collection receipts,
and graph proof. The kernel does not call the clock and does not infer tenant or
runtime scope from process state.

## Wasm Contract

The Wasm guest is a bounded JSON protocol built on `cerebro-wasm-guest` and hosted by
the shared Go `wasmjson` runtime. It exports an ABI version, bounded allocator, and
one evaluation operation.

The request selects an operation and carries one versioned payload. The response is
a tagged result containing exactly one snapshot, delta, verification, or candidate
cut list. Unknown fields, unsupported schema revisions, oversized inputs, oversized
outputs, malformed UTF-8, and malformed JSON fail closed.

The guest has:

- no imports;
- no filesystem, network, environment, clock, random, or database access;
- an explicit input and output byte limit;
- a Wasm artifact digest and size budget;
- denied unsafe Rust outside the reviewed shared linear-memory helper.

## Compatibility And Shadow Mode

The first release does not change customer-visible decisions. Go computes the
current result and invokes Rust with the same normalized input. The adapter compares
canonical JSON and digests and records one bounded parity result:

- `match`;
- `rust_error`;
- `go_error`;
- `result_mismatch`; or
- `not_evaluated` when shadow evaluation is disabled.

Shadow mismatches do not replace the Go response. They fail focused tests and expose
bounded telemetry without including graph paths, resource identifiers, tenant data,
or raw proof.

The Rust output becomes authoritative only after all release gates pass and a later
change switches the adapter. The Go implementation remains as a differential oracle
until the authoritative release has operated without mismatches through the agreed
rollback window.

## Differential Corpus

Go and Rust consume the same checked-in, non-sensitive fixtures covering:

- input ordering and label changes;
- multiple proofs for the same logical route;
- duplicate source-runtime assertions;
- missing source, runtime, event, or observation-time provenance;
- full and incomplete collection receipts;
- provider-family and configuration-revision changes;
- added, removed, proof-changed, and unchanged paths;
- equivalent routes with different proof identities;
- shared relationship cuts and deterministic tie breaking;
- malformed, oversized, and unsupported protocol payloads.

Property tests assert order independence, stable digest reproduction, idempotent
normalization, comparison symmetry where defined, and the rule that incomplete data
cannot produce a verified-absence result.

## Benchmarks

Benchmarks use generated, non-sensitive paths and receipts at fixed sizes. They
measure:

- native Rust snapshot, comparison, verification, and cut-ranking time;
- Wasm cold instantiation and warm invocation time;
- Go baseline time on the same logical fixture sizes;
- peak Wasm input/output bytes and release artifact size.

The initial performance gates are:

- warm Wasm evaluation remains below 25 milliseconds at 1,000 material paths on the
  CI benchmark host;
- native Rust evaluation does not regress more than 20 percent between revisions at
  the recorded benchmark size;
- the Wasm artifact stays within its checked-in size budget;
- no benchmark bypasses normal validation or canonicalization.

Benchmark results are engineering evidence, not a public latency commitment.

## Release Gates

Rust cannot become authoritative until tests prove:

- every checked-in Go/Rust differential fixture matches byte-for-byte after canonical
  encoding;
- replaying the same input produces the same result and digest;
- path and proof ordering do not change identity;
- missing provenance or collection coverage remains indeterminate;
- a removed path requires fresh receipts for every contributing runtime;
- provider-family or configuration-revision changes block absence verification;
- unknown schema revisions and unknown fields fail closed;
- Wasm memory, input, output, and artifact budgets hold;
- fuzz and property suites pass without panics or unbounded allocation;
- the Go process can disable the Wasm evaluator without losing the compatibility
  response during shadow mode;
- rollback to the previous compatibility image does not invalidate stored snapshots
  or receipts.

## Delivery Sequence

1. Add the pure Rust crate, schemas, unit tests, properties, and native benchmarks.
2. Add the bounded Wasm guest, embedded artifact manifest, ABI tests, and Wasm
   benchmarks.
3. Add the Go shadow adapter and checked-in differential corpus.
4. Exercise shadow evaluation in security-path capture without changing returned or
   persisted results.
5. Review parity and performance evidence and make Rust authoritative in a separate
   change.
6. Link the same native crate into the Rust control kernel when the first mandate
   consumes security-path verification.
7. Remove duplicate Go decision logic only after the rollback window and replay proof
   are complete.

## Non-Goals

- Porting connectors or provider SDKs to Rust.
- Moving Neo4j, Postgres, JetStream, HTTP, or MCP adapters into Wasm.
- Adding CGO or in-process native Rust FFI to the Go service.
- Creating another graph, workflow, or evidence store.
- Treating provider success as proof that a security path is absent.
- Creating a generic rule or workflow language as part of this carve.
