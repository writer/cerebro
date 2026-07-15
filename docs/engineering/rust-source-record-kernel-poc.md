# Rust Source Record Kernel PoC

Status: executable boundary proof; no source runtime cutover.

## Decision

Keep provider transport, credentials, retries, pagination requests, and source
lifecycle in the Go Source CDK. Carve deterministic record validation and
mapping into a small Rust kernel compiled to zero-import WebAssembly.

Do not port connectors wholesale. Do not add runtime source discovery. Do not
load third-party artifacts. Do not give the guest a clock, random source,
environment, file system, socket, DNS resolver, or secret handle.

The first useful Rust seam is the point after a provider page arrives and
before a source event is accepted:

```text
Go Source CDK
  provider client -> bounded page bytes -> Rust record kernel
                                           | accepted records
                                           | quarantined row references
                                           | page receipt
                                           ` proposed checkpoint
                  <- fixed JSON ABI -------+
  append accepted events -> commit checkpoint
```

The host remains responsible for durable idempotency, event publication, and
checkpoint commit. The guest is a pure decision function.

## Customer Value

This boundary improves four concrete operator outcomes.

1. A malformed provider page cannot make the mapping step open a socket, read
   a file, inspect the process environment, or fetch a secret. The committed
   guest has zero imports, so those handles do not exist.
2. Every mapping call has hard input, output, memory, record-count,
   record-size, and wall-clock limits. One connector cannot turn a mapping bug
   into unbounded work inside the Cerebro process.
3. Accepted rows, quarantined rows, the proposed cursor, the canonical input
   digest, and the mapped-record digest travel together. A cursor is not a
   successful checkpoint until the Go host appends the accepted events.
4. The same request produces the same ordered records and receipt regardless
   of JSON object key order. Replay can compare digests instead of trusting
   that a second execution was equivalent.

This is useful before a plugin marketplace exists. It makes the most variable
part of a built-in source smaller and easier to replay without changing how
sources are installed or operated.

## Executable Proofs

### Proof 1: contract state is a type

`SourcePlan<Draft>` can be constructed but has no mapping method.
`SourcePlan<Validated>` exposes `map_page`. The conversion checks source ID,
family, identity field, maximum record count, and maximum record size.

The crate documentation contains a `compile_fail` test that attempts to map a
page with a draft plan. `cargo test --doc` passes only when that program fails
to compile.

Customer consequence: a new call path cannot forget contract validation and
still compile.

### Proof 2: an execution permit cannot be copied

`ExecutionPermit` implements neither `Copy` nor `Clone`. `map_page` takes the
permit by value. A second call with the same value is a compile error because
the first call moved it.

The second `compile_fail` test exercises this exact case.

Customer consequence: inside the deterministic kernel, an authorization token
cannot be accidentally duplicated and reused by another branch. This does not
replace the durable lease, idempotency key, or authorization check at the
service boundary. It removes one class of implementation error after those
checks have issued a permit.

### Proof 3: mapping is deterministic and bounded

The Rust kernel:

- rejects a page above its validated record limit before mapping any row;
- rejects an oversized cursor;
- canonicalizes JSON object keys through the parsed value representation;
- computes SHA-256 fingerprints for individual rows;
- accepts only bounded, non-empty string identities;
- quarantines non-object, oversized, missing-identity, and duplicate-identity
  rows without returning their payloads;
- sorts accepted rows by external identity;
- returns accepted and quarantined counts plus a SHA-256 record-set receipt;
- returns a proposed cursor with a SHA-256 digest of the semantic input.

Native Rust tests prove that JSON key order does not change the output and that
bad rows remain bounded quarantine records. Go host tests call the compiled
Wasm module twice and compare the complete JSON result byte for byte.

### Proof 4: the guest has no ambient capability surface

The guest targets `wasm32-unknown-unknown` and exports only:

- `cerebro_recordkernel_abi_version`;
- `cerebro_recordkernel_alloc`;
- `cerebro_recordkernel_evaluate`.

The shared Go `wasmjson` host refuses a module with any imported function or
memory. It creates a fresh instance for each call with these limits:

| Limit | Value |
| --- | ---: |
| Linear memory | 128 pages / 8 MiB |
| Input | 1 MiB |
| Output | 2 MiB |
| Call deadline | 2 seconds |
| Contract records | 1 to 1,000 |
| Record bytes | 1 to 256 KiB |
| Cursor bytes | 4 KiB |

The host test compiles the committed artifact with wazero and asserts zero
function imports and zero memory imports before executing a page.

## Reproducible Toolchain Evidence

Run:

```bash
make rust-source-kernel-evidence
```

With the pinned Rust 1.93.1 and Go 1.26.5 toolchains, the current artifacts
report:

| Artifact | Workload | Bytes | Imported functions | Callable exports |
| --- | --- | ---: | ---: | --- |
| Rust source record kernel | JSON validation, canonicalization, quarantine, SHA-256 receipts | 164,078 | 0 | ABI version, allocation, evaluation |
| Standard Go Wasm runtime floor | Empty `main` | 1,849,278 | 10 | `_start` |

The standard Go artifact is built with VCS stamping disabled so the comparison
does not change with the repository revision. It imports arguments, environment,
wall clock, random, file-descriptor write, polling, process exit, and scheduler
functions through WASI. The Rust artifact performs the actual record work
without an import.

This is not a speed benchmark and the two programs do not do equal work. The
measurement answers a narrower question: what is the minimum ambient runtime
and ABI shape each pinned standard toolchain puts at the host boundary?

## The Exact Rust Case

No customer-facing source capability is impossible to implement in Go. Go can
parse JSON, hash records, enforce runtime limits, run a subprocess, and produce
deterministic output. The decision is about which failures the compiler and
artifact format prevent before production.

Rust provides three properties the Go language or the pinned standard Go Wasm
toolchain cannot express.

### Move-only values

Rust user-defined values can be non-copyable. The compiler rejects reuse after
move. Go values are copyable; `sync.Mutex`, an atomic claimed bit, a pointer
identity, or a `noCopy` vet marker can detect or discourage misuse, but the Go
type system cannot define a user value that the compiler refuses to copy.

Use this property for in-kernel execution permits, secret leases, transaction
guards, and cursor commit tokens. Keep durable uniqueness in Postgres or
JetStream because ownership does not span process crashes or replicas.

### Closed state machines with exhaustive matches

Rust enums form a closed set. A match over mission, decision, quarantine, or
receipt states must handle every variant; adding a variant breaks every
non-exhaustive match at compile time.

Go interfaces are open and type switches are not compiler-exhaustive. Separate
named structs and package-private marker methods can approximate a closed set,
and generators or linters can enforce coverage, but the language does not make
the match exhaustive.

Use this property for high-consequence state transitions and refusal reasons.
Do not move ordinary CRUD types merely to gain enum syntax.

### A zero-import callable Wasm library from the standard toolchain

The Rust `wasm32-unknown-unknown` target emits a library with explicit exports
and no required host functions. The pinned standard Go `wasip1/wasm` target
emits a command runtime with `_start` and required WASI imports. It does not
emit the zero-import, caller-invoked library ABI used by `internal/wasmjson`.

Go can still host this module. A different Go compiler could produce a smaller
or library-shaped artifact, but that introduces another compiler, runtime
behavior, compatibility matrix, and release supply chain. An out-of-process Go
worker can also be sandboxed, but then every extension needs process or
container lifecycle, IPC, resource isolation, and credential routing.

For many-megabyte provider SDKs and network transport, those costs can be
reasonable. For a 500-millisecond pure mapping function, the zero-import guest
is the smaller operational unit.

## What Rust Does Not Provide Here

The following properties come from the Go host or the platform contract, not
from Rust:

- the Wasm memory and time ceilings come from wazero configuration;
- tenant authorization and source runtime identity remain host checks;
- retry, rate limiting, pagination requests, and provider credentials remain
  Source CDK responsibilities;
- append-before-checkpoint durability remains a service transaction;
- artifact signing and provenance are not implemented by this PoC;
- a digest proves byte identity, not semantic correctness;
- safe Rust does not make an incorrect mapping rule correct;
- process and replica idempotency still require durable state.

These limits matter because “written in Rust” is not a control. The control is
the combination of a small pure kernel, compiler-enforced states, a zero-import
artifact, a rejecting host ABI, and durable platform transactions outside it.

## Making Sources Rust-Friendly

### Split transport from record semantics

Each eligible source should have two explicit halves:

1. a Go transport plan that owns provider SDK calls, HTTP safety, credentials,
   retries, pagination requests, and raw response byte limits;
2. a Rust record plan that owns field extraction, bounded validation, family
   assignment, stable identity, quarantine reasons, and deterministic receipts.

The boundary payload must contain provider data and a source contract, never a
client, token, URL fetch instruction, tenant credential, or store handle.

### Generate both sides from one source contract

Extend source generation only after the PoC contract stabilizes. One source
definition should generate:

- the Go request and response structs;
- the Rust draft contract and bounded identifiers;
- the JSON fixture schema;
- ABI version constants on both sides;
- parity fixtures that run against native Rust and embedded Wasm;
- the host budget declaration;
- a contract digest included in the page receipt.

Generated types eliminate hand-maintained JSON field drift. The generated code
must not generate provider behavior or a general mapping language.

### Make capability absence the default

Version 1 has no host calls. If a future kernel needs a capability, add one
named import with a narrow value contract. Examples include a monotonic fuel
counter or a bounded code-only diagnostic sink. Do not expose WASI wholesale.
Do not expose the environment, wall clock, random generator, file descriptors,
network, DNS, or secret retrieval.

Every new import changes the threat model and must appear in the ABI validator,
the source contract, and the artifact evidence report.

### Keep secrets opaque and host-owned

The record kernel should never deserialize a provider credential. The Go host
uses the credential to obtain bounded page bytes, then drops the credential
before guest invocation. If mapping needs a secret-derived comparison, the host
should pass a scoped, irreversible value or perform the comparison itself.

### Treat cursor advancement as a commit token

The guest proposes a cursor; it does not persist one. The host may commit the
cursor only after every accepted event is durably appended. A future Rust
native source worker can represent this with a non-copyable `CursorCommitToken`
whose consume operation is behind the append transaction. The current Go host
must continue to enforce the same rule at runtime.

### Certify artifacts, not source names

Before a kernel can leave shadow mode, record:

- ABI version;
- source contract digest;
- Wasm artifact SHA-256;
- Rust toolchain and lockfile digest;
- import and export manifest;
- input, output, memory, and time budgets;
- native-versus-Wasm fixture parity result;
- replay digest over the source fixture corpus.

This supports exact rollback and audit without creating a marketplace.

## Selection Rule

Move a source computation into the record kernel only when all conditions hold:

- it is deterministic from a bounded request;
- it needs no provider call, clock, random value, environment, or secret;
- its output is a typed event candidate, quarantine, receipt, or refusal;
- replay equivalence has operator value;
- a type-state or exhaustive-state guarantee removes a concrete error class;
- native and Wasm fixture parity can be tested.

Keep the computation in Go when it is primarily provider SDK orchestration,
streaming I/O, retry policy, credential exchange, or an existing stable helper
with no replay or safety gap.

## Production Gates

The PoC is not on the source runtime execution path. A production shadow must
land separately and satisfy all of these gates:

1. Choose one built-in source with representative nested JSON and no custom
   provider-side normalization dependency.
2. Run the Go mapping and Rust mapping in shadow from the same bounded page.
3. Compare accepted identities, event payloads, quarantines, cursor proposal,
   and receipt digest for a fixed fixture corpus and live redacted samples.
4. Prove the guest cannot receive tenant credentials or provider clients.
5. Add fuzz targets for JSON depth, numeric edges, duplicate keys, large
   strings, Unicode identities, and cursor boundaries.
6. Set a per-source memory and time budget from measured fixture percentiles.
7. Prove append failure prevents cursor commit.
8. Prove a kernel timeout or trap leaves the existing source runtime in an
   explicit failed attempt state with no partial checkpoint.
9. Prove an artifact downgrade restores the prior digest and replay result.
10. Keep the Go path available until shadow parity and rollback acceptance are
    recorded.

## Delivery Sequence

1. **Boundary proof:** this PoC, compile-fail tests, zero-import artifact, Go
   host, deterministic receipts, and evidence tool.
2. **Contract generation:** generate the two language DTOs, ABI constants,
   fixture schema, and contract digest.
3. **One-source shadow:** run without affecting emitted events or cursors;
   persist only comparison metrics and bounded mismatch codes.
4. **One-source authority:** make the kernel authoritative for record mapping
   after parity, failure, and rollback gates pass.
5. **Repeated-source extraction:** move shared mapping primitives into the
   kernel only after two authoritative sources need the same behavior.
6. **Distribution decision:** revisit the plugin-marketplace non-goal only when
   source count, deploy blast radius, or third-party authorship supplies the
   documented operational threshold. This PoC does not meet that threshold by
   itself.

## Current Artifacts

- Rust kernel: `internal/sourceruntime/recordkernel/`
- Embedded guest: `internal/sourceruntime/recordkernel/recordkernel.wasm`
- Go host: `internal/sourceruntime/recordkernel/host.go`
- Host and capability tests: `internal/sourceruntime/recordkernel/host_test.go`
- ABI evidence tool: `tools/wasminspect/`
- Standard Go runtime floor: `tools/wasminspect/testdata/go-wasi-baseline/`
- Reproduction script: `scripts/rust-source-kernel-evidence.sh`
