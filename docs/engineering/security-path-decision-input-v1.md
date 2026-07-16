# Security Path Decision Input V1

Status: implementation plan

Base revision: `0fcf22bc2067ba361df4a89ac829e0a7b99535aa`

## Outcome

Make every Rust security-path decision reject malformed, oversized, ambiguous, or incorrectly bound input before evaluation. Keep the Go result authoritative while the Rust result remains in shadow mode.

An operator should be able to answer three questions from one decision result:

1. Which normalized input did the kernel evaluate?
2. Which source snapshots supplied that input?
3. Did both evaluators return the same decision digest?

## Boundary

Go remains responsible for graph projection and canonical snapshot construction. Rust owns validation and evaluation of a small, versioned decision input. This change does not move graph I/O, source I/O, persistence, scheduling, or action execution into Rust.

The existing Go comparison remains the response returned to callers. A Rust validation failure or mismatch is recorded as shadow evidence and cannot change the customer-visible result.

## Contract

`DecisionInputV1` carries:

- an exact schema version;
- the requested operation;
- an input digest computed over the normalized, decision-relevant fields;
- the source snapshot digests used by the operation;
- bounded snapshots, paths, proof edges, runtime receipts, and requested identifiers.

Rust returns a decision receipt containing the schema version, input digest, source snapshot digests, operation, and decision digest. Go accepts a receipt only when every binding matches the request it sent.

Unknown fields and unknown schema versions fail closed. Duplicate stable identifiers fail validation instead of relying on last-write or first-write behavior.

## Limits

The V1 decoder enforces limits below the generic Wasm transport limits:

- at most 100 attack paths per snapshot;
- at most 64 proof edges per path;
- at most 256 runtime receipts per snapshot;
- at most 256 requested runtime identifiers;
- at most 4,096 bytes per decision-relevant string.

The implementation will reject a limit violation with a typed validation error. Limits are part of the versioned contract; changing them requires a new contract revision or an explicit compatible revision to this document and its tests.

## Work Packages

### 1. Versioned input and receipt

- Add the V1 request envelope to the Rust crate and the Go shadow adapter.
- Bind the operation and normalized decision fields to one input digest.
- Bind result receipts to the input digest and source snapshot digests.
- Reject an unsupported schema version before evaluation.

Acceptance:

- changing a decision-relevant field changes the input digest;
- an asserted digest that does not match the input is rejected;
- a receipt with a wrong input or source digest is rejected by Go;
- existing Go API response shapes remain unchanged.

### 2. Validated domain input

- Validate lengths, counts, required fields, timestamps, and digest shapes.
- Reject duplicate path, proof-edge, runtime-receipt, and requested-runtime identifiers where identity must be unique.
- Pass only a validated input type to comparison, verification, and ranking functions.

Acceptance:

- evaluators cannot be called with an unvalidated decoded request;
- each bound and uniqueness rule has a focused regression test;
- malformed input returns a stable error category without leaking input data.

### 3. Differential and adversarial coverage

- Add structured generators for compare, verify, and rank inputs.
- Mutate version, digest, counts, identifiers, ordering, and timestamps.
- Keep the existing Go implementation as the parity oracle.
- Add fixed corpus entries for digest mismatch, duplicate identity, boundary-size input, and one-over-bound input.

Acceptance:

- native Rust property tests cover all three operations;
- the Go/Wasm differential corpus covers valid and rejected requests;
- the fuzz target reaches semantic validation and evaluation, not only JSON parsing.

### 4. Resource evidence

- Benchmark native Rust evaluation, warm Wasm evaluation, and the end-to-end Go shadow path.
- Report time, allocations, and bytes allocated for representative 1-, 10-, and 100-path inputs.
- Verify the embedded artifact stays within its size budget.

Acceptance:

- no material regression from the base revision for a 100-path valid input;
- oversized input is rejected before evaluation work;
- benchmark commands and results are recorded in the pull request before review.

## Rollout

1. Deploy with Go authoritative and Rust shadow disabled by default.
2. Enable V1 shadow evaluation for deterministic samples.
3. Observe only receipt-valid, parity-matched runs as promotion evidence.
4. Treat validation errors, timeouts, receipt mismatches, and decision mismatches as failed samples.

Promotion to an authoritative Rust decision is out of scope for this change.

## Rollback

Disable the Rust shadow evaluator. The Go decision path and its public response contract remain unchanged. The previous embedded artifact can be restored independently because the adapter verifies the artifact manifest before execution.

## Security Validation

- no raw path, resource, tenant, or runtime identifiers are added to metrics;
- request and response digest comparisons use exact decoded values;
- validation runs before decision work;
- transport input, output, memory, and execution-time limits remain enforced;
- the shadow path cannot authorize or execute an action.

## Open Decisions

- Promotion thresholds and minimum observation windows belong in the follow-up decision-receipt work.
- Durable parity storage belongs in the existing event and state-store boundaries; this change emits a receipt but does not add a new store.
- Counterfactual action evaluation consumes only receipt-valid V1 decisions and lands separately.
