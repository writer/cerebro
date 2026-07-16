# Self-Authoring Tests

## Outcome

Cerebro should turn a demonstrated test gap into a reviewable regression test:

1. identify one behavior that is not proved by the current suite
2. record the contract or runtime evidence that demonstrates the gap
3. build a synthetic, minimal fixture
4. render the fixture through a deterministic test-family generator
5. prove that the test detects the gap
6. publish a test-only draft change with validation receipts

The initial release does not let a model write arbitrary `_test.go` files or change
production behavior. It produces a typed test specification that existing Go
generators render into repository-owned test patterns.

## Why This Fits Cerebro

Cerebro already has the required execution substrate:

- finding-rule scaffolding emits a rule, fixture, and test
- policy contracts require positive and pass fixtures
- workflow and append-log events can be replayed
- source generation carries grammar, reproducibility, and proof checks
- agent behavior has fixture-backed golden evaluations
- high-risk Rust kernels have property, fuzz, and mutation-oriented checks

The missing component is a governed loop that converts those signals into a
durable test proposal and rejects proposals that only repeat current output.

## Test Specification

`internal/testauthor` owns the in-repository specification and validation library.
The specification is the source of truth; rendered Go code is an adapter.

```yaml
api_version: testauthor.cerebro.dev/v1alpha1
id: finding-rule-unrelated-close
family: finding_rule
subject: github-secret-scanning-disabled
behavior: unrelated events do not close an open finding
signal:
  kind: contract_gap
  reference: finding-lifecycle/unrelated-close
oracle:
  kind: lifecycle_contract
  assertion: finding_status == open
fixture:
  kind: synthetic_event_sequence
  schema_ref: github/audit/v1
generator:
  name: finding_rule_fixture
  version: v1
```

A valid specification contains:

- a stable ID and test family
- one subject and one observable behavior
- provenance for the signal that requested the test
- an oracle independent of the current implementation output
- a synthetic fixture description
- the deterministic generator and version

Runtime evidence may identify a gap, but raw runtime payloads are not stored in
the specification or copied into a pull request.

## Authoring Signals

### Contract gaps

Repository declarations identify missing required cases. The first supported
family is finding rules. Required cases are:

- positive open
- negative non-open
- missing required attribute
- stable fingerprint on repeated evidence
- remediation close when the lifecycle supports closeout
- unrelated-event non-close
- deprovision or offboard close where applicable
- cross-tenant isolation
- repeat-event idempotency

Later families can cover policy fixtures, connector contracts, OpenAPI behavior,
assessment replay, and agent evaluation scenarios.

### Runtime counterexamples

Panics, dead letters, rejected events, schema mismatches, replay disagreements,
and incorrect finding transitions can request a test. The author must minimize and
replace the payload with synthetic values before rendering a fixture.

### Change gaps

A changed contract, matcher, lifecycle, endpoint, or projector can request a test
when the affected behavior has no corresponding assertion.

### Mutation survivors

Bounded mutations can request tests for high-value invariants including tenant
scope, authorization, finding fingerprints, closeout anchors, evidence freshness,
and idempotency. Coverage can prioritize a mutation but cannot supply the oracle.

## Validation Receipts

Every proposal records machine-readable receipts for the gates it passed. A test
proposal is publishable only when:

- its specification is valid and has a stable identity
- its oracle comes from an allowlisted contract family
- its fixture is synthetic, bounded, deterministic, and free of credentials
- it does not require network access or the wall clock
- it fails on the relevant unprotected revision and passes on the protected
  revision, or kills a named bounded mutation
- it passes the focused package, race, contract, architecture, and fixture-safety
  checks required by its family
- repeated generation produces byte-identical output

The first implementation records receipts locally. Persistence, runtime ingestion,
and automatic pull-request creation are later adapters and must not be prerequisites
for deterministic authoring.

## Package Boundaries

```text
repository contracts / sanitized counterexamples / bounded mutations
                              |
                              v
                    testauthor: TestSpec
                     |                 |
                     v                 v
             deterministic author   deterministic validator
                     |                 |
                     +--------+--------+
                              v
                    generated test + receipt
```

- `internal/testauthor` owns types, normalization, validation, gap identities, and
  validation receipts.
- Test-family packages translate an allowlisted contract into a `TestSpec` and
  render repository-owned fixtures or tests.
- Existing packages remain owners of finding, connector, policy, replay, and agent
  semantics. `testauthor` reads their exported contracts; it does not duplicate
  their engines.
- `internal/bootstrap` does not own authoring logic.
- GitHub publication consumes validated output. It is not part of the correctness
  boundary.

## Initial Pull Request Series

The work lands as stacked draft pull requests:

| Pull request | Scope | Review boundary |
| --- | --- | --- |
| Intent and contract | This document and the stable ownership boundaries. | Confirm the safety model and the first test family. |
| Specification core | `TestSpec`, normalization, validation, receipts, and tests. | Confirm deterministic identity and fail-closed validation. |
| Finding-rule author | Detect missing finding-rule contract cases and emit deterministic specifications. | Confirm that repository declarations, not model output, choose required behavior. |
| Proof runner | Validate reproducibility and mutation or revision proof for generated cases. | Confirm that a proposed test detects a real gap before publication. |

Every pull request remains draft until its dependency is accepted. No dependent
change should bypass a rejected ownership or oracle decision in an earlier pull
request.

## Safety Boundaries

- Do not place tenant records, hostnames, account IDs, resource labels, URNs,
  finding examples, or operational endpoints in generated fixtures or public pull
  request metadata.
- Do not derive expected results by snapshotting the current implementation.
- Do not let a generated test update its own expected result.
- Do not generate production code in the same authoring operation.
- Do not overwrite an existing test or fixture.
- Do not automatically merge a test-plus-fix change.
- Do not treat line coverage as evidence that a behavior is correct.

Automatic landing can be considered later for test-only changes from allowlisted
deterministic families after their acceptance rate, flake rate, and incident value
are measured. Until then, publication stops at a draft pull request.

## Operating Measures

Measure whether authored tests improve defect detection:

- time from a demonstrated gap to a draft regression test
- proposal acceptance and rejection reasons by test family
- percentage of proposals that fail the unprotected revision
- targeted mutation kill rate
- generated-test flake rate
- recurrence rate for defects with an accepted generated test
- fixture-safety rejection rate
- duplicate proposal rate

Raw generated-test count and aggregate line coverage are inventory measures, not
success measures.
