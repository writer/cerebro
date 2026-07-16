# Compliance program refiner

## Outcome

Cerebro turns verified compliance-program gaps into cited, testable draft changes and asks a human GRC owner to decide whether to merge them.

The refiner uses the program record, exact scope and control-implementation revisions, completed assessment results, readiness blockers, monitored changes, and remediation outcomes. It does not improve a score by weakening scope, deleting a control, ignoring unknown evidence, or changing the active program directly.

## Operating loop

1. The **refiner** identifies a specific gap from verified program state and records the current measure, target measure, guardrails, and exact input revisions.
2. The **researcher** assembles claims with source citations, counterevidence, and unresolved questions. An uncited claim cannot support a change.
3. The **verifier** checks tenant scope, revision identity, evidence freshness, source coverage, regression risk, and prohibited scope weakening.
4. The **author** produces a bounded repository patch, validation commands, and rollback instructions against an exact base commit.
5. The **draft publisher** opens a draft pull request. Its capability exposes no approve, merge, force-merge, retarget, close, or default-branch write operation.
6. The **team notifier** publishes the decision record: what should change, why, supporting and opposing evidence, expected result, checks, pull-request URL, and the human decision required.
7. A human GRC team member accepts or rejects the proposal. Only the repository's existing human merge process can activate the change.

## Durable records

An improvement run is a first-class, tenant-scoped record with immutable revisions. It moves through these states:

- `detected`
- `researching`
- `proposed`
- `validated`
- `draft_pr_opened`
- `accepted`
- `rejected`
- `expired`
- `superseded`

Each revision records:

- program, scope, control-implementation, assessment-run, and source-snapshot revisions;
- the observed gap, baseline measurement, target measurement, and guardrails;
- cited claims, counterevidence, unknowns, and evidence freshness;
- proposed file changes, exact repository base commit, tests, benchmarks, and rollback steps;
- verifier results and the content digest of the verified proposal;
- the draft pull-request receipt and team-update receipt;
- the human decision, actor, timestamp, rationale, and accepted proposal digest.

Expected-version writes and idempotency keys prevent two runs from silently replacing one another. A proposal expires when a required program, assessment, evidence, or repository revision changes.

## Acceptance gates

A proposal can enter `validated` only when:

- every claim has at least one source citation;
- counterevidence and unknowns are preserved;
- all referenced program and assessment revisions exist and match the proposal;
- evidence required by the affected controls is current under the program policy;
- the baseline, target, and guardrail measures are machine-readable;
- the patch is bounded by configured file, byte, and operation limits;
- tests and rollback instructions are present;
- the change does not remove in-scope subjects, controls, evidence requirements, owners, or review requirements merely to improve readiness;
- the verifier reports no blocking result.

Draft publication also requires an exact repository base commit, a unique branch, and a validated proposal digest. Publication fails closed if the base moved.

## Draft-only repository capability

The repository port provides one operation:

```go
type DraftPullRequestPublisher interface {
	OpenDraftPullRequest(context.Context, OpenDraftPullRequestRequest) (DraftPullRequestReceipt, error)
}
```

The request contains a validated proposal digest, exact base commit, bounded file changes, draft title and body, and an idempotency key. The implementation creates a commit on a proposal branch and opens a pull request with `draft: true`. It does not receive a merge credential or expose a method that can change pull-request readiness, approval, merge state, base branch, or lifecycle.

Public pull-request metadata contains only repository-safe change intent and validation commands. Tenant identifiers, resource identifiers, evidence excerpts, operational counts, and internal decision details remain in the durable proposal and team update.

## Team update

The notifier writes a structured update to an outbox. Delivery adapters can post the same safe summary to approved team channels without coupling the refiner to a collaboration provider.

The update answers:

- What program gap is being addressed?
- Which verified facts support or oppose the change?
- What measurable result should change, and what must not regress?
- What files and behavior will change?
- Which checks passed?
- Where is the draft pull request?
- Which human GRC owner needs to decide?

Delivery is idempotent by proposal digest and destination. Failed delivery does not reopen or duplicate the pull request.

## Evaluation and rollout

The local demonstration will seed a program gap, cited research, counterevidence, and a bounded repository change. It will show:

1. an uncited proposal is blocked;
2. a scope-weakening proposal is blocked;
3. a cited proposal with a measurable target is validated;
4. the publisher sends only draft pull-request requests;
5. the team update carries the decision record and human action;
6. the active compliance program remains unchanged until a human records acceptance after merge.

Focused tests cover state transitions, exact-revision conflicts, idempotent retries, content-digest verification, research citation rules, anti-gaming gates, publication limits, public-data redaction, and the absence of merge capabilities. Benchmarks measure validation and deterministic digest generation at configured maximum input sizes.

The first rollout keeps proposal generation manual-triggered and publication disabled by default. Enabling publication requires an installation-scoped repository credential with contents and pull-request write permissions, an allowlisted repository, an allowlisted base branch, and an assigned human GRC decision owner.

## Non-goals

- Automatically approving, merging, force-merging, closing, or retargeting pull requests.
- Writing to the default branch.
- Directly changing an active compliance program.
- Generating claims without traceable source citations.
- Hiding failures, unknown evidence, exceptions, or opposing evidence.
- Reducing scope or requirements solely to improve readiness measures.
- Posting tenant or evidence detail in public repository metadata.
