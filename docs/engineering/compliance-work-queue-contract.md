# Compliance work queue contract

## Canonical record

Cerebro owns the canonical compliance and security work item. A work item keeps one stable fingerprint across assessment runs and retains its occurrences and actions in the append log. Postgres serves the current tenant-scoped projection. Companion cases and other clients are adapters over this record; they do not create a second authoritative queue.

The supported HTTP journey is:

1. `GET /grc/work-items` lists a bounded page of current work. Clients can filter by state and owner and continue with the opaque cursor.
2. `GET /grc/work-items/{workItemID}` returns the current item with immutable occurrence and action history.
3. `POST /grc/work-items/{workItemID}/commands` records a typed action against an expected version.

Existing create, read, command, remediation-plan, and `verify` behavior remains available. New clients should retain the Cerebro work item ID and version in any local view so commands use optimistic concurrency instead of overwriting newer operator actions.

## Post-change assurance verification

`verify_assurance` resolves verification-required work only when the command references a persisted `AssuranceDecision` that meets every gate below:

- the decision is qualified for production use;
- the result is satisfied;
- tenant, program, scope revision, control, objective, and source match the work fingerprint;
- the result evaluation, decision time, and decision record time are after the most recent remediation action;
- the verifier is not the owner or the actor who recorded remediation; and
- the command version matches the current work item version.

The service derives the verification receipt and evidence IDs from the decision. Caller-supplied evidence cannot replace or modify the decision proof. The work projection and immutable action record retain the decision ID, run ID, result ID, decision digest, record digest, evaluation time, and decision time.

An invalidation clears the prior verification receipt and remediation anchor. The work must enter remediation again before another assurance decision can resolve it.

## Companion adapter

A companion security case may retain its own conversation and execution state, but it must use the Cerebro work item ID as its canonical reference. Queue reads come from `/grc/work-items`. State changes go through the typed command endpoint. Case closure follows a successful `verify_assurance` response; local finding reads or local completion receipts cannot close canonical work by themselves.

## Rollout gates

Deploy in dependency order:

1. assurance-decision persistence and projection;
2. assurance-decision HTTP contracts;
3. canonical queue listing and `verify_assurance`;
4. companion case adapter.

Before enabling the adapter, verify:

- append-log replay rebuilds work items and assurance decisions;
- Postgres returns tenant-scoped list, item, and decision reads;
- the API principal has security read and finding lifecycle write scopes;
- stale, mismatched, unqualified, self-verified, and stale-version commands fail before append; and
- a qualified post-remediation decision resolves exactly one expected work item version.

No table rewrite is required. New verification fields live in the existing JSON work projection and immutable action payloads. Older payloads continue to decode without those fields.

## Rollback

Disable the companion adapter first and stop issuing `verify_assurance`. Existing clients can continue using their current list, read, command, remediation-plan, and `verify` paths. Keep appended events, assurance decisions, verification receipts, and projection columns intact. Do not delete or rewrite proof records during rollback.

If the current projection must be rebuilt, replay assurance decisions before work actions so every retained verification receipt can be resolved to its immutable decision record.
