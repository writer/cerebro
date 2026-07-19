# Decision Workflows

Cerebro measures completed security and compliance work through three stable workflows:

- `change_decision`: decide whether a proposed change should proceed.
- `finding_to_verified_fix`: move a finding from current evidence to independently verified closure.
- `continuous_evidence`: deliver current control evidence with an export receipt.

Workflow names are contract values. Client navigation labels and persona names are not workflow identifiers.

## Completion Rules

A completed decision requires all of these records:

1. an immutable decision packet built for an authenticated tenant;
2. an append-first decision event that references the packet receipt;
3. a supported decision state;
4. a durable terminal outcome; and
5. no later reopen outcome for the same decision.

Packet construction is request activity. It does not record acceptance and does not increment completed decisions.
Provider acceptance is action progress. It is not verified closure.

Each workflow has one completion boundary:

- `change_decision`: `accepted`, `rejected`, or `deferred`;
- `finding_to_verified_fix`: `verified_closed`; and
- `continuous_evidence`: `audit_packet_delivered` with a verified export receipt.

`audit_packet_delivered` requires a verified export receipt. The outcome command fails closed when an export-receipt
verifier is unavailable.

## Record A Decision

Build a packet through `POST /platform/decision-packets`, then record the actor's disposition through the existing
knowledge decision command:

```json
{
  "packetId": "dpr_...",
  "decisionDisposition": "accepted",
  "metadata": {
    "tenant_id": "tenant-1"
  }
}
```

Allowed dispositions are `accepted`, `rejected`, and `deferred`. Rejected and deferred decisions require one bounded
reason: `not_relevant`, `insufficient_evidence`, `duplicate`, `accepted_risk`, or `other`.

The server loads the packet receipt and records its workflow, decision state, schema version, and digest. Caller
values cannot replace those fields. The authenticated request identity replaces `madeBy` on this path.

## Record A Terminal Outcome

Record a terminal result through the existing knowledge outcome command:

```json
{
  "decisionId": "urn:cerebro:tenant-1:decision:...",
  "outcomeType": "verified_closed",
  "metadata": {
    "tenant_id": "tenant-1"
  }
}
```

The command resolves the referenced decision from the append log before it writes the outcome. `verified_closed`
requires an actor other than the actor who recorded the decision. A missing decision, mismatched tenant, incomplete
packet reference, or unavailable append log prevents the write.

Terminal outcomes are `accepted`, `rejected`, `deferred`, `verified_closed`, `audit_packet_delivered`, `failed`, and
`reopened`.

## Durable Summary

Weekly completion summaries are derived from durable decision and outcome records. Replay uses stable record IDs, so
duplicate delivery does not change the count. Conflicting payloads with one stable ID are excluded and reported as
conflicts. When closure and reopen share a timestamp, reopen wins.

The summary reports completed decisions by workflow and outcome plus total completion latency. Tenant IDs, packet
IDs, decision IDs, evidence IDs, resource URNs, request IDs, and trace IDs are not metric dimensions.

## Metrics

- `cerebro_decisions_requested_total`
- `cerebro_decision_packets_built_total`
- `cerebro_decisions_completed_total`
- `cerebro_decision_actions_total`
- `cerebro_decision_outcomes_total`
- `cerebro_decision_duration_seconds`
- `cerebro_decision_evidence_freshness_seconds`

Metric dimensions are limited to workflow, decision state, coverage state, action state, and outcome.
